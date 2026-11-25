"""
Qiling execution backend — Linux user-space ELF with the firmware rootfs.

This is the primary path for the software side of EmberScan: it runs an
individual ELF from an extracted firmware image using the image's own
filesystem as the sysroot, so dynamically-linked binaries resolve their libc
and the program sees a realistic environment. Qiling models the OS/syscalls;
this backend layers the normalized event stream on top.

Call resolution uses Qiling's ``set_api`` name interception for the functions
the detectors care about (sources, sinks, allocators, crypto, RNG, compares),
with ``CALL``/``EXIT`` hooks giving us :class:`CallEvent` / :class:`RetEvent`.
``set_api`` resolves names through the binary's PT_DYNAMIC relocations, so it
sees nothing in a statically-linked ELF (no PLT/GOT indirection to intercept).
As a fallback for that case, :meth:`_load_static_symbols` parses the binary's
own ``.symtab`` for defined addresses of the same function names and
:meth:`_hook_block` resolves calls/returns against that map directly —
mirroring :class:`.unicorn_backend.UnicornBackend`'s symbol-driven approach.
A dynamically-linked binary's ``.symtab`` only has these as *undefined*
references, so the two mechanisms don't double-fire.
Memory and unmapped-access hooks feed the memory-safety detector. Everything is
feature-detected with ``getattr`` and wrapped in ``try/except`` so Qiling
version drift degrades gracefully instead of crashing the scan.

Qiling is imported lazily; :pyattr:`available` reports whether it is installed.

NOTE: this backend executes code from the target firmware. Run it inside the
project's Docker sandbox / a throwaway VM, never against production, and only
on firmware you are authorised to assess.
"""

from __future__ import annotations

import os
import sys
import time
from contextlib import contextmanager
from typing import Dict, List, Optional, Set

from .backend import BackendError, BackendUnavailable, EmitFn, ExecutionBackend, RunOutcome

# Markers the guest dynamic loader prints when it cannot resolve a binary's
# shared libraries / symbols. Their presence means the program never actually
# ran, so any fault it hits afterwards is a loader artifact, not a real bug.
_LOAD_FAIL_MARKERS = (
    "symbol not found",
    "Error loading shared library",
    "Error relocating",
    "Operation not permitted",
    "can't load library",
    "not found (needed by",
)


@contextmanager
def _redirect_fds(target_fd: int):
    """Redirect OS-level stdout/stderr (fd 1 & 2) to ``target_fd``.

    The emulated program's own dynamic loader (ld-uClibc/musl) writes directly
    to guest fd 1/2 — e.g. ``Error loading shared library ...: Operation not
    permitted`` and ``Error relocating ...: symbol not found`` — which Qiling
    forwards to the real terminal, flooding the CLI. These come from trying to
    run full userspace daemons (uhttpd, dnsmasq, ubusd, dbus-daemon) standalone
    without their ubus/dbus runtime, so they are expected emulation noise, not
    EmberScan errors. Redirecting at the fd level is the only way to catch
    output the guest writes through emulated syscalls.
    """
    saved = {}
    try:
        sys.stdout.flush()
        sys.stderr.flush()
        for fd in (1, 2):
            try:
                saved[fd] = os.dup(fd)
                os.dup2(target_fd, fd)
            except OSError:
                saved.pop(fd, None)
        yield
    finally:
        for fd, old in saved.items():
            try:
                os.dup2(old, fd)
                os.close(old)
            except OSError:
                pass


from .events import READ, WRITE, BlockEvent, CallEvent, MemEvent, RetEvent

# Function names the detectors key off; we intercept these by name.
_HOOK_NAMES: Set[str] = {
    # input sources
    "read",
    "recv",
    "recvfrom",
    "fgets",
    "fread",
    "gets",
    "nvram_get",
    "nvram_safe_get",
    "getenv",
    "websGetVar",
    "webGetVar",
    "GetValue",
    "get_cgi",
    # copy / propagation
    "memcpy",
    "memmove",
    "strcpy",
    "strncpy",
    "strcat",
    "strncat",
    "stpcpy",
    "strlcpy",
    "strlcat",
    "bcopy",
    "sprintf",
    "vsprintf",
    # command sinks
    "system",
    "popen",
    "execl",
    "execlp",
    "execle",
    "execv",
    "execvp",
    "execvpe",
    "execve",
    "doSystem",
    "do_system",
    # format / egress
    "printf",
    "fprintf",
    "dprintf",
    "snprintf",
    "vsnprintf",
    "syslog",
    "asprintf",
    "send",
    "sendto",
    "write",
    "fwrite",
    "puts",
    "fputs",
    # allocators
    "malloc",
    "calloc",
    "realloc",
    "free",
    "reallocarray",
    # crypto / rng / compare
    "MD5",
    "MD5_Init",
    "SHA1",
    "SHA1_Init",
    "DES_set_key",
    "DES_ecb_encrypt",
    "RC4",
    "RC4_set_key",
    "crypt",
    "rand",
    "random",
    "srand",
    "srandom",
    "time",
    "strcmp",
    "strncmp",
    "strcasecmp",
    "memcmp",
}

_ARG_REGS = {
    "arm": ["r0", "r1", "r2", "r3"],
    "arm64": ["x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"],
    "mips": ["a0", "a1", "a2", "a3"],
    "x86_64": ["rdi", "rsi", "rdx", "rcx", "r8", "r9"],
    "x86": [],
}
_RET_REG = {"arm": "r0", "arm64": "x0", "mips": "v0", "x86": "eax", "x86_64": "rax"}
_SP_REG = {"arm": "sp", "arm64": "sp", "mips": "sp", "x86": "esp", "x86_64": "rsp"}
_LR_REG = {"arm": "lr", "arm64": "lr", "mips": "ra"}
# Reported even when nested inside another hooked call: heap tracking needs
# every allocation, including libc's own (stdio buffers etc.).
_ALLOC_NAMES: Set[str] = {"malloc", "calloc", "realloc", "free", "reallocarray"}

# R_<arch>_IRELATIVE relocation types, keyed by pyelftools e_machine string.
_IRELATIVE = {"EM_X86_64": 37, "EM_386": 42, "EM_AARCH64": 1032, "EM_ARM": 160}


class QilingBackend(ExecutionBackend):
    name = "qiling"

    def __init__(self) -> None:
        super().__init__()
        self._ql = None
        self._emit: Optional[EmitFn] = None
        self._outcome = RunOutcome()
        self._blocks = 0
        self._deadline = 0.0
        self._rootfs = ""
        self._argv: List[str] = []
        self._mem_events = True
        self._load_incomplete = False
        # Symbol-map fallback (static binaries / locally-defined functions that
        # set_api can't intercept): entry address -> name, plus IFUNC GOT slots.
        self._sym_map: Dict[int, str] = {}
        self._irel_slots: Dict[int, str] = {}
        self._frames: List[dict] = []

    @property
    def available(self) -> bool:
        try:
            import qiling  # noqa: F401

            return True
        except Exception:
            return False

    def _guarded(self, fn):
        """Run ``fn`` with guest stdout/stderr captured off the console.

        Captured text is inspected for dynamic-loader failure markers; if found,
        ``self._load_incomplete`` is set so crash findings from a binary that
        never actually loaded can be discarded. Set ``EMBERSCAN_EMU_VERBOSE=1``
        to let the guest output through to the terminal (and skip capture).
        """
        if os.environ.get("EMBERSCAN_EMU_VERBOSE"):
            return fn()
        import tempfile

        with tempfile.TemporaryFile() as tf:
            with _redirect_fds(tf.fileno()):
                result = fn()
            try:
                tf.seek(0)
                text = tf.read().decode("latin-1", "replace")
            except OSError:
                text = ""
        if text and any(m in text for m in _LOAD_FAIL_MARKERS):
            self._load_incomplete = True
        return result

    # -- loading --------------------------------------------------------------
    def load(self, target: str, **opts) -> None:
        if not self.available:
            raise BackendUnavailable(
                "Qiling is not installed. `pip install qiling` (brings Unicorn)."
            )
        from qiling import Qiling

        try:
            from qiling.const import QL_VERBOSE

            verbose = QL_VERBOSE.OFF
        except Exception:  # pragma: no cover
            verbose = 0

        self._rootfs = opts.get("rootfs") or "."
        self._argv = [target] + list(opts.get("argv", []))
        self._mem_events = opts.get("mem_events", True)
        self._load_incomplete = False

        try:
            # The guest dynamic loader runs during construction and writes
            # library/relocation errors straight to fd 1/2; capture those and
            # note whether the binary failed to load its libraries.
            self._ql = self._guarded(
                lambda: Qiling(self._argv, self._rootfs, verbose=verbose, console=False)
            )
        except Exception as exc:
            raise BackendError(f"Qiling failed to load {target}: {exc}")

        self.arch = self._arch_tag()
        self.pointer_size = getattr(self._ql.arch, "pointersize", 4)
        self.endian = "big" if self._is_big_endian() else "little"
        self.entrypoint = getattr(self._ql.loader, "entry_point", 0) or getattr(
            self._ql.loader, "elf_entry", 0
        )
        if self.arch == "arm64":
            self._fix_arm64_hwcap()
        self._build_symbol_map(target)
        self.loaded = True

    # AT_HWCAP auxv tag, and a conservative arm64 value: FP | ASIMD.
    _AT_HWCAP = 16
    _ARM64_SAFE_HWCAP = 0x3

    def _fix_arm64_hwcap(self) -> None:
        """Stop glibc picking ARMv8.1 LSE atomics Unicorn can't execute.

        Qiling (<=1.4.6) writes the x86 HWCAP constant for *every* 64-bit
        arch. On arm64 that sets bit 8 (HWCAP_ATOMICS), so glibc's outline
        atomics dispatch to ``casal`` etc., which the default Unicorn CPU model
        (Cortex-A72, ARMv8.0) raises as an undefined-instruction interrupt
        ("_hook_intr_cb : not handled"). Rewrite AT_HWCAP to FP|ASIMD.
        """
        auxv = getattr(self._ql.loader, "auxv", None)
        if not auxv:
            return
        try:
            ps = self.pointer_size
            # Walk (key, val) pairs until AT_NULL; patch the AT_HWCAP value.
            for i in range(64):
                key = self.read_ptr(auxv + i * 2 * ps)
                if key == 0:
                    break
                if key == self._AT_HWCAP:
                    self._ql.mem.write(
                        auxv + i * 2 * ps + ps, self._ARM64_SAFE_HWCAP.to_bytes(ps, "little")
                    )
                    break
        except Exception:
            pass

    # -- symbol-map fallback --------------------------------------------------
    def _build_symbol_map(self, target: str) -> None:
        """Map entry addresses of *defined* interesting functions to names.

        ``set_api`` only intercepts imports resolved through the dynamic
        linker, so it sees nothing in a statically-linked binary and misses
        functions a dynamic binary defines itself (e.g. a vendor ``doSystem``).
        Those are recovered here from ``.symtab``/``.dynsym`` and detected in
        :meth:`_hook_block`, mirroring ``UnicornBackend._hook_block``.

        IFUNC symbols (glibc's ``strcpy``/``memcpy``/... in static builds)
        point at a resolver, not the implementation; calls reach the chosen
        implementation through an IRELATIVE GOT slot. We watch those slots and
        learn the implementation address when startup code fills them in.
        """
        self._sym_map = {}
        self._irel_slots = {}
        try:
            from elftools.elf.elffile import ELFFile
            from elftools.elf.relocation import RelocationSection
            from elftools.elf.sections import SymbolTableSection
        except Exception:  # pyelftools ships with qiling; be defensive anyway
            return
        try:
            with open(target, "rb") as fh:
                elf = ELFFile(fh)
                base = 0
                if elf["e_type"] == "ET_DYN":
                    base = getattr(self._ql.loader, "load_address", 0) or 0
                thumb_mask = ~1 if self.arch == "arm" else ~0

                resolvers: Dict[int, str] = {}
                for sec in elf.iter_sections():
                    if not isinstance(sec, SymbolTableSection):
                        continue
                    for sym in sec.iter_symbols():
                        name = sym.name
                        if name not in _HOOK_NAMES or not sym["st_value"]:
                            continue
                        if sym["st_shndx"] == "SHN_UNDEF":
                            continue  # import: set_api's job
                        addr = (base + sym["st_value"]) & thumb_mask
                        stype = sym["st_info"]["type"]
                        if stype == "STT_FUNC":
                            self._sym_map.setdefault(addr, name)
                        elif stype == "STT_LOOS":  # STT_GNU_IFUNC
                            resolvers.setdefault(addr, name)

                irel = _IRELATIVE.get(elf["e_machine"])
                if resolvers and irel is not None:
                    for sec in elf.iter_sections():
                        if not isinstance(sec, RelocationSection):
                            continue
                        for rel in sec.iter_relocations():
                            if rel["r_info_type"] != irel:
                                continue
                            slot = base + rel["r_offset"]
                            if rel.is_RELA():
                                resolver = base + rel["r_addend"]
                            else:  # REL: addend is the slot's initial content
                                resolver = base + self.read_ptr(slot)
                            name = resolvers.get(resolver & thumb_mask)
                            if name:
                                self._irel_slots[slot] = name
        except Exception:
            self._sym_map = {}
            self._irel_slots = {}

    def _hook_irel_slot(self, ql, access, address, size, value, *a):
        name = self._irel_slots.get(address)
        if name and value:
            mask = ~1 if self.arch == "arm" else ~0
            self._sym_map[value & mask] = name

    # -- run ------------------------------------------------------------------
    def run(
        self,
        emit: EmitFn,
        *,
        max_instructions: int = 2_000_000,
        timeout_s: int = 30,
        begin: Optional[int] = None,
        until: Optional[int] = None,
    ) -> RunOutcome:
        self._emit = emit
        self._outcome = RunOutcome()
        self._blocks = 0
        self._frames = []
        self._deadline = time.time() + timeout_s
        ql = self._ql

        self._install_hooks()

        run_kwargs = {}
        if begin is not None:
            run_kwargs["begin"] = begin
        if until is not None:
            run_kwargs["end"] = until
        # Qiling maps timeout (us) and count onto the underlying Unicorn.
        run_kwargs["timeout"] = timeout_s * 1_000_000
        run_kwargs["count"] = max_instructions

        try:
            self._guarded(lambda: ql.run(**run_kwargs))
            self._outcome.completed = not self._outcome.crashed
        except Exception as exc:  # Qiling raises on faults / unmapped exec
            if not self._outcome.crashed:
                self._outcome.crashed = True
                self._outcome.reason = f"{type(exc).__name__}: {exc}"
                self._outcome.crash_pc = self._safe_pc()
        self._outcome.blocks = self._blocks
        self._outcome.load_incomplete = self._load_incomplete
        return self._outcome

    def _install_hooks(self) -> None:
        ql = self._ql
        # block coverage + budget
        try:
            ql.hook_block(self._hook_block)
        except Exception:
            pass
        # memory + faults
        try:
            ql.hook_mem_unmapped(self._hook_unmapped)
        except Exception:
            pass
        if self._mem_events:
            try:
                ql.hook_mem_read(self._hook_mem_read)
                ql.hook_mem_write(self._hook_mem_write)
            except Exception:
                pass
        # IFUNC GOT slots for the symbol-map fallback
        for slot in self._irel_slots:
            try:
                ql.hook_mem_write(
                    self._hook_irel_slot, begin=slot, end=slot + self.pointer_size - 1
                )
            except Exception:
                pass
        # function interception by name (CALL + EXIT)
        self._install_api_hooks()

    def _install_api_hooks(self) -> None:
        ql = self._ql
        set_api = getattr(getattr(ql, "os", None), "set_api", None)
        if set_api is None:
            return
        try:
            from qiling.const import QL_INTERCEPT

            # ENTER observes the call and lets the real implementation run
            # afterward; QL_INTERCEPT.CALL would *replace* it instead, which
            # drops all side effects (read() never fills its buffer, strcpy()
            # never copies, system() never execs, ...).
            on_enter, on_exit = QL_INTERCEPT.ENTER, QL_INTERCEPT.EXIT
        except Exception:  # pragma: no cover
            on_enter = on_exit = None

        for name in _HOOK_NAMES:
            enter = self._make_call_cb(name)
            exit_ = self._make_ret_cb(name)
            try:
                if on_enter is not None:
                    set_api(name, enter, on_enter)
                    set_api(name, exit_, on_exit)
                else:  # older signature: set_api(name, cb)
                    set_api(name, enter)
            except Exception:
                continue

    # -- hook callbacks -------------------------------------------------------
    def _hook_block(self, ql, address, size, *a):
        self._blocks += 1
        if time.time() > self._deadline:
            self._outcome.timed_out = True
            try:
                ql.emu_stop()
            except Exception:
                pass
            return
        self._emit(BlockEvent(pc=address, size=size))
        if self._sym_map:
            self._symbol_calls(address)

    def _symbol_calls(self, address: int) -> None:
        """Call/return detection for the symbol-map fallback."""
        frames = self._frames
        while frames and frames[-1]["ret"] == address:
            fr = frames.pop()
            self._emit(RetEvent(pc=address, name=fr["name"], retval=self._read_ret()))
        name = self._sym_map.get(address)
        if frames:
            # Still inside a hooked function. Drop the frame if the stack has
            # unwound past it (longjmp, tail-exit); otherwise ignore nested
            # libc-internal calls, matching what set_api reports for imports
            # -- except allocators, which heap tracking must always see.
            sp = self.read_reg(_SP_REG.get(self.arch, "sp"))
            if sp > frames[-1]["sp"] + self.pointer_size:
                frames.pop()
            elif name not in _ALLOC_NAMES:
                return
        if name is None:
            return
        ret = self._return_address()
        sp = self.read_reg(_SP_REG.get(self.arch, "sp"))
        if (
            frames
            and frames[-1]["entry"] == address
            and frames[-1]["ret"] == ret
            and frames[-1]["sp"] == sp
        ):
            return  # entry block re-executed (loop back to entry), not a call
        self._emit(
            CallEvent(pc=address, target=address, name=name, args=self._read_args(6), ret_addr=ret)
        )
        frames.append({"ret": ret, "name": name, "sp": sp, "entry": address})

    def _hook_mem_read(self, ql, access, address, size, value, *a):
        self._emit(
            MemEvent(
                pc=self._safe_pc(),
                access=READ,
                addr=address,
                size=size,
                value=value or 0,
                mapped=True,
            )
        )

    def _hook_mem_write(self, ql, access, address, size, value, *a):
        self._emit(
            MemEvent(
                pc=self._safe_pc(),
                access=WRITE,
                addr=address,
                size=size,
                value=value or 0,
                mapped=True,
            )
        )

    def _hook_unmapped(self, ql, access, address, size, value, *a):
        pc = self._safe_pc()
        kind = WRITE if self._is_write(access) else READ
        self._emit(
            MemEvent(pc=pc, access=kind, addr=address, size=size, value=value or 0, mapped=False)
        )
        self._outcome.crashed = True
        self._outcome.crash_pc = pc
        self._outcome.crash_addr = address
        self._outcome.crash_access = kind
        self._outcome.reason = f"unmapped {kind} @ 0x{address:x}"
        try:
            ql.emu_stop()
        except Exception:
            pass
        return False

    def _make_call_cb(self, name: str):
        def cb(*a):
            try:
                args = self._read_args(6)
                pc = self._safe_pc()
                self._emit(CallEvent(pc=pc, target=pc, name=name, args=args))
            except Exception:
                pass

        return cb

    def _make_ret_cb(self, name: str):
        def cb(*a):
            try:
                self._emit(RetEvent(pc=self._safe_pc(), name=name, retval=self._read_ret()))
            except Exception:
                pass

        return cb

    # -- inspection -----------------------------------------------------------
    def read_mem(self, addr: int, size: int) -> bytes:
        if not self._ql or size <= 0:
            return b""
        try:
            return bytes(self._ql.mem.read(addr, size))
        except Exception:
            return b""

    def read_reg(self, name: str) -> int:
        try:
            return int(self._ql.arch.regs.read(name))
        except Exception:
            return 0

    def close(self) -> None:
        self._ql = None
        self.loaded = False

    # -- helpers --------------------------------------------------------------
    def _read_args(self, n: int) -> List[int]:
        regs = _ARG_REGS.get(self.arch, [])
        out = [self.read_reg(r) for r in regs[:n]]
        if len(out) < n:
            sp = self.read_reg(_SP_REG.get(self.arch, "sp"))
            off = self.pointer_size if self.arch == "x86" else 0
            for i in range(len(out), n):
                out.append(self.read_ptr(sp + off + i * self.pointer_size))
        return out

    def _read_ret(self) -> int:
        return self.read_reg(_RET_REG.get(self.arch, "r0"))

    def _return_address(self) -> int:
        """Return address at function entry (link reg, or top of stack)."""
        lr = _LR_REG.get(self.arch)
        if lr:
            ra = self.read_reg(lr)
            return ra & ~1 if self.arch == "arm" else ra
        return self.read_ptr(self.read_reg(_SP_REG.get(self.arch, "sp")))

    def _safe_pc(self) -> int:
        for n in ("pc", "rip", "eip"):
            v = self.read_reg(n)
            if v:
                return v
        return 0

    def _arch_tag(self) -> str:
        try:
            from qiling.const import QL_ARCH

            t = self._ql.arch.type
            return {
                QL_ARCH.ARM: "arm",
                QL_ARCH.ARM64: "arm64",
                QL_ARCH.MIPS: "mips",
                QL_ARCH.X86: "x86",
                QL_ARCH.X8664: "x86_64",
            }.get(t, "unknown")
        except Exception:
            bits = getattr(self._ql.arch, "bits", 32)
            return "x86_64" if bits == 64 else "x86"

    def _is_big_endian(self) -> bool:
        try:
            return bool(getattr(self._ql.arch, "endian", 0)) and self.arch == "mips"
        except Exception:
            return False

    @staticmethod
    def _is_write(access) -> bool:
        try:
            import unicorn as U

            return access in (U.UC_MEM_WRITE, U.UC_MEM_WRITE_UNMAPPED, U.UC_MEM_WRITE_PROT)
        except Exception:
            return False
