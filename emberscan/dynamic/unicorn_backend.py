"""
Unicorn execution backend — bare-metal blobs and single functions.

This is the lightweight "load the binary and emulate the code" path for raw
firmware blobs and statically-linked / bare-metal ELF, where there is no OS to
model. It maps the image, sets up a stack, and runs under Unicorn while
emitting the normalized event stream the detectors consume.

Calls are resolved against a caller-supplied ``symbols`` map ({addr: name}):
when execution enters a known address the backend reads the arguments per the
architecture calling convention and emits a :class:`CallEvent`, and emits a
:class:`RetEvent` when the captured return address is reached. That is enough
for the taint / weak-code / info-leak detectors (they key off libc-style
symbols); the memory-safety detector additionally uses the raw read/write and
unmapped-access hooks.

Unicorn and Capstone are imported lazily, so importing this module never fails
when they are absent — :pyattr:`available` reports that instead. Full dynamic
linking and syscalls are Qiling's job; see :mod:`.qiling_backend`.
"""

from __future__ import annotations

import os
import struct
import time
from typing import List, Optional

# Silence Unicorn's noisy "register accessing on id 0 is deprecated" message,
# which it prints directly to stderr on some arch/register combinations.
os.environ.setdefault("UC_IGNORE_REG_BREAK", "1")

from .backend import BackendError, BackendUnavailable, EmitFn, ExecutionBackend, RunOutcome
from .events import FETCH, READ, WRITE, BlockEvent, CallEvent, MemEvent, RetEvent

PAGE = 0x1000


def _align_down(x: int) -> int:
    return x & ~(PAGE - 1)


def _align_up(x: int) -> int:
    return (x + PAGE - 1) & ~(PAGE - 1)


# ELF e_machine -> our arch tag
_EM = {0x28: "arm", 0xB7: "arm64", 0x08: "mips", 0x03: "x86", 0x3E: "x86_64"}


class UnicornBackend(ExecutionBackend):
    name = "unicorn"

    def __init__(self) -> None:
        super().__init__()
        self._uc = None
        self._emit: Optional[EmitFn] = None
        self._outcome = RunOutcome()
        self._frames: List[dict] = []
        self._blocks = 0
        self._deadline = 0.0
        self._max_blocks = 1 << 30
        self._stack_base = 0
        self._mapped: List = []  # (base, size)

    # -- availability ---------------------------------------------------------
    @property
    def available(self) -> bool:
        try:
            import unicorn  # noqa: F401

            return True
        except Exception:
            return False

    # -- loading --------------------------------------------------------------
    def load(self, target: str, **opts) -> None:
        if not self.available:
            raise BackendUnavailable("Unicorn is not installed. `pip install unicorn capstone`.")
        import unicorn as U

        with open(target, "rb") as fh:
            blob = fh.read()

        arch = opts.get("arch")
        base = opts.get("base", 0)
        if blob[:4] == b"\x7fELF":
            info = self._parse_elf(blob)
            arch = arch or info["arch"]
            self.endian = info["endian"]
            self.entrypoint = opts.get("entry", info["entry"])
            segments = info["segments"]
        else:
            # raw/flat blob
            if not arch:
                raise BackendError("raw blob requires arch= (arm/arm64/mips/" "mipsel/x86/x86_64)")
            self.endian = "big" if arch == "mips" else "little"
            self.entrypoint = opts.get("entry", base)
            segments = [(base, blob)]

        self.arch = "mips" if arch in ("mips", "mipsel") else arch
        if arch == "mipsel":
            self.endian = "little"
        self.pointer_size = 8 if self.arch in ("arm64", "x86_64") else 4

        uc_arch, uc_mode = self._uc_arch_mode(arch, self.endian)
        self._uc = U.Uc(uc_arch, uc_mode)
        self.symbols = dict(opts.get("symbols", {}))

        # map segments
        for seg_base, data in segments:
            self._map(seg_base, data)

        # stack
        stack_size = opts.get("stack_size", 2 * 1024 * 1024)
        stack_addr = opts.get("stack_addr", 0x7000_0000)
        self._map(stack_addr, b"\x00" * stack_size)
        self._stack_base = stack_addr + stack_size - 0x1000
        self._set_sp(self._stack_base)

        self.loaded = True

    def _map(self, base: int, data: bytes) -> None:
        import unicorn as U

        start = _align_down(base)
        size = _align_up(base + len(data)) - start
        try:
            self._uc.mem_map(start, size)
            self._mapped.append((start, size))
        except U.UcError:
            pass  # overlap with an already-mapped page; tolerate
        self._uc.mem_write(base, data)

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
        import unicorn as U

        self._emit = emit
        self._outcome = RunOutcome()
        self._frames = []
        self._blocks = 0
        self._max_blocks = max(1, max_instructions // 2)
        self._deadline = time.time() + timeout_s

        uc = self._uc
        uc.hook_add(U.UC_HOOK_BLOCK, self._hook_block)
        uc.hook_add(U.UC_HOOK_MEM_READ | U.UC_HOOK_MEM_WRITE, self._hook_mem)
        uc.hook_add(
            U.UC_HOOK_MEM_READ_UNMAPPED
            | U.UC_HOOK_MEM_WRITE_UNMAPPED
            | U.UC_HOOK_MEM_FETCH_UNMAPPED
            | U.UC_HOOK_MEM_READ_PROT
            | U.UC_HOOK_MEM_WRITE_PROT,
            self._hook_mem_invalid,
        )

        start = begin if begin is not None else self.entrypoint
        end = until if until is not None else 0
        try:
            uc.emu_start(start, end, timeout=timeout_s * 1_000_000, count=max_instructions)
            self._outcome.completed = not self._outcome.crashed
        except U.UcError as exc:
            if not self._outcome.crashed:
                self._outcome.crashed = True
                self._outcome.reason = f"UcError: {exc}"
                self._outcome.crash_pc = self._safe_pc()
        self._outcome.blocks = self._blocks
        self._outcome.instructions = self._blocks  # lower bound
        return self._outcome

    # -- hooks ----------------------------------------------------------------
    def _hook_block(self, uc, address, size, user_data):
        self._blocks += 1
        if self._blocks > self._max_blocks or time.time() > self._deadline:
            self._outcome.timed_out = True
            uc.emu_stop()
            return
        self._emit(BlockEvent(pc=address, size=size))

        # return-site detection (check before entering a new frame)
        while self._frames and self._frames[-1]["ret"] == address:
            fr = self._frames.pop()
            self._emit(RetEvent(pc=address, name=fr["name"], retval=self._read_ret()))

        # call detection via symbol map
        name = self.symbols.get(address)
        if name is not None:
            args = self._read_args(8)
            ret = self._return_address()
            self._emit(CallEvent(pc=address, target=address, name=name, args=args, ret_addr=ret))
            self._frames.append({"ret": ret, "name": name})

    def _hook_mem(self, uc, access, address, size, value, user_data):
        import unicorn as U

        kind = WRITE if access == U.UC_MEM_WRITE else READ
        self._emit(
            MemEvent(
                pc=self._safe_pc(),
                access=kind,
                addr=address,
                size=size,
                value=value & 0xFFFFFFFFFFFFFFFF,
                mapped=True,
            )
        )

    def _hook_mem_invalid(self, uc, access, address, size, value, user_data):
        import unicorn as U

        if access in (U.UC_MEM_WRITE_UNMAPPED, U.UC_MEM_WRITE_PROT):
            kind = WRITE
        elif access in (U.UC_MEM_FETCH_UNMAPPED,):
            kind = FETCH
        else:
            kind = READ
        pc = self._safe_pc()
        self._emit(
            MemEvent(
                pc=pc,
                access=kind,
                addr=address,
                size=size,
                value=value & 0xFFFFFFFFFFFFFFFF,
                mapped=False,
            )
        )
        self._outcome.crashed = True
        self._outcome.crash_pc = pc
        self._outcome.crash_addr = address
        self._outcome.crash_access = kind
        self._outcome.reason = f"invalid {kind} @ 0x{address:x}"
        uc.emu_stop()
        return False  # do not attempt to continue

    # -- inspection -----------------------------------------------------------
    def read_mem(self, addr: int, size: int) -> bytes:
        if not self._uc or size <= 0:
            return b""
        try:
            return bytes(self._uc.mem_read(addr, size))
        except Exception:
            return b""

    def read_reg(self, name: str) -> int:
        const = self._reg_const(name)
        if const is None:
            return 0
        try:
            return int(self._uc.reg_read(const))
        except Exception:
            return 0

    def close(self) -> None:
        self._uc = None
        self.loaded = False

    # -- calling convention ---------------------------------------------------
    def _read_args(self, n: int) -> List[int]:
        a = self.arch
        if a == "arm":
            regs = ["r0", "r1", "r2", "r3"]
        elif a == "arm64":
            regs = ["x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"]
        elif a == "mips":
            regs = ["a0", "a1", "a2", "a3"]
        elif a == "x86_64":
            regs = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"]
        else:  # x86 cdecl: all args on the stack
            regs = []
        out = [self.read_reg(r) for r in regs[:n]]
        # remaining args from the stack
        if len(out) < n:
            sp = self._get_sp()
            # x86: [esp] is return addr, args start at [esp+4]
            off = self.pointer_size if a == "x86" else 0
            for i in range(len(out), n):
                out.append(self.read_ptr(sp + off + i * self.pointer_size))
        return out

    def _return_address(self) -> int:
        if self.arch in ("arm", "arm64"):
            return self.read_reg("lr")
        if self.arch == "mips":
            return self.read_reg("ra")
        # x86 / x86_64: return address sits at the top of the stack on entry
        return self.read_ptr(self._get_sp())

    def _read_ret(self) -> int:
        return self.read_reg("ret")

    def _get_sp(self) -> int:
        return self.read_reg("sp")

    def _set_sp(self, value: int) -> None:
        const = self._reg_const("sp")
        if const is not None:
            self._uc.reg_write(const, value)

    def _safe_pc(self) -> int:
        try:
            return self.read_reg("pc")
        except Exception:
            return 0

    # -- arch tables ----------------------------------------------------------
    def _uc_arch_mode(self, arch: str, endian: str):
        import unicorn as U

        big = U.UC_MODE_BIG_ENDIAN
        little = U.UC_MODE_LITTLE_ENDIAN
        if arch == "arm":
            return U.UC_ARCH_ARM, U.UC_MODE_ARM | (big if endian == "big" else little)
        if arch == "arm64":
            return U.UC_ARCH_ARM64, little
        if arch in ("mips", "mipsel"):
            mode = U.UC_MODE_MIPS32 | (big if endian == "big" else little)
            return U.UC_ARCH_MIPS, mode
        if arch == "x86":
            return U.UC_ARCH_X86, U.UC_MODE_32
        if arch == "x86_64":
            return U.UC_ARCH_X86, U.UC_MODE_64
        raise BackendError(f"unsupported arch: {arch}")

    def _reg_const(self, name: str):
        uc_mods = self._reg_module()
        if uc_mods is None:
            return None
        table, prefix = uc_mods
        a = self.arch
        name = name.lower()
        # normalize logical names to arch registers
        alias = {
            "arm": {
                "sp": "SP",
                "lr": "LR",
                "pc": "PC",
                "ret": "R0",
                "r0": "R0",
                "r1": "R1",
                "r2": "R2",
                "r3": "R3",
            },
            "arm64": {
                "sp": "SP",
                "lr": "X30",
                "pc": "PC",
                "ret": "X0",
                "x0": "X0",
                "x1": "X1",
                "x2": "X2",
                "x3": "X3",
                "x4": "X4",
                "x5": "X5",
                "x6": "X6",
                "x7": "X7",
            },
            "mips": {
                "sp": "SP",
                "ra": "RA",
                "pc": "PC",
                "ret": "V0",
                "a0": "A0",
                "a1": "A1",
                "a2": "A2",
                "a3": "A3",
            },
            "x86": {"sp": "ESP", "pc": "EIP", "ret": "EAX"},
            "x86_64": {
                "sp": "RSP",
                "pc": "RIP",
                "ret": "RAX",
                "rdi": "RDI",
                "rsi": "RSI",
                "rdx": "RDX",
                "rcx": "RCX",
                "r8": "R8",
                "r9": "R9",
            },
        }.get(a, {})
        reg = alias.get(name, name.upper())
        return getattr(table, f"{prefix}_REG_{reg}", None)

    def _reg_module(self):
        try:
            if self.arch == "arm":
                from unicorn import arm_const as m

                return m, "UC_ARM"
            if self.arch == "arm64":
                from unicorn import arm64_const as m

                return m, "UC_ARM64"
            if self.arch == "mips":
                from unicorn import mips_const as m

                return m, "UC_MIPS"
            if self.arch == "x86":
                from unicorn import x86_const as m

                return m, "UC_X86"
            if self.arch == "x86_64":
                from unicorn import x86_const as m

                return m, "UC_X86"
        except Exception:
            return None
        return None

    # -- minimal ELF loader ---------------------------------------------------
    @staticmethod
    def _parse_elf(blob: bytes) -> dict:
        if len(blob) < 20 or blob[:4] != b"\x7fELF":
            raise BackendError("not an ELF file")
        ei_class = blob[4]  # 1=32, 2=64
        ei_data = blob[5]  # 1=LE, 2=BE
        endian = "big" if ei_data == 2 else "little"
        e = ">" if endian == "big" else "<"
        is64 = ei_class == 2
        e_machine = struct.unpack_from(e + "H", blob, 18)[0]
        arch = _EM.get(e_machine)
        if arch is None:
            raise BackendError(f"unsupported ELF e_machine=0x{e_machine:x}")
        if arch == "mips" and endian == "little":
            arch = "mipsel"
        if is64:
            e_entry = struct.unpack_from(e + "Q", blob, 24)[0]
            e_phoff = struct.unpack_from(e + "Q", blob, 32)[0]
            e_phentsize, e_phnum = struct.unpack_from(e + "HH", blob, 54)
        else:
            e_entry = struct.unpack_from(e + "I", blob, 24)[0]
            e_phoff = struct.unpack_from(e + "I", blob, 28)[0]
            e_phentsize, e_phnum = struct.unpack_from(e + "HH", blob, 42)

        segments: List = []
        for i in range(e_phnum):
            off = e_phoff + i * e_phentsize
            if off + e_phentsize > len(blob):
                break
            p_type = struct.unpack_from(e + "I", blob, off)[0]
            if p_type != 1:  # PT_LOAD
                continue
            if is64:
                p_offset = struct.unpack_from(e + "Q", blob, off + 8)[0]
                p_vaddr = struct.unpack_from(e + "Q", blob, off + 16)[0]
                p_filesz = struct.unpack_from(e + "Q", blob, off + 32)[0]
                p_memsz = struct.unpack_from(e + "Q", blob, off + 40)[0]
            else:
                p_offset = struct.unpack_from(e + "I", blob, off + 4)[0]
                p_vaddr = struct.unpack_from(e + "I", blob, off + 8)[0]
                p_filesz = struct.unpack_from(e + "I", blob, off + 16)[0]
                p_memsz = struct.unpack_from(e + "I", blob, off + 20)[0]
            data = blob[p_offset : p_offset + p_filesz]
            if p_memsz > p_filesz:
                data += b"\x00" * (p_memsz - p_filesz)
            segments.append((p_vaddr, data))
        return {"arch": arch, "endian": endian, "entry": e_entry, "segments": segments}
