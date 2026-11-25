"""
Execution-backend abstraction for EmberScan dynamic analysis.

An :class:`ExecutionBackend` is anything that can *run a target and report what
happened* as a stream of :class:`~emberscan.dynamic.events.TraceEvent` objects,
while also letting a detector inspect memory and registers on demand.

Today the concrete backends are emulators (Unicorn for bare-metal/raw code,
Qiling for Linux user-space ELF). The point of this seam is that the *same*
detector pipeline runs unchanged over any backend. In particular, the planned
Raspberry-Pi hardware harness becomes :class:`HardwareBackend`: it drives a
real chip over JTAG/SWD or a serial agent and feeds the identical event stream,
so every detector in ``emberscan.dynamic.detectors`` works on physical hardware
with no change. That is the integration path for merging the software and
hardware sides of the toolkit.

This module imports no emulator and no EmberScan models, so it stays importable
and testable everywhere; :class:`MockBackend` exists precisely so the detectors
can be unit-tested against a scripted event stream with no native dependencies.
"""

from __future__ import annotations

import abc
from dataclasses import dataclass
from typing import Callable, Dict, Iterable, List, Optional

from .events import TraceEvent


class BackendError(Exception):
    """Raised when a backend cannot load or run a target."""


class BackendUnavailable(BackendError):
    """Raised when the backend's native dependencies are not installed."""


EmitFn = Callable[[TraceEvent], None]


@dataclass
class RunOutcome:
    """Summary of a single emulation/execution run."""

    completed: bool = False  # reached a normal exit / return
    crashed: bool = False  # faulted (unmapped access, bad insn, ...)
    timed_out: bool = False
    crash_pc: Optional[int] = None
    crash_addr: Optional[int] = None
    crash_access: Optional[str] = None
    reason: str = ""
    instructions: int = 0
    blocks: int = 0
    exit_code: Optional[int] = None
    # The guest dynamic loader failed to resolve the binary's shared libraries
    # / symbols, so the program never ran its own code. Any fault it then hits
    # is a loader artifact, not a real vulnerability -- callers drop such
    # crash-derived findings.
    load_incomplete: bool = False


class ExecutionBackend(abc.ABC):
    """Abstract base for everything that can run a target under observation."""

    #: short identifier, e.g. "unicorn", "qiling", "hardware"
    name: str = "backend"

    def __init__(self) -> None:
        # Target metadata, populated by load().
        self.arch: str = "unknown"
        self.endian: str = "little"
        self.pointer_size: int = 4
        self.entrypoint: int = 0
        self.loaded: bool = False
        #: optional {address: symbol_name} map used to name CallEvents
        self.symbols: Dict[int, str] = {}

    # -- lifecycle ---------------------------------------------------------

    @property
    @abc.abstractmethod
    def available(self) -> bool:
        """Whether this backend's dependencies are importable right now."""

    @abc.abstractmethod
    def load(self, target: str, **opts) -> None:
        """Prepare ``target`` for execution and populate metadata.

        Must set ``arch``, ``endian``, ``pointer_size``, ``entrypoint`` and
        ``loaded = True`` on success, or raise :class:`BackendError`.
        """

    @abc.abstractmethod
    def run(
        self,
        emit: EmitFn,
        *,
        max_instructions: int = 2_000_000,
        timeout_s: int = 30,
        begin: Optional[int] = None,
        until: Optional[int] = None,
    ) -> RunOutcome:
        """Execute, calling ``emit`` once per :class:`TraceEvent`.

        ``begin``/``until`` optionally restrict execution to a single function
        (harness mode). Backends must never let a target fault crash the host:
        an invalid access is reported as a ``MemEvent(mapped=False)`` and/or a
        crashing :class:`RunOutcome`, not a raised exception.
        """

    def close(self) -> None:
        """Release any resources. Safe to call multiple times."""
        self.loaded = False

    # -- inspection (used by detectors) ------------------------------------

    @abc.abstractmethod
    def read_mem(self, addr: int, size: int) -> bytes:
        """Read ``size`` bytes at ``addr``; return ``b""`` if unreadable."""

    def read_cstring(self, addr: int, max_len: int = 256) -> bytes:
        """Read a NUL-terminated string (without the NUL). Best-effort."""
        if addr == 0:
            return b""
        out = bytearray()
        chunk = 32
        while len(out) < max_len:
            data = self.read_mem(addr + len(out), chunk)
            if not data:
                break
            nul = data.find(b"\x00")
            if nul != -1:
                out += data[:nul]
                break
            out += data
        return bytes(out[:max_len])

    def read_reg(self, name: str) -> int:  # pragma: no cover - backend specific
        """Read a named register. Optional; default raises."""
        raise BackendError(f"{self.name}: register read not supported")

    def read_ptr(self, addr: int) -> int:
        """Read one pointer-sized word at ``addr``."""
        data = self.read_mem(addr, self.pointer_size)
        if len(data) < self.pointer_size:
            return 0
        return int.from_bytes(data, "big" if self.endian == "big" else "little")


class MockBackend(ExecutionBackend):
    """A scripted backend for tests and for exercising detectors offline.

    Construct it with a list of events to replay and an optional ``memory``
    dict ``{addr: bytes}`` serving :meth:`read_mem`. No native dependencies.
    """

    name = "mock"

    def __init__(
        self,
        events: Optional[Iterable[TraceEvent]] = None,
        memory: Optional[Dict[int, bytes]] = None,
        *,
        arch: str = "arm",
        endian: str = "little",
        pointer_size: int = 4,
        outcome: Optional[RunOutcome] = None,
        regs: Optional[Dict[str, int]] = None,
    ) -> None:
        super().__init__()
        self._events: List[TraceEvent] = list(events or [])
        self._memory: Dict[int, bytes] = dict(memory or {})
        self._regs: Dict[str, int] = dict(regs or {})
        self.arch = arch
        self.endian = endian
        self.pointer_size = pointer_size
        self._outcome = outcome or RunOutcome(completed=True)

    @property
    def available(self) -> bool:
        return True

    def load(self, target: str, **opts) -> None:
        self.loaded = True
        self.entrypoint = opts.get("entrypoint", 0)

    def run(self, emit: EmitFn, **kwargs) -> RunOutcome:
        for ev in self._events:
            emit(ev)
        return self._outcome

    def read_mem(self, addr: int, size: int) -> bytes:
        # Serve from any region that contains [addr, addr+size).
        for base, data in self._memory.items():
            if base <= addr < base + len(data):
                off = addr - base
                return data[off : off + size]
        return b""

    def read_reg(self, name: str) -> int:
        return self._regs.get(name, 0)


class HardwareBackend(ExecutionBackend):
    """Placeholder for the Raspberry-Pi hardware harness (future project).

    The hardware side is a separate build, but it lands here: a Pi-hosted agent
    (JTAG/SWD via OpenOCD, or a serial/GDB-stub monitor on the target) drives
    the real chip and reports the *same* events this module defines —
    ``BlockEvent`` from a trace/ETM or single-step loop, ``MemEvent`` from
    watchpoints, ``CallEvent`` from breakpoints on resolved symbols — while
    :meth:`read_mem`/:meth:`read_reg` are served over the debug transport.

    Because the detector pipeline only depends on :class:`ExecutionBackend`,
    implementing this class is all that is required to run EmberScan's
    vulnerability / leak / weak-code oracles against physical hardware. The
    methods raise until that harness exists, so wiring it in now is safe.
    """

    name = "hardware"

    def __init__(self, transport: Optional[object] = None) -> None:
        super().__init__()
        self.transport = transport

    @property
    def available(self) -> bool:
        return False

    def load(self, target: str, **opts) -> None:  # pragma: no cover - stub
        raise BackendUnavailable(
            "HardwareBackend is not implemented yet. It is the integration "
            "point for the Raspberry-Pi hardware harness: implement load/run/"
            "read_mem/read_reg over your debug transport (OpenOCD/GDB stub) and "
            "every existing detector will run unchanged on real hardware."
        )

    def run(self, emit: EmitFn, **kwargs) -> RunOutcome:  # pragma: no cover
        raise BackendUnavailable("HardwareBackend.run not implemented")

    def read_mem(self, addr: int, size: int) -> bytes:  # pragma: no cover
        raise BackendUnavailable("HardwareBackend.read_mem not implemented")
