"""
Backend-agnostic trace events and findings for EmberScan dynamic analysis.

The dynamic-analysis subsystem is built around a single idea: an *execution
backend* (an emulator today, real hardware tomorrow) produces a normalized
stream of :class:`TraceEvent` objects while a binary runs, and a set of
backend-agnostic *detectors* consume that stream and emit :class:`Finding`
objects.

Nothing in this module imports an emulator or EmberScan's data models, so it
stays trivially importable and unit-testable with a synthetic event stream.
The scanner layer is responsible for turning :class:`Finding` objects into
``emberscan.core.models.Vulnerability`` instances.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

# ---------------------------------------------------------------------------
# Memory access kinds
# ---------------------------------------------------------------------------

READ = "read"
WRITE = "write"
FETCH = "fetch"  # instruction fetch / execute


# ---------------------------------------------------------------------------
# Trace events
# ---------------------------------------------------------------------------


@dataclass
class TraceEvent:
    """Base class for all events emitted by an execution backend."""

    pc: int = 0  # program counter at the time of the event


@dataclass
class BlockEvent(TraceEvent):
    """A basic block began executing at ``pc`` (used for coverage)."""

    size: int = 0


@dataclass
class InsnEvent(TraceEvent):
    """A single instruction executed. Optional/expensive; off by default."""

    size: int = 0
    mnemonic: Optional[str] = None
    op_str: Optional[str] = None
    raw: Optional[bytes] = None


@dataclass
class MemEvent(TraceEvent):
    """A memory access.

    ``mapped`` is ``False`` for an access to unmapped/invalid memory, which is
    how backends report a crash-class fault (segfault analogue) to the
    detectors without raising.
    """

    access: str = READ  # READ / WRITE / FETCH
    addr: int = 0
    size: int = 0
    value: int = 0  # value written, or value read (best-effort)
    mapped: bool = True


@dataclass
class CallEvent(TraceEvent):
    """A resolved call into a known function.

    ``target`` is the callee address; ``name`` is its symbol if the backend
    could resolve one (e.g. a PLT entry, an imported libc symbol, or a
    user-supplied symbol map). ``args`` is a best-effort list of integer
    argument values read from registers/stack per the calling convention.
    """

    target: int = 0
    name: Optional[str] = None
    args: List[int] = field(default_factory=list)
    ret_addr: int = 0


@dataclass
class RetEvent(TraceEvent):
    """Return from a function previously entered via a :class:`CallEvent`."""

    name: Optional[str] = None
    retval: int = 0


@dataclass
class TaintSourceEvent(TraceEvent):
    """Untrusted input entered the program at ``addr`` (length ``size``).

    Emitted either by the backend (when it models an input syscall such as
    ``read``/``recv``) or synthesized by the harness when it writes a fuzz/seed
    input into a known buffer. ``label`` names the source (``"stdin"``,
    ``"recv"``, ``"nvram_get"``, ``"argv"`` ...).
    """

    addr: int = 0
    size: int = 0
    label: str = "input"


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------

# Severity strings understood by the scanner mapper (mirror of models.Severity).
CRITICAL = "critical"
HIGH = "high"
MEDIUM = "medium"
LOW = "low"
INFO = "info"


@dataclass
class Finding:
    """A single dynamic-analysis result, independent of EmberScan's models.

    ``vuln_type`` is a lowercase key that the scanner maps onto
    ``VulnerabilityType`` (falls back to ``OTHER`` if unknown), so detectors
    never need to import the models layer.
    """

    category: str  # detector category, e.g. "memory_safety"
    title: str
    description: str
    severity: str = INFO
    vuln_type: str = "other"
    cwe: Optional[str] = None
    pc: Optional[int] = None
    function: Optional[str] = None
    evidence: str = ""
    remediation: str = ""
    confidence: float = 0.8
    detector: str = ""  # filled in by the pipeline
    metadata: Dict[str, Any] = field(default_factory=dict)

    def key(self) -> tuple:
        """Dedupe key: same defect at the same site is one finding."""
        return (self.category, self.title, self.pc, self.function)
