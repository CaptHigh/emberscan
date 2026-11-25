"""
Taint detector: untrusted input reaching a dangerous sink.

Sources are either reported by the backend as ``TaintSourceEvent`` or inferred
from calls to input-returning libc functions (``read``/``recv``/``fgets``/
``nvram_get`` ...); both are handled by the shared :class:`TaintTracker`, which
also propagates taint through the common copy functions. A finding is raised
when a tainted buffer reaches:

* a command-execution sink (``system``/``popen``/``exec*`` and router variants
  such as ``doSystem``) -> command injection (CWE-78), or
* an unbounded string copy (``strcpy``/``strcat``/``sprintf``/``gets``) ->
  overflow primitive (CWE-120 / CWE-242).

Scalar "attacker-controlled size" taint (e.g. a tainted ``memcpy`` length)
needs register-level shadow and is intentionally out of scope here; buffer
taint, which drives most real firmware bugs, is precise.
"""

from __future__ import annotations

from ..events import CRITICAL, HIGH, CallEvent, RetEvent, TaintSourceEvent
from ._shadow import TaintTracker
from .base import Detector

_CMD_SINKS = {
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
    "CsteSystem",
    "bstar_system",
    "twsystem",
    "ExeCmd",
    "runCommand",
}
_OVERFLOW_SINKS = {"strcpy", "strcat", "stpcpy", "sprintf", "vsprintf"}
_ALWAYS_UNSAFE = {"gets"}


class TaintDetector(Detector):
    category = "taint"

    def __init__(self) -> None:
        super().__init__()
        self.tracker = TaintTracker()
        self._reported = set()

    def on_source(self, ev: TaintSourceEvent) -> None:
        self.tracker.source(ev)

    def on_ret(self, ev: RetEvent) -> None:
        self.tracker.ret(ev)

    def on_call(self, ev: CallEvent) -> None:
        name = (ev.name or "").lstrip("_")
        self.tracker.call(ev, self.ctx.read_cstring)  # sourcing + propagation

        if name in _CMD_SINKS:
            self._check_cmd_sink(ev, name)
        elif name in _OVERFLOW_SINKS:
            self._check_overflow_sink(ev, name)
        elif name in _ALWAYS_UNSAFE:
            self._flag_gets(ev, name)

    # -- sink checks ----------------------------------------------------------
    def _check_cmd_sink(self, ev: CallEvent, name: str) -> None:
        for idx in (0, 1):
            if len(ev.args) <= idx:
                break
            ptr = ev.args[idx]
            label = self.tracker.tainted_ptr(ptr, self.ctx.read_cstring)
            if label:
                sample = self.ctx.read_cstring(ptr, 120).decode("latin-1", "replace")
                self._raise(
                    ("cmd", ev.pc, name),
                    title=f"Command injection via {name}()",
                    description=f"Untrusted data ({label}) reaches the command "
                    f"string of {name}() — an attacker-controlled "
                    f"shell command.",
                    severity=CRITICAL,
                    vuln_type="command_injection",
                    cwe="CWE-78",
                    pc=ev.pc,
                    function=name,
                    confidence=0.9,
                    evidence=f"{name}(arg{idx}=0x{ptr:x} -> {sample!r})",
                    remediation="Never pass untrusted data to a shell; use "
                    "exec* with a fixed argv and validate inputs.",
                )
                return

    def _check_overflow_sink(self, ev: CallEvent, name: str) -> None:
        if len(ev.args) <= 1:
            return
        src = ev.args[1]
        label = self.tracker.tainted_ptr(src, self.ctx.read_cstring)
        if label:
            dst = ev.args[0]
            self._raise(
                ("ovf", ev.pc, name),
                title=f"Tainted data into unbounded {name}()",
                description=f"Untrusted data ({label}) is copied by {name}() "
                f"with no bound — stack/heap overflow primitive.",
                severity=HIGH,
                vuln_type="buffer_overflow",
                cwe="CWE-120",
                pc=ev.pc,
                function=name,
                confidence=0.75,
                evidence=f"{name}(dst=0x{dst:x}, src=0x{src:x} [tainted])",
                remediation=f"Replace {name} with a bounded equivalent "
                f"(strlcpy/snprintf) and validate length.",
            )

    def _flag_gets(self, ev: CallEvent, name: str) -> None:
        self._raise(
            ("gets", ev.pc, name),
            title="Reachable gets() call",
            description="gets() cannot be used safely and is reachable under "
            "the emulated input.",
            severity=HIGH,
            vuln_type="buffer_overflow",
            cwe="CWE-242",
            pc=ev.pc,
            function=name,
            confidence=0.9,
            evidence=f"gets() at pc=0x{ev.pc:x}",
            remediation="Replace gets() with fgets() and a size bound.",
        )

    def _raise(self, key, **kw) -> None:
        if key in self._reported:
            return
        self._reported.add(key)
        self._add(**kw)
