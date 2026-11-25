"""
Information-leak detector ("code leaks" / disclosure, at runtime).

Two oracles over the event stream:

* **Format-string** (CWE-134): a ``printf``-family call whose *format* argument
  is attacker-tainted, or whose format string literal contains ``%n`` — the
  classic read/write-anything-and-leak primitive. Tainted format => HIGH;
  a suspicious ``%n`` literal => MEDIUM.
* **Secret egress** (CWE-200): a region the harness labelled as secret
  (``TaintSourceEvent`` with a ``secret*`` label — e.g. a key or shadow entry
  loaded into memory) reaches a network/file egress sink (``send``/``write``/
  ``fwrite``/``puts`` ...). This stays dormant until a secret is labelled, so
  it never fires spuriously on an ordinary run.

Format-string detection reuses the shared taint tracker so it sees the same
propagated input as the taint detector; secret tracking is kept in a separate
map so secret labels never bleed into the other detectors' sink logic.
"""

from __future__ import annotations

from .base import Detector
from ._shadow import TaintTracker, TaintMap
from ..events import CallEvent, RetEvent, TaintSourceEvent, HIGH, MEDIUM

# printf-family -> index of the format-string argument
_FORMAT_FUNCS = {
    "printf": 0, "vprintf": 0, "fprintf": 1, "vfprintf": 1, "dprintf": 1,
    "sprintf": 1, "vsprintf": 1, "snprintf": 2, "vsnprintf": 2,
    "asprintf": 1, "syslog": 1, "err": 1, "warn": 1, "errx": 1, "warnx": 1,
}
# egress sinks -> index of the data-buffer argument
_EGRESS_FUNCS = {
    "send": 1, "sendto": 1, "write": 1, "fwrite": 0, "puts": 0, "fputs": 0,
}


class InfoLeakDetector(Detector):
    category = "info_leak"

    def __init__(self) -> None:
        super().__init__()
        self.taint = TaintTracker()
        self.secrets = TaintMap()
        self._reported = set()

    def on_source(self, ev: TaintSourceEvent) -> None:
        self.taint.source(ev)
        if (ev.label or "").startswith("secret") and ev.size > 0:
            self.secrets.add(ev.addr, ev.addr + ev.size, ev.label)

    def on_ret(self, ev: RetEvent) -> None:
        self.taint.ret(ev)

    def on_call(self, ev: CallEvent) -> None:
        name = (ev.name or "").lstrip("_")
        self.taint.call(ev, self.ctx.read_cstring)

        if name in _FORMAT_FUNCS:
            self._check_format(ev, name, _FORMAT_FUNCS[name])
        if name in _EGRESS_FUNCS:
            self._check_secret_egress(ev, name, _EGRESS_FUNCS[name])

    # -- format string --------------------------------------------------------
    def _check_format(self, ev: CallEvent, name: str, idx: int) -> None:
        if len(ev.args) <= idx:
            return
        fmt_ptr = ev.args[idx]
        if not fmt_ptr:
            return
        label = self.taint.tainted_ptr(fmt_ptr, self.ctx.read_cstring)
        fmt = self.ctx.read_cstring(fmt_ptr, 200)
        if label:
            self._raise(
                ("fmt", ev.pc, name),
                title=f"Format-string vulnerability in {name}()",
                description=f"The format argument of {name}() is attacker-"
                            f"tainted ({label}); this leaks memory via %x/%s and "
                            f"can write via %n.",
                severity=HIGH, vuln_type="format_string", cwe="CWE-134",
                pc=ev.pc, function=name, confidence=0.9,
                evidence=f"{name}(fmt=0x{fmt_ptr:x} [tainted] = "
                         f"{fmt[:60]!r})",
                remediation=f'Use a fixed format: {name}("%s", user_data).',
            )
        elif b"%n" in fmt:
            self._raise(
                ("fmtn", ev.pc, name),
                title=f"Dangerous %n format specifier in {name}()",
                description=f"The format string passed to {name}() contains %n, "
                            f"a memory-write primitive. Confirm it is not "
                            f"reachable with attacker-influenced state.",
                severity=MEDIUM, vuln_type="format_string", cwe="CWE-134",
                pc=ev.pc, function=name, confidence=0.5,
                evidence=f"fmt={fmt[:80]!r}",
                remediation="Remove %n; it is disabled by FORTIFY for good reason.",
            )

    # -- secret egress --------------------------------------------------------
    def _check_secret_egress(self, ev: CallEvent, name: str, idx: int) -> None:
        if not self.secrets or len(ev.args) <= idx:
            return
        buf = ev.args[idx]
        if not buf:
            return
        slen = len(self.ctx.read_cstring(buf)) or 1
        label = self.secrets.overlaps(buf, buf + slen)
        if label:
            self._raise(
                ("leak", ev.pc, name),
                title=f"Secret data written to {name}()",
                description=f"Data labelled '{label}' is passed to {name}(), an "
                            f"egress sink — potential disclosure of secret "
                            f"material.",
                severity=HIGH, vuln_type="info_disclosure", cwe="CWE-200",
                pc=ev.pc, function=name, confidence=0.7,
                evidence=f"{name}(buf=0x{buf:x} overlaps secret '{label}')",
                remediation="Do not transmit key material; redact before output.",
            )

    def _raise(self, key, **kw) -> None:
        if key in self._reported:
            return
        self._reported.add(key)
        self._add(**kw)
