"""
Shared taint shadow-memory and a reusable taint tracker.

``TaintMap`` is a coalescing interval set over tainted byte ranges.
``TaintTracker`` layers the standard source/propagation policy on top of it
(input-returning libc functions become sources; the common copy functions
propagate taint) so the taint and info-leak detectors share one consistent
notion of "tainted" without depending on each other.
"""

from __future__ import annotations

from typing import Dict, List, Optional, Tuple


class TaintMap:
    """Coalescing set of tainted byte intervals ``[lo, hi)`` with a label."""

    def __init__(self, max_intervals: int = 8192) -> None:
        self._iv: List[List] = []  # sorted, non-overlapping [lo, hi, label]
        self._max = max_intervals

    def add(self, lo: int, hi: int, label: str = "input") -> None:
        if hi <= lo:
            return
        self._iv.append([lo, hi, label])
        self._iv.sort(key=lambda x: x[0])
        merged: List[List] = []
        for lo2, hi2, lab in self._iv:
            if merged and lo2 <= merged[-1][1]:
                if hi2 > merged[-1][1]:
                    merged[-1][1] = hi2
            else:
                merged.append([lo2, hi2, lab])
        if len(merged) > self._max:
            merged = merged[: self._max]
        self._iv = merged

    def label_at(self, addr: int) -> Optional[str]:
        for lo, hi, lab in self._iv:
            if lo <= addr < hi:
                return lab
        return None

    def overlaps(self, lo: int, hi: int) -> Optional[str]:
        if hi <= lo:
            hi = lo + 1
        for ilo, ihi, lab in self._iv:
            if ilo < hi and lo < ihi:
                return lab
        return None

    def __bool__(self) -> bool:
        return bool(self._iv)

    def __len__(self) -> int:
        return len(self._iv)


# libc copy-like functions and how to read their (dst, src, n).
_N_ARG = {"memcpy": 2, "memmove": 2, "strncpy": 2, "strncat": 2,
          "strlcpy": 2, "strlcat": 2}
_STR_SRC = {"strcpy", "strcat", "stpcpy", "sprintf", "vsprintf"}
ALL_COPY_FUNCS = set(_N_ARG) | _STR_SRC | {"bcopy"}

# input functions whose destination buffer is a taint source.
# name -> (buf_arg_index, length spec: int index | ("mul", i, j) | ("const", n))
_INPUT_BUF = {
    "read": (1, 2), "recv": (1, 2), "recvfrom": (1, 2),
    "fgets": (0, 1), "fread": (0, ("mul", 1, 2)),
    "gets": (0, ("const", 256)),
}
# input functions returning a freshly-populated pointer (taint on return).
_INPUT_RET = {"nvram_get", "nvram_safe_get", "getenv", "websGetVar",
              "webGetVar", "GetValue", "get_cgi"}


def copy_spec(ev, read_cstring) -> Optional[Tuple[int, int, int]]:
    """Resolve ``(dst, src, length)`` for a copy-style call, else ``None``."""
    name = (ev.name or "").lstrip("_")
    args = ev.args
    if name == "bcopy":  # bcopy(src, dst, n)
        return (args[1], args[0], args[2]) if len(args) >= 3 else None
    if name in _N_ARG:
        return (args[0], args[1], args[2]) if len(args) >= 3 else None
    if name in _STR_SRC and len(args) >= 2:
        src = args[1]
        n = len(read_cstring(src)) if src else 0
        return (args[0], src, n)
    return None


def _resolve_len(spec, args) -> int:
    if isinstance(spec, int):
        return args[spec] if len(args) > spec else 0
    if isinstance(spec, tuple):
        if spec[0] == "const":
            return spec[1]
        if spec[0] == "mul" and len(args) > max(spec[1], spec[2]):
            return args[spec[1]] * args[spec[2]]
    return 0


class TaintTracker:
    """Maintains a :class:`TaintMap` under the standard source/propagation policy."""

    def __init__(self) -> None:
        self.tmap = TaintMap()
        self._pending_ret: Dict[str, List[int]] = {}

    def source(self, ev) -> None:
        if ev.size > 0:
            self.tmap.add(ev.addr, ev.addr + ev.size, ev.label or "input")

    def call(self, ev, read_cstring) -> None:
        name = (ev.name or "").lstrip("_")
        args = ev.args
        spec = _INPUT_BUF.get(name)
        if spec and args:
            buf = args[spec[0]] if len(args) > spec[0] else 0
            n = _resolve_len(spec[1], args)
            if buf and n:
                self.tmap.add(buf, buf + n, name)
        if name in _INPUT_RET:
            self._pending_ret.setdefault(name, []).append(256)
        if name in ALL_COPY_FUNCS:
            cs = copy_spec(ev, read_cstring)
            if cs:
                dst, src, n = cs
                if n and src and self.tmap.overlaps(src, src + max(n, 1)):
                    self.tmap.add(dst, dst + max(n, 1), "input")

    def ret(self, ev) -> None:
        name = (ev.name or "").lstrip("_")
        pend = self._pending_ret.get(name)
        if pend:
            n = pend.pop(0)
            if ev.retval:
                self.tmap.add(ev.retval, ev.retval + n, name)

    # queries -----------------------------------------------------------------
    def tainted_ptr(self, ptr: int, read_cstring) -> Optional[str]:
        if not ptr:
            return None
        slen = len(read_cstring(ptr))
        return self.tmap.overlaps(ptr, ptr + max(slen, 1))
