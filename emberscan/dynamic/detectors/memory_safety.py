"""
Memory-safety detector (ASAN-style, driven by the event stream).

Catches at runtime what static analysis only guesses at:

* faulting accesses (unmapped / NULL) reported by the backend as
  ``MemEvent(mapped=False)`` -> out-of-bounds or NULL-deref,
* heap red-zone violations and use-after-free / double-free, tracked from
  ``malloc``/``calloc``/``realloc``/``free`` call+return events plus the
  memory-access stream.

It needs no source and no symbols beyond the allocator names; the backend
supplies allocation sizes (call args) and returned pointers (return values).
"""

from __future__ import annotations

from typing import Dict, List, Optional

from .base import Detector, RunContext
from ..events import (
    MemEvent,
    CallEvent,
    RetEvent,
    WRITE,
    READ,
    CRITICAL,
    HIGH,
    MEDIUM,
)

REDZONE = 16  # bytes guarded on each side of a heap allocation


class _Alloc:
    __slots__ = ("base", "size", "alive", "alloc_pc")

    def __init__(self, base: int, size: int, pc: int) -> None:
        self.base = base
        self.size = size
        self.alive = True
        self.alloc_pc = pc


class MemorySafetyDetector(Detector):
    category = "memory_safety"

    _ALLOCATORS = {
        "malloc",
        "calloc",
        "realloc",
        "valloc",
        "memalign",
        "posix_memalign",
        "aligned_alloc",
        "reallocarray",
    }

    def __init__(self, max_per_kind: int = 25) -> None:
        super().__init__()
        self._allocs: Dict[int, _Alloc] = {}
        self._await: Dict[str, List[dict]] = {}
        self._freed: List[_Alloc] = []
        self._max = max_per_kind
        self._counts: Dict[str, int] = {}
        # Allocator calls in flight (call seen, return not yet). The allocator
        # itself legitimately touches chunk headers and freed blocks (tcache
        # links), so heap checks are paused until it returns.
        self._inside: List[str] = []
        # Pointers whose free() is in flight: glibc's first free() re-enters
        # free(p) on the same pointer after initialising the tcache.
        self._freeing: List[int] = []

    # -- allocator bookkeeping ------------------------------------------------
    def on_call(self, ev: CallEvent) -> None:
        name = (ev.name or "").lstrip("_")
        if name in self._ALLOCATORS or name == "free":
            self._inside.append(name)
        elif self._inside:
            # A non-allocator call while "inside" malloc means we missed the
            # allocator's return; don't leave heap checking paused forever.
            self._inside.clear()
            self._freeing.clear()
        if name in self._ALLOCATORS:
            size = ev.args[0] if ev.args else 0
            if name == "calloc" and len(ev.args) >= 2:
                size = ev.args[0] * ev.args[1]
            elif name in ("realloc", "reallocarray") and len(ev.args) >= 2:
                size = ev.args[1] if name == "realloc" else ev.args[1] * ev.args[0]
            old = ev.args[0] if name.startswith("realloc") and ev.args else 0
            self._await.setdefault(name, []).append({"size": size, "old": old, "pc": ev.pc})
        elif name == "free":
            ptr = ev.args[0] if ev.args else 0
            if ptr and ptr in self._freeing:
                self._freeing.append(ptr)  # re-entrant free of the same block
                return
            self._freeing.append(ptr)
            self._handle_free(ptr, ev.pc)

    def on_ret(self, ev: RetEvent) -> None:
        name = (ev.name or "").lstrip("_")
        if name in self._inside:
            idx = len(self._inside) - 1 - self._inside[::-1].index(name)
            del self._inside[idx]
        if name == "free" and self._freeing:
            self._freeing.pop()
        pend = self._await.get(name)
        if not pend:
            return
        info = pend.pop(0)
        ptr = ev.retval
        if name.startswith("realloc") and info["old"]:
            self._mark_freed(info["old"])
        if ptr:
            self._allocs[ptr] = _Alloc(ptr, int(info["size"]), info["pc"])

    def _handle_free(self, ptr: int, pc: int) -> None:
        if ptr == 0:
            return  # free(NULL) is legal
        alloc = self._allocs.get(ptr)
        if alloc is None:
            # Freeing a pointer we never saw allocated. Could be a static/global
            # buffer; report with modest confidence.
            if self._bump("invalid_free"):
                self._add(
                    title="Invalid free()",
                    description=f"free() called on 0x{ptr:x}, which was not "
                    f"returned by a tracked allocation.",
                    severity=MEDIUM,
                    vuln_type="memory_corruption",
                    cwe="CWE-590",
                    pc=pc,
                    confidence=0.4,
                    evidence=f"free(0x{ptr:x}) at pc=0x{pc:x}",
                    remediation="Only free() pointers returned by *alloc; set "
                    "pointers to NULL after freeing.",
                )
            return
        if not alloc.alive:
            if self._bump("double_free"):
                self._add(
                    title="Double free",
                    description=f"Heap block 0x{ptr:x} freed more than once.",
                    severity=HIGH,
                    vuln_type="memory_corruption",
                    cwe="CWE-415",
                    pc=pc,
                    confidence=0.9,
                    evidence=f"second free(0x{ptr:x}) at pc=0x{pc:x}",
                    remediation="Track ownership; NULL the pointer after free.",
                )
            return
        self._mark_freed(ptr)

    def _mark_freed(self, ptr: int) -> None:
        alloc = self._allocs.get(ptr)
        if alloc and alloc.alive:
            alloc.alive = False
            self._freed.append(alloc)

    # -- access checking ------------------------------------------------------
    def on_mem(self, ev: MemEvent) -> None:
        if not ev.mapped:
            self._report_fault(ev)
            return
        self._check_heap(ev)

    def _report_fault(self, ev: MemEvent) -> None:
        is_write = ev.access == WRITE
        null = ev.addr < 0x1000
        if null:
            kind = "null_deref"
            title = f"NULL-pointer dereference ({'write' if is_write else 'read'})"
            sev = HIGH if is_write else MEDIUM
            cwe = "CWE-476"
            vt = "memory_corruption"
        else:
            kind = "oob_write" if is_write else "oob_read"
            title = f"Out-of-bounds {'write' if is_write else 'read'} (faulting access)"
            sev = CRITICAL if is_write else HIGH
            cwe = "CWE-787" if is_write else "CWE-125"
            vt = "buffer_overflow" if is_write else "info_disclosure"
        if not self._bump(kind):
            return
        self._add(
            title=title,
            description=f"Access to unmapped address 0x{ev.addr:x} "
            f"(size {ev.size}) at pc=0x{ev.pc:x} faulted during "
            f"emulation.",
            severity=sev,
            vuln_type=vt,
            cwe=cwe,
            pc=ev.pc,
            confidence=0.85,
            evidence=f"{ev.access} {ev.size}B @ 0x{ev.addr:x}, pc=0x{ev.pc:x}",
            remediation="Validate indices/lengths before access; this address "
            "is reachable under the emulated input.",
            metadata={"fault_addr": ev.addr, "kind": kind},
        )

    def _check_heap(self, ev: MemEvent) -> None:
        if self._inside:
            return  # allocator internals: chunk headers, free-list links
        addr, end = ev.addr, ev.addr + max(ev.size, 1)
        # Real heaps pack chunks tightly, so a neighbour's red zone overlaps
        # this block. An access inside any live block is in bounds.
        for alloc in self._allocs.values():
            if alloc.alive and alloc.base <= addr and end <= alloc.base + alloc.size:
                return
        for alloc in self._allocs.values():
            if not alloc.alive:
                continue
            lo, hi = alloc.base, alloc.base + alloc.size
            if addr < lo and end > lo - REDZONE:
                self._heap_finding(ev, alloc, "underflow")
                return
            if addr >= hi and addr < hi + REDZONE:
                self._heap_finding(ev, alloc, "overflow")
                return
        for alloc in self._freed:
            if alloc.base <= addr < alloc.base + alloc.size:
                if self._bump("uaf"):
                    self._add(
                        title=f"Use-after-free ({'write' if ev.access == WRITE else 'read'})",
                        description=f"Access to freed heap block 0x{alloc.base:x} "
                        f"at pc=0x{ev.pc:x}.",
                        severity=HIGH,
                        vuln_type="use_after_free",
                        cwe="CWE-416",
                        pc=ev.pc,
                        confidence=0.85,
                        evidence=f"{ev.access} @ 0x{ev.addr:x} in freed block "
                        f"0x{alloc.base:x}+{alloc.size}",
                        remediation="Do not use pointers after free(); NULL them.",
                    )
                return

    def _heap_finding(self, ev: MemEvent, alloc: _Alloc, kind: str) -> None:
        is_write = ev.access == WRITE
        if not self._bump(f"heap_{kind}_{'w' if is_write else 'r'}"):
            return
        self._add(
            title=f"Heap {kind} ({'write' if is_write else 'read'})",
            description=f"Access 0x{ev.addr:x} lies in the red-zone "
            f"{kind} of heap block 0x{alloc.base:x} "
            f"(size {alloc.size}).",
            severity=HIGH if is_write else MEDIUM,
            vuln_type="buffer_overflow" if is_write else "info_disclosure",
            cwe="CWE-122",
            pc=ev.pc,
            confidence=0.75,
            evidence=f"{ev.access} @ 0x{ev.addr:x}, block 0x{alloc.base:x}"
            f"+{alloc.size}, alloc pc=0x{alloc.alloc_pc:x}",
            remediation="Bound the write/read to the allocation size.",
        )

    # -- helpers --------------------------------------------------------------
    def _bump(self, kind: str) -> bool:
        n = self._counts.get(kind, 0)
        self._counts[kind] = n + 1
        return n < self._max
