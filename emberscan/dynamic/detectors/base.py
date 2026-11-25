"""
Detector base class and pipeline.

A :class:`Detector` subscribes to the backend event stream (one no-op hook per
event type, override what you need) and returns a list of
:class:`~emberscan.dynamic.events.Finding` objects at the end of a run. The
:class:`DetectorPipeline` fans every event out to all detectors, isolates
detector exceptions, and de-duplicates the merged findings.

Detectors are backend-agnostic by construction: they receive a
:class:`RunContext` that exposes ``read_mem`` / ``read_reg`` without knowing
whether the bytes come from Unicorn, Qiling, or real hardware.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any

from ..backend import ExecutionBackend
from ..events import (
    TraceEvent,
    BlockEvent,
    InsnEvent,
    MemEvent,
    CallEvent,
    RetEvent,
    TaintSourceEvent,
    Finding,
    INFO,
)

logger = logging.getLogger(__name__)


@dataclass
class RunContext:
    """Per-run context handed to each detector at ``on_start``."""

    backend: ExecutionBackend
    binary_path: str = ""
    label: str = ""
    arch: str = "unknown"
    endian: str = "little"
    pointer_size: int = 4
    entrypoint: int = 0
    symbols: Dict[int, str] = field(default_factory=dict)
    options: Dict[str, Any] = field(default_factory=dict)

    # convenience delegations -------------------------------------------------
    def read_mem(self, addr: int, size: int) -> bytes:
        return self.backend.read_mem(addr, size)

    def read_cstring(self, addr: int, max_len: int = 256) -> bytes:
        return self.backend.read_cstring(addr, max_len)

    def read_reg(self, name: str) -> int:
        return self.backend.read_reg(name)


class Detector:
    """Base detector. Override the hooks you care about."""

    #: short category slug, surfaces on every Finding (e.g. "memory_safety")
    category: str = "generic"

    def __init__(self) -> None:
        self.ctx: Optional[RunContext] = None
        self._findings: List[Finding] = []

    # lifecycle ---------------------------------------------------------------
    def on_start(self, ctx: RunContext) -> None:
        self.ctx = ctx

    def finalize(self) -> List[Finding]:
        return self._findings

    # event hooks (default no-ops) -------------------------------------------
    def on_block(self, ev: BlockEvent) -> None: ...
    def on_insn(self, ev: InsnEvent) -> None: ...
    def on_mem(self, ev: MemEvent) -> None: ...
    def on_call(self, ev: CallEvent) -> None: ...
    def on_ret(self, ev: RetEvent) -> None: ...
    def on_source(self, ev: TaintSourceEvent) -> None: ...

    # helper ------------------------------------------------------------------
    def _add(
        self,
        title: str,
        description: str,
        severity: str = INFO,
        vuln_type: str = "other",
        **kwargs,
    ) -> Finding:
        f = Finding(
            category=self.category,
            title=title,
            description=description,
            severity=severity,
            vuln_type=vuln_type,
            detector=type(self).__name__,
            **kwargs,
        )
        self._findings.append(f)
        return f


class DetectorPipeline:
    """Fans events out to detectors and collects de-duplicated findings."""

    def __init__(self, detectors: List[Detector]) -> None:
        self.detectors = detectors

    def run_on(
        self,
        backend: ExecutionBackend,
        ctx: RunContext,
        prelude: Optional[List[TraceEvent]] = None,
        **run_kwargs,
    ) -> List[Finding]:
        """Start detectors, run the backend, finalize, and merge findings.

        ``prelude`` events (e.g. seed :class:`TaintSourceEvent` objects written
        by the harness) are delivered to the detectors before execution starts.
        """
        for det in self.detectors:
            try:
                det.on_start(ctx)
            except Exception as exc:  # pragma: no cover - defensive
                logger.error("detector %s on_start failed: %s", det.category, exc)

        emit = self._make_emit()
        for ev in (prelude or []):
            emit(ev)

        outcome = backend.run(emit, **run_kwargs)
        ctx.options["outcome"] = outcome

        findings: List[Finding] = []
        for det in self.detectors:
            try:
                findings.extend(det.finalize())
            except Exception as exc:  # pragma: no cover - defensive
                logger.error("detector %s finalize failed: %s", det.category, exc)

        return self._dedupe(findings)

    # -- internals ------------------------------------------------------------
    def _make_emit(self):
        # Route each event type to the matching hook on every detector.
        dispatch = {
            BlockEvent: "on_block",
            InsnEvent: "on_insn",
            MemEvent: "on_mem",
            CallEvent: "on_call",
            RetEvent: "on_ret",
            TaintSourceEvent: "on_source",
        }

        def emit(ev: TraceEvent) -> None:
            hook = dispatch.get(type(ev))
            if hook is None:
                return
            for det in self.detectors:
                try:
                    getattr(det, hook)(ev)
                except Exception as exc:  # pragma: no cover - defensive
                    logger.debug("detector %s %s failed: %s", det.category, hook, exc)

        return emit

    @staticmethod
    def _dedupe(findings: List[Finding]) -> List[Finding]:
        seen: Dict[tuple, Finding] = {}
        for f in findings:
            k = f.key()
            # keep the highest-confidence instance of an identical finding
            if k not in seen or f.confidence > seen[k].confidence:
                seen[k] = f
        return list(seen.values())
