"""
EmberScan dynamic-analysis subsystem.

Load a binary, emulate its code, and run backend-agnostic detectors over the
resulting event stream to find vulnerabilities, information leaks, and weak
code at runtime.

Layering (top to bottom):

* :class:`~emberscan.dynamic.harness.EmulationRunner` — selects targets, runs a
  backend under the detector pipeline, returns findings.
* :mod:`~emberscan.dynamic.detectors` — memory-safety, taint, info-leak,
  weak-code oracles that consume :mod:`~emberscan.dynamic.events`.
* :class:`~emberscan.dynamic.backend.ExecutionBackend` — Unicorn (bare-metal),
  Qiling (Linux user-space), and the future hardware harness, all emitting the
  same events.

The scanner wrapper (``emberscan.scanners.emulation_scanner``) adapts findings
to EmberScan's ``Vulnerability`` model.
"""

from __future__ import annotations

from typing import Optional

from .backend import (
    BackendError,
    BackendUnavailable,
    ExecutionBackend,
    HardwareBackend,
    MockBackend,
    RunOutcome,
)
from .detectors import DEFAULT_DETECTORS, DetectorPipeline, build_detectors
from .harness import EmulationRunner, select_binaries
from .qiling_backend import QilingBackend
from .unicorn_backend import UnicornBackend

_BACKENDS = {
    "unicorn": UnicornBackend,
    "qiling": QilingBackend,
    "mock": MockBackend,
    "hardware": HardwareBackend,
}


def get_backend(name: str = "auto") -> ExecutionBackend:
    """Return a backend instance.

    ``"auto"`` prefers Qiling (full Linux user-space) and falls back to Unicorn
    (bare-metal) based on what is installed.
    """
    if name == "auto":
        q = QilingBackend()
        if q.available:
            return q
        return UnicornBackend()
    cls = _BACKENDS.get(name)
    if cls is None:
        raise BackendError(f"unknown backend: {name}")
    return cls()


__all__ = [
    "ExecutionBackend",
    "MockBackend",
    "HardwareBackend",
    "UnicornBackend",
    "QilingBackend",
    "RunOutcome",
    "BackendError",
    "BackendUnavailable",
    "DetectorPipeline",
    "build_detectors",
    "DEFAULT_DETECTORS",
    "EmulationRunner",
    "select_binaries",
    "get_backend",
]
