"""Dynamic-analysis detectors (backend-agnostic)."""

from __future__ import annotations

from typing import Dict, List, Type

from .base import Detector, DetectorPipeline, RunContext
from .info_leak import InfoLeakDetector
from .memory_safety import MemorySafetyDetector
from .taint import TaintDetector
from .weak_code import WeakCodeDetector

#: name -> Detector class, for config-driven selection
REGISTRY: Dict[str, Type[Detector]] = {
    "memory_safety": MemorySafetyDetector,
    "taint": TaintDetector,
    "info_leak": InfoLeakDetector,
    "weak_code": WeakCodeDetector,
}

DEFAULT_DETECTORS: List[str] = list(REGISTRY.keys())


def build_detectors(names: List[str] = None) -> List[Detector]:
    """Instantiate detectors by name (unknown names are skipped)."""
    names = names or DEFAULT_DETECTORS
    out: List[Detector] = []
    for n in names:
        cls = REGISTRY.get(n)
        if cls:
            out.append(cls())
    return out


__all__ = [
    "Detector",
    "DetectorPipeline",
    "RunContext",
    "MemorySafetyDetector",
    "TaintDetector",
    "InfoLeakDetector",
    "WeakCodeDetector",
    "REGISTRY",
    "DEFAULT_DETECTORS",
    "build_detectors",
]
