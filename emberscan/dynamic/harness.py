"""
Harness: target selection and the run loop that ties a backend to the
detector pipeline.

:func:`select_binaries` walks an extracted rootfs and returns ELF binaries,
network-facing/interesting ones first. :class:`EmulationRunner` loads a binary
into a backend, runs it under the detector pipeline, and returns the findings
plus the run outcome.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

from .backend import ExecutionBackend, RunOutcome, BackendError
from .detectors import build_detectors, DetectorPipeline
from .detectors.base import RunContext
from .events import Finding, TaintSourceEvent

logger = logging.getLogger(__name__)

# binaries most worth emulating first (attack surface)
_INTERESTING = (
    "httpd",
    "uhttpd",
    "lighttpd",
    "goahead",
    "boa",
    "mini_httpd",
    "thttpd",
    "cgi",
    "nvram",
    "telnetd",
    "dropbear",
    "upnp",
    "miniupnpd",
    "dnsmasq",
    "hostapd",
    "wpa_supplicant",
    "ubusd",
    "dbus",
    "snmpd",
    "ftpd",
    "samba",
    "smbd",
    "rtsp",
    "onvif",
    "ser2net",
    "busybox",
)
_SEARCH_DIRS = (
    "bin",
    "sbin",
    "usr/bin",
    "usr/sbin",
    "www",
    "usr/www",
    "www/cgi-bin",
    "cgi-bin",
    "usr/lib",
    "lib",
)


def _is_elf(path: Path) -> bool:
    """True only for *runnable* ELFs (ET_EXEC / ET_DYN).

    Kernel modules and other relocatable objects (``.ko``, ``.o`` → ET_REL)
    cannot be emulated as programs and only produce load errors, so they are
    excluded here rather than attempted and warned about per file.
    """
    try:
        with open(path, "rb") as fh:
            head = fh.read(18)
        if len(head) < 18 or head[:4] != b"\x7fELF":
            return False
        little = head[5] != 2  # e_ident[EI_DATA]: 2 == big-endian
        e_type = int.from_bytes(head[16:18], "little" if little else "big")
        return e_type in (2, 3)  # ET_EXEC, ET_DYN
    except Exception:
        return False


def _score(path: Path) -> int:
    name = path.name.lower()
    for i, key in enumerate(_INTERESTING):
        if key in name:
            return 100 - i
    return 0


def select_binaries(
    rootfs: str, limit: int = 25, include: Optional[List[str]] = None
) -> List[Path]:
    """Return ELF binaries from ``rootfs``, highest attack-surface first."""
    root = Path(rootfs)
    found: dict = {}
    dirs = [root / d for d in _SEARCH_DIRS]
    dirs = [d for d in dirs if d.exists()] or [root]
    for d in dirs:
        for item in d.rglob("*"):
            if item.is_file() and not item.is_symlink() and _is_elf(item):
                found[item.resolve()] = item
    bins = list(found.values())
    if include:
        bins = [b for b in bins if any(g in b.name for g in include)]
    bins.sort(key=_score, reverse=True)
    return bins[:limit]


@dataclass
class RunResult:
    binary: str
    findings: List[Finding] = field(default_factory=list)
    outcome: Optional[RunOutcome] = None
    error: Optional[str] = None


class EmulationRunner:
    """Runs a backend under the detector pipeline for one or more binaries."""

    def __init__(
        self,
        detector_names: Optional[List[str]] = None,
        *,
        timeout_s: int = 30,
        max_instructions: int = 2_000_000,
        mem_events: bool = True,
    ) -> None:
        self.detector_names = detector_names
        self.timeout_s = timeout_s
        self.max_instructions = max_instructions
        self.mem_events = mem_events

    def run_binary(
        self,
        backend: ExecutionBackend,
        path: str,
        *,
        rootfs: Optional[str] = None,
        arch: Optional[str] = None,
        entry: Optional[int] = None,
        begin: Optional[int] = None,
        until: Optional[int] = None,
        seeds: Optional[List[TaintSourceEvent]] = None,
        label: str = "",
    ) -> RunResult:
        """Load ``path`` into ``backend`` and run it under the detectors."""
        try:
            backend.load(path, rootfs=rootfs, arch=arch, entry=entry, mem_events=self.mem_events)
        except BackendError as exc:
            return RunResult(binary=path, error=str(exc))
        except Exception as exc:  # pragma: no cover - backend-specific
            return RunResult(binary=path, error=f"load failed: {exc}")

        ctx = RunContext(
            backend=backend,
            binary_path=path,
            label=label or Path(path).name,
            arch=backend.arch,
            endian=backend.endian,
            pointer_size=backend.pointer_size,
            entrypoint=backend.entrypoint,
            symbols=backend.symbols,
        )
        pipeline = DetectorPipeline(build_detectors(self.detector_names))
        try:
            findings = pipeline.run_on(
                backend,
                ctx,
                prelude=seeds,
                max_instructions=self.max_instructions,
                timeout_s=self.timeout_s,
                begin=begin,
                until=until,
            )
        except Exception as exc:  # pragma: no cover - defensive
            return RunResult(binary=path, error=f"run failed: {exc}")
        finally:
            try:
                backend.close()
            except Exception:
                pass

        outcome = ctx.options.get("outcome")
        # A crash that no detector attributed is itself a finding -- unless the
        # binary never loaded its libraries, in which case the fault is a
        # dynamic-loader artifact, not a reachable bug.
        if (
            outcome
            and outcome.crashed
            and not getattr(outcome, "load_incomplete", False)
            and not any(f.category == "memory_safety" for f in findings)
        ):
            findings.append(
                Finding(
                    category="memory_safety",
                    title="Crash during emulation",
                    description=f"Execution faulted: {outcome.reason}",
                    severity="high",
                    vuln_type="memory_corruption",
                    pc=outcome.crash_pc,
                    confidence=0.6,
                    evidence=outcome.reason,
                    remediation="Reproduce under a debugger; the fault is reachable "
                    "with the emulated input.",
                    detector="EmulationRunner",
                )
            )
        return RunResult(binary=path, findings=findings, outcome=outcome)
