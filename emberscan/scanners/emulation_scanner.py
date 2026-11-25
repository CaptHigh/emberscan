"""
Emulation Scanner.

Dynamic, emulation-driven vulnerability analysis: load each binary from the
extracted firmware, emulate its code, and run the detector pipeline
(memory-safety, taint, information-leak, weak-code) over the execution. This is
the runtime counterpart to the static ``binary``/``crypto``/``credential``
scanners — it reports issues that only show up when code actually runs.

The heavy lifting lives in :mod:`emberscan.dynamic`; this class only selects
targets, drives the runner, and maps :class:`~emberscan.dynamic.events.Finding`
objects onto EmberScan ``Vulnerability`` objects. It degrades gracefully: if no
emulation backend (Qiling/Unicorn) is installed, it records one INFO finding
explaining how to enable it rather than failing the scan.
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import List, Optional

from .base import BaseScanner, ScannerRegistry
from ..core.config import Config
from ..core.logger import get_logger
from ..core.models import (
    FirmwareInfo,
    ScanResult,
    Vulnerability,
    Severity,
    VulnerabilityType,
    Architecture,
)

logger = get_logger(__name__)

# Finding.vuln_type -> VulnerabilityType (by attribute name, OTHER fallback)
_VT = {
    "command_injection": "COMMAND_INJECTION",
    "buffer_overflow": "BUFFER_OVERFLOW",
    "info_disclosure": "INFORMATION_DISCLOSURE",
    "weak_crypto": "WEAK_CRYPTO",
    "auth_bypass": "AUTHENTICATION_BYPASS",
    "format_string": "FORMAT_STRING",
    "weak_rng": "WEAK_RNG",
    "memory_corruption": "MEMORY_CORRUPTION",
    "use_after_free": "USE_AFTER_FREE",
}

_ARCH_TAG = {
    Architecture.MIPS_BE: "mips",
    Architecture.MIPS_LE: "mipsel",
    Architecture.ARM: "arm",
    Architecture.ARM64: "arm64",
    Architecture.X86: "x86",
    Architecture.X86_64: "x86_64",
}


@ScannerRegistry.register("emulation")
class EmulationScanner(BaseScanner):
    """Runtime vulnerability analysis via per-binary emulation."""

    @property
    def name(self) -> str:
        return "emulation_scanner"

    @property
    def scan_type(self) -> str:
        return "emulation"

    def scan(self, target: str, firmware: FirmwareInfo, **kwargs) -> ScanResult:
        result = self._create_result()
        self._start_scan(result)

        emu_cfg = getattr(self.config, "emulation", None)
        try:
            from ..dynamic import get_backend, select_binaries, EmulationRunner
            from ..dynamic.backend import BackendUnavailable
        except Exception as exc:  # pragma: no cover - import guard
            self._fail_scan(result, f"dynamic subsystem unavailable: {exc}")
            return result

        backend_name = getattr(emu_cfg, "backend", "auto")
        # availability probe on a throwaway instance
        probe = get_backend(backend_name)
        if not probe.available:
            result.vulnerabilities.append(
                self._create_vulnerability(
                    title="Emulation backend not installed",
                    description="EmulationScanner needs Qiling and/or Unicorn to run "
                    "binaries. Install with: pip install 'emberscan[emulation]' "
                    "(or: pip install qiling unicorn capstone).",
                    severity=Severity.INFO,
                    vuln_type=VulnerabilityType.OTHER,
                    confidence=1.0,
                    remediation="pip install 'emberscan[emulation]'",
                )
            )
            self._complete_scan(result)
            return result

        # resolve targets
        tpath = Path(target)
        rootfs_override = getattr(emu_cfg, "rootfs", None)
        if tpath.is_dir():
            # the firmware rootfs is both the binary-selection search root and
            # (unless overridden) its own sysroot; --rootfs only overrides the
            # latter, so it never redirects select_binaries() onto some other
            # filesystem (e.g. "/" would otherwise walk the whole host disk).
            rootfs = rootfs_override or str(tpath)
            limit = getattr(emu_cfg, "max_binaries", 25)
            include = getattr(emu_cfg, "include", None)
            binaries = select_binaries(str(tpath), limit=limit, include=include)
        else:
            rootfs = rootfs_override or str(tpath.parent)
            binaries = [tpath]

        if not binaries:
            logger.info(f"[{self.name}] no ELF binaries found under {target}")
            self._complete_scan(result)
            return result

        result.items_scanned = len(binaries)
        runner = EmulationRunner(
            detector_names=getattr(emu_cfg, "detectors", None),
            timeout_s=getattr(emu_cfg, "timeout_per_binary", 30),
            max_instructions=getattr(emu_cfg, "max_instructions", 2_000_000),
            mem_events=getattr(emu_cfg, "mem_events", True),
        )
        arch_tag = _ARCH_TAG.get(firmware.architecture)
        budget = getattr(emu_cfg, "total_timeout", 0) or self.config.scanner.timeout_per_scan
        deadline = time.time() + budget

        _FAULT_KINDS = {"oob_write", "oob_read", "null_deref"}
        collected = []  # (finding, binary) pairs surviving the per-binary filter

        for binary in binaries:
            if time.time() > deadline:
                logger.warning(
                    f"[{self.name}] time budget exhausted; "
                    f"stopping with {len(binaries)} selected"
                )
                break
            backend = get_backend(backend_name)  # fresh instance per binary
            logger.info(f"[{self.name}] emulating {binary}")
            run = runner.run_binary(
                backend,
                str(binary),
                rootfs=rootfs,
                arch=arch_tag,
            )
            if run.error:
                logger.warning(f"[{self.name}] {binary}: {run.error}")
                continue
            # When the guest loader could not resolve the binary's shared
            # libraries, the program never ran its own code, so any faulting
            # access it hit is a loader artifact rather than a real bug. Drop
            # those crash-derived findings to avoid false-positive overflows.
            load_incomplete = bool(run.outcome and getattr(run.outcome, "load_incomplete", False))
            dropped = 0
            for f in run.findings:
                if load_incomplete and (f.metadata or {}).get("kind") in _FAULT_KINDS:
                    dropped += 1
                    continue
                collected.append((f, binary))
            if dropped:
                logger.info(
                    f"[{self.name}] {binary}: dropped {dropped} fault-derived "
                    "finding(s) from a binary whose libraries did not resolve"
                )

        # Systemic-artifact suppression: a faulting access at the *same* program
        # counter across several unrelated binaries is an emulation artifact (a
        # common libc/loader stub that always faults under emulation), never a
        # real per-binary overflow. Drop any fault PC shared by >= 3 binaries.
        from collections import defaultdict

        pc_bins = defaultdict(set)
        for f, b in collected:
            if (f.metadata or {}).get("kind") in _FAULT_KINDS and f.pc:
                pc_bins[f.pc].add(str(b))
        systemic = {pc for pc, bins in pc_bins.items() if len(bins) >= 3}

        suppressed = 0
        for f, b in collected:
            if (f.metadata or {}).get("kind") in _FAULT_KINDS and f.pc in systemic:
                suppressed += 1
                continue
            result.vulnerabilities.append(self._to_vuln(f, b, rootfs))
        if suppressed:
            logger.info(
                f"[{self.name}] suppressed {suppressed} systemic emulation "
                f"fault(s) recurring at {len(systemic)} shared address(es)"
            )

        self._complete_scan(result)
        return result

    # -- mapping --------------------------------------------------------------
    def _to_vuln(self, finding, binary: Path, rootfs: str) -> Vulnerability:
        try:
            severity = Severity(finding.severity)
        except ValueError:
            severity = Severity.INFO
        vt_name = _VT.get(finding.vuln_type, "OTHER")
        vuln_type = getattr(VulnerabilityType, vt_name, VulnerabilityType.OTHER)

        try:
            rel = str(binary.relative_to(rootfs))
        except Exception:
            rel = str(binary)

        func = finding.function
        if finding.pc:
            func = f"{func or '?'} @ 0x{finding.pc:x}"

        return self._create_vulnerability(
            title=finding.title,
            description=finding.description,
            severity=severity,
            vuln_type=vuln_type,
            file_path=rel,
            function_name=func,
            evidence=finding.evidence,
            remediation=finding.remediation,
            confidence=finding.confidence,
            cwe_ids=[finding.cwe] if finding.cwe else [],
        )
