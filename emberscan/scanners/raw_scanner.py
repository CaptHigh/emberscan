"""
Raw firmware / blob scanner.

Static analysis fallback for images that cannot be unpacked into a root
filesystem -- bare-metal MCU firmware (ESP32/Xtensa, ARM Cortex-M), encrypted
or proprietary blobs, bootloaders, or single executables. Instead of aborting
the whole scan, EmberScan still extracts human-readable strings from the raw
bytes and flags secrets, keys, risky URLs and weak-crypto indicators.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import List

from ..core.logger import get_logger
from ..core.models import FirmwareInfo, ScanResult, Severity, Vulnerability, VulnerabilityType
from .base import BaseScanner

logger = get_logger(__name__)

# Minimum printable-run length when extracting strings from the blob.
_MIN_STR = 6
_PRINTABLE = re.compile(rb"[\x20-\x7e]{%d,}" % _MIN_STR)

# (regex, title, severity, vuln_type, cwe)
_PATTERNS = [
    (
        re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"),
        "Embedded private key",
        Severity.CRITICAL,
        VulnerabilityType.HARDCODED_CREDENTIALS,
        "CWE-321",
    ),
    (
        re.compile(r"AKIA[0-9A-Z]{16}"),
        "AWS access key id",
        Severity.CRITICAL,
        VulnerabilityType.HARDCODED_CREDENTIALS,
        "CWE-798",
    ),
    (
        re.compile(r"(?:ghp|gho|ghs|github_pat)_[0-9A-Za-z_]{20,}"),
        "GitHub token",
        Severity.HIGH,
        VulnerabilityType.HARDCODED_CREDENTIALS,
        "CWE-798",
    ),
    (
        re.compile(r"(?i)(?:api[_-]?key|secret|token|passwd|password)\s*[:=]\s*['\"]?[^\s'\"]{4,}"),
        "Hardcoded credential / secret",
        Severity.HIGH,
        VulnerabilityType.HARDCODED_CREDENTIALS,
        "CWE-798",
    ),
    (
        re.compile(r"\b[A-Za-z0-9]{2,20}:\$[1256]\$[^\s:]+"),
        "Unix password hash",
        Severity.HIGH,
        VulnerabilityType.HARDCODED_CREDENTIALS,
        "CWE-259",
    ),
    (
        re.compile(r"(?i)\b(telnetd|telnet)\b"),
        "Telnet service string (insecure protocol)",
        Severity.MEDIUM,
        VulnerabilityType.INSECURE_PROTOCOL,
        "CWE-319",
    ),
    (
        re.compile(r"http://[^\s'\"]+"),
        "Cleartext HTTP URL",
        Severity.LOW,
        VulnerabilityType.INSECURE_PROTOCOL,
        "CWE-319",
    ),
]

# Weak crypto / RNG primitive names worth noting (reported once each).
_WEAK_CRYPTO = {
    "md5": "MD5 (broken hash)",
    "sha1": "SHA-1 (weak hash)",
    "des_": "DES (weak cipher)",
    "rc4": "RC4 (weak cipher)",
    "srand": "srand()/rand() (insecure PRNG)",
}


class RawFirmwareScanner(BaseScanner):
    """String-based static scan over a single raw firmware image or binary."""

    @property
    def name(self) -> str:
        return "raw_firmware_scanner"

    @property
    def scan_type(self) -> str:
        return "static-raw"

    def scan(self, target: str, firmware: FirmwareInfo, **kwargs) -> ScanResult:
        result = self._create_result()
        self._start_scan(result)

        path = Path(target)
        try:
            data = path.read_bytes()
        except OSError as e:
            self._fail_scan(result, f"could not read {target}: {e}")
            return result

        result.items_scanned = 1
        strings_blob = b"\n".join(_PRINTABLE.findall(data)).decode("latin-1", "replace")

        # 1. Informational: what did we identify?
        arch = getattr(firmware.architecture, "value", "unknown")
        result.vulnerabilities.append(
            self._create_vulnerability(
                title=f"Raw image analyzed ({arch})",
                description=(
                    "Firmware could not be unpacked to a filesystem; EmberScan fell "
                    "back to raw string analysis of the image bytes. Findings below "
                    "come from printable strings, not an emulated run."
                ),
                severity=Severity.INFO,
                vuln_type=VulnerabilityType.OTHER,
                file_path=path.name,
                evidence=f"{len(data):,} bytes, architecture={arch}",
            )
        )

        seen = set()

        # 2. Pattern-based secret / protocol findings (de-duped by match text).
        for rx, title, sev, vt, cwe in _PATTERNS:
            for m in rx.finditer(strings_blob):
                snippet = m.group(0)[:60]
                key = (title, snippet)
                if key in seen:
                    continue
                seen.add(key)
                v = self._create_vulnerability(
                    title=title,
                    description=f"Pattern '{title}' found in raw image strings.",
                    severity=sev,
                    vuln_type=vt,
                    file_path=path.name,
                    evidence=snippet,
                )
                v.cwe_ids = [cwe]
                result.vulnerabilities.append(v)
                if len(seen) > 200:  # safety cap on noisy blobs
                    break

        # 3. Weak-crypto primitive references (one finding each).
        low = strings_blob.lower()
        for needle, label in _WEAK_CRYPTO.items():
            if needle in low:
                v = self._create_vulnerability(
                    title=f"Weak cryptographic primitive: {label}",
                    description=f"Reference to {label} found in image strings.",
                    severity=Severity.LOW,
                    vuln_type=VulnerabilityType.WEAK_CRYPTO,
                    file_path=path.name,
                    evidence=needle,
                )
                v.cwe_ids = ["CWE-327"]
                result.vulnerabilities.append(v)

        self._complete_scan(result)
        return result
