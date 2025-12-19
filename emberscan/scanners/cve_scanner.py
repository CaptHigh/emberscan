"""
CVE Vulnerability Scanner.

Correlates firmware components with known CVEs:
- Component version detection
- NVD database integration
- Known vulnerability matching
- Embedded device CVE database
"""

import json
import os
import re
import subprocess
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from ..core.config import Config
from ..core.logger import get_logger
from ..core.models import FirmwareInfo, ScanResult, Severity, Vulnerability, VulnerabilityType
from .base import BaseScanner, ScannerRegistry

logger = get_logger(__name__)


@dataclass
class SoftwareComponent:
    """Detected software component."""

    name: str
    version: str
    file_path: str
    confidence: float = 1.0


# Known embedded device vulnerabilities (subset for demonstration)
EMBEDDED_CVE_DATABASE = {
    "busybox": [
        {
            "cve": "CVE-2022-28391",
            "versions": ["<1.35"],
            "severity": Severity.HIGH,
            "description": "BusyBox shell command injection via crafted CRLF",
        },
        {
            "cve": "CVE-2021-42386",
            "versions": ["<1.34"],
            "severity": Severity.HIGH,
            "description": "BusyBox awk heap overflow",
        },
        {
            "cve": "CVE-2021-28831",
            "versions": ["<1.33"],
            "severity": Severity.MEDIUM,
            "description": "BusyBox decompress_gunzip invalid free",
        },
    ],
    "dropbear": [
        {
            "cve": "CVE-2021-36369",
            "versions": ["<2020.81"],
            "severity": Severity.MEDIUM,
            "description": "Dropbear SSH trivial authentication bypass",
        },
        {
            "cve": "CVE-2018-15599",
            "versions": ["<2018.76"],
            "severity": Severity.MEDIUM,
            "description": "Dropbear username enumeration",
        },
    ],
    "openssl": [
        {
            "cve": "CVE-2022-0778",
            "versions": ["<1.1.1n", "<3.0.2"],
            "severity": Severity.HIGH,
            "description": "OpenSSL infinite loop in BN_mod_sqrt()",
        },
        {
            "cve": "CVE-2021-3711",
            "versions": ["<1.1.1l"],
            "severity": Severity.CRITICAL,
            "description": "OpenSSL SM2 decryption buffer overflow",
        },
    ],
    "dnsmasq": [
        {
            "cve": "CVE-2021-3448",
            "versions": ["<2.85"],
            "severity": Severity.MEDIUM,
            "description": "Dnsmasq DNS cache poisoning",
        },
        {
            "cve": "CVE-2020-25681",
            "versions": ["<2.83"],
            "severity": Severity.HIGH,
            "description": "Dnsmasq heap buffer overflow (DNSpooq)",
        },
    ],
    "lighttpd": [
        {
            "cve": "CVE-2022-22707",
            "versions": ["<1.4.64"],
            "severity": Severity.MEDIUM,
            "description": "Lighttpd mod_extforward infinite loop DoS",
        },
    ],
    "uhttpd": [
        {
            "cve": "CVE-2019-19945",
            "versions": ["<2019"],
            "severity": Severity.HIGH,
            "description": "uhttpd command injection via CGI",
        },
    ],
    "libcurl": [
        {
            "cve": "CVE-2022-27774",
            "versions": ["<7.83.0"],
            "severity": Severity.MEDIUM,
            "description": "curl credential leak via same host redirect",
        },
    ],
    "miniupnpd": [
        {
            "cve": "CVE-2019-12108",
            "versions": ["<2.1.20190625"],
            "severity": Severity.HIGH,
            "description": "MiniUPnPd stack buffer overflow",
        },
    ],
}


@ScannerRegistry.register("cve")
class CVEScanner(BaseScanner):
    """
    CVE correlation scanner for firmware components.
    """

    @property
    def name(self) -> str:
        return "cve_scanner"

    @property
    def scan_type(self) -> str:
        return "cve"

    def __init__(self, config: Config):
        super().__init__(config)
        self.cve_database_path = config.cve_database
        self.nvd_api_key = config.nvd_api_key
        self._loaded_database: Dict = {}

    def scan(self, target: str, firmware: FirmwareInfo, **kwargs) -> ScanResult:
        """
        Scan firmware for known CVEs.

        Args:
            target: Path to extracted rootfs
            firmware: FirmwareInfo context
        """
        result = self._create_result()
        self._start_scan(result)

        try:
            rootfs = Path(target)

            # Load CVE database
            self._load_cve_database()

            # Phase 1: Detect software components
            logger.info(f"[{self.name}] Detecting software components")
            components = self._detect_components(rootfs)
            result.items_scanned = len(components)

            logger.info(f"[{self.name}] Found {len(components)} components")

            # Phase 2: Match against CVE database
            logger.info(f"[{self.name}] Matching against CVE database")
            cve_vulns = self._match_cves(components)
            result.vulnerabilities.extend(cve_vulns)

            # Phase 3: Check firmware-specific CVEs
            logger.info(f"[{self.name}] Checking firmware-specific CVEs")
            fw_vulns = self._check_firmware_cves(firmware)
            result.vulnerabilities.extend(fw_vulns)

            self._complete_scan(result)

        except Exception as e:
            self._fail_scan(result, str(e))

        return result

    def find_cves(self, vulnerability: Vulnerability, firmware: FirmwareInfo) -> List[str]:
        """
        Find related CVEs for a discovered vulnerability.

        Used for CVE correlation with other scanner findings.
        """
        cves = []

        # Map vulnerability types to potential CVEs
        # This would integrate with NVD API in production

        return cves

    def _load_cve_database(self):
        """Load CVE database from file or use embedded."""
        # Try to load from file
        if self.cve_database_path and Path(self.cve_database_path).exists():
            try:
                with open(self.cve_database_path) as f:
                    self._loaded_database = json.load(f)
                logger.info(f"Loaded CVE database from {self.cve_database_path}")
                return
            except Exception as e:
                logger.warning(f"Failed to load CVE database: {e}")

        # Use embedded database
        self._loaded_database = EMBEDDED_CVE_DATABASE
        logger.info("Using embedded CVE database")

    def _detect_components(self, rootfs: Path) -> List[SoftwareComponent]:
        """Detect software components and versions."""
        components = []

        # Common binaries to check
        binary_checks = {
            "busybox": ["bin/busybox", "sbin/busybox"],
            "dropbear": ["usr/sbin/dropbear", "sbin/dropbear"],
            "openssl": ["usr/bin/openssl", "usr/lib/libssl.so*"],
            "lighttpd": ["usr/sbin/lighttpd"],
            "uhttpd": ["usr/sbin/uhttpd"],
            "dnsmasq": ["usr/sbin/dnsmasq"],
            "miniupnpd": ["usr/sbin/miniupnpd"],
            "hostapd": ["usr/sbin/hostapd"],
            "wpa_supplicant": ["usr/sbin/wpa_supplicant"],
        }

        for component_name, paths in binary_checks.items():
            for path_pattern in paths:
                for match in rootfs.glob(path_pattern):
                    if match.exists():
                        version = self._get_component_version(match, component_name)
                        if version:
                            components.append(
                                SoftwareComponent(
                                    name=component_name,
                                    version=version,
                                    file_path=str(match.relative_to(rootfs)),
                                )
                            )
                        break

        # Check package info files
        pkg_files = [
            "usr/lib/opkg/status",
            "var/lib/dpkg/status",
            "etc/opkg/distfeeds.conf",
        ]

        for pkg_file in pkg_files:
            pkg_path = rootfs / pkg_file
            if pkg_path.exists():
                pkg_components = self._parse_package_info(pkg_path, rootfs)
                components.extend(pkg_components)

        # Deduplicate
        seen = set()
        unique_components = []
        for comp in components:
            key = f"{comp.name}:{comp.version}"
            if key not in seen:
                seen.add(key)
                unique_components.append(comp)

        return unique_components

    def _get_component_version(self, binary_path: Path, component_name: str) -> Optional[str]:
        """Extract version from binary."""
        try:
            # Try running with --version
            if component_name == "busybox":
                result = subprocess.run(
                    ["strings", str(binary_path)], capture_output=True, text=True, timeout=10
                )

                # Look for BusyBox version string
                match = re.search(r"BusyBox v(\d+\.\d+\.\d+)", result.stdout)
                if match:
                    return match.group(1)

            elif component_name == "dropbear":
                result = subprocess.run(
                    ["strings", str(binary_path)], capture_output=True, text=True, timeout=10
                )

                match = re.search(r"dropbear[_-]?(\d{4}\.\d+)", result.stdout, re.I)
                if match:
                    return match.group(1)

            elif component_name == "openssl":
                result = subprocess.run(
                    ["strings", str(binary_path)], capture_output=True, text=True, timeout=10
                )

                match = re.search(r"OpenSSL (\d+\.\d+\.\d+[a-z]?)", result.stdout)
                if match:
                    return match.group(1)

            else:
                # Generic version extraction
                result = subprocess.run(
                    ["strings", str(binary_path)], capture_output=True, text=True, timeout=10
                )

                patterns = [
                    rf"{component_name}[/_-]?v?(\d+\.\d+\.\d+)",
                    rf"version[:\s]+(\d+\.\d+\.\d+)",
                    rf"v(\d+\.\d+\.\d+)",
                ]

                for pattern in patterns:
                    match = re.search(pattern, result.stdout, re.I)
                    if match:
                        return match.group(1)

        except Exception as e:
            logger.debug(f"Failed to get version for {binary_path}: {e}")

        return None

    def _parse_package_info(self, pkg_file: Path, rootfs: Path) -> List[SoftwareComponent]:
        """Parse package manager status file."""
        components = []

        try:
            content = pkg_file.read_text()

            # Parse opkg/dpkg format
            current_pkg = {}

            for line in content.split("\n"):
                if line.startswith("Package:"):
                    if current_pkg.get("name") and current_pkg.get("version"):
                        components.append(
                            SoftwareComponent(
                                name=current_pkg["name"],
                                version=current_pkg["version"],
                                file_path=str(pkg_file.relative_to(rootfs)),
                                confidence=0.9,
                            )
                        )
                    current_pkg = {"name": line.split(":", 1)[1].strip()}
                elif line.startswith("Version:"):
                    current_pkg["version"] = line.split(":", 1)[1].strip()

            # Don't forget last package
            if current_pkg.get("name") and current_pkg.get("version"):
                components.append(
                    SoftwareComponent(
                        name=current_pkg["name"],
                        version=current_pkg["version"],
                        file_path=str(pkg_file.relative_to(rootfs)),
                        confidence=0.9,
                    )
                )

        except Exception as e:
            logger.debug(f"Failed to parse package info: {e}")

        return components

    def _match_cves(self, components: List[SoftwareComponent]) -> List[Vulnerability]:
        """Match components against CVE database."""
        vulnerabilities = []

        for component in components:
            # Check embedded database
            if component.name.lower() in self._loaded_database:
                cve_list = self._loaded_database[component.name.lower()]

                for cve_info in cve_list:
                    if self._version_affected(component.version, cve_info["versions"]):
                        vuln = self._create_vulnerability(
                            title=f"{cve_info['cve']}: {component.name}",
                            description=cve_info["description"],
                            severity=cve_info["severity"],
                            vuln_type=VulnerabilityType.CVE,
                            file_path=component.file_path,
                            cve_ids=[cve_info["cve"]],
                            evidence=f"Detected version: {component.version}",
                            remediation=f"Update {component.name} to latest version",
                            references=[f"https://nvd.nist.gov/vuln/detail/{cve_info['cve']}"],
                        )
                        vulnerabilities.append(vuln)

                        logger.info(
                            f"CVE match: {cve_info['cve']} for {component.name} {component.version}"
                        )

        return vulnerabilities

    def _version_affected(self, detected_version: str, affected_versions: List[str]) -> bool:
        """Check if detected version is affected."""
        from packaging import version as pkg_version

        try:
            detected = pkg_version.parse(detected_version)

            for affected in affected_versions:
                if affected.startswith("<"):
                    threshold = pkg_version.parse(affected[1:])
                    if detected < threshold:
                        return True
                elif affected.startswith("<="):
                    threshold = pkg_version.parse(affected[2:])
                    if detected <= threshold:
                        return True
                elif affected.startswith("="):
                    threshold = pkg_version.parse(affected[1:])
                    if detected == threshold:
                        return True
                elif "-" in affected:
                    # Range: 1.0-2.0
                    parts = affected.split("-")
                    low = pkg_version.parse(parts[0])
                    high = pkg_version.parse(parts[1])
                    if low <= detected <= high:
                        return True

        except Exception:
            # If version parsing fails, do string comparison
            for affected in affected_versions:
                clean_affected = affected.lstrip("<>=")
                if detected_version == clean_affected:
                    return True

        return False

    def _check_firmware_cves(self, firmware: FirmwareInfo) -> List[Vulnerability]:
        """Check for firmware-specific CVEs based on vendor/model."""
        vulnerabilities = []

        # Known vendor-specific CVEs
        vendor_cves = {
            "tp-link": [
                {
                    "cve": "CVE-2022-40486",
                    "models": ["archer ax10", "archer ax21", "archer ax50"],
                    "severity": Severity.CRITICAL,
                    "description": "TP-Link command injection via config restore",
                },
                {
                    "cve": "CVE-2022-30075",
                    "models": ["archer ax10"],
                    "severity": Severity.HIGH,
                    "description": "TP-Link Archer authentication bypass",
                },
            ],
            "d-link": [
                {
                    "cve": "CVE-2022-28891",
                    "models": ["dir-"],
                    "severity": Severity.CRITICAL,
                    "description": "D-Link DIR remote code execution",
                },
            ],
            "netgear": [
                {
                    "cve": "CVE-2021-45521",
                    "models": ["r6700", "r7000", "r8000"],
                    "severity": Severity.CRITICAL,
                    "description": "Netgear authentication bypass",
                },
            ],
        }

        vendor = firmware.vendor.lower() if firmware.vendor else ""
        name = firmware.name.lower() if firmware.name else ""

        for vendor_key, cve_list in vendor_cves.items():
            if vendor_key in vendor or vendor_key in name:
                for cve_info in cve_list:
                    # Check if model matches
                    for model in cve_info["models"]:
                        if model.lower() in name.lower():
                            vuln = self._create_vulnerability(
                                title=f"{cve_info['cve']}: {firmware.vendor or 'Unknown'} Firmware",
                                description=cve_info["description"],
                                severity=cve_info["severity"],
                                vuln_type=VulnerabilityType.CVE,
                                cve_ids=[cve_info["cve"]],
                                evidence=f"Firmware: {firmware.name}, Vendor: {firmware.vendor}",
                                remediation="Update firmware to latest version from manufacturer",
                                references=[f"https://nvd.nist.gov/vuln/detail/{cve_info['cve']}"],
                            )
                            vulnerabilities.append(vuln)
                            break

        return vulnerabilities

    def update_database(self, output_path: str = None):
        """Update CVE database from NVD."""
        if not self.nvd_api_key:
            logger.warning("NVD API key not configured - cannot update database")
            return

        # Would implement NVD API integration here
        # https://services.nvd.nist.gov/rest/json/cves/2.0

        logger.info("CVE database update not yet implemented")
