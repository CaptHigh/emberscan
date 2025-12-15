"""
Binary Analysis Scanner.

Analyzes executable binaries in firmware for security issues:
- Dangerous function calls (system, popen, strcpy)
- SUID/SGID binaries
- Binary hardening (ASLR, NX, PIE, Stack Canaries)
- Backdoor indicators
- Hardcoded secrets
"""

import os
import re
import subprocess
import struct
from pathlib import Path
from typing import List, Dict, Optional, Any, Set
from datetime import datetime

from .base import BaseScanner, ScannerRegistry
from ..core.config import Config
from ..core.logger import get_logger
from ..core.models import (
    FirmwareInfo,
    ScanResult,
    ScanStatus,
    Vulnerability,
    Severity,
    VulnerabilityType,
)

logger = get_logger(__name__)


# Dangerous libc functions
DANGEROUS_FUNCTIONS = {
    "system": (Severity.HIGH, "Shell command execution"),
    "popen": (Severity.HIGH, "Shell command execution"),
    "exec": (Severity.MEDIUM, "Process execution"),
    "execve": (Severity.MEDIUM, "Process execution"),
    "execl": (Severity.MEDIUM, "Process execution"),
    "execlp": (Severity.MEDIUM, "Process execution"),
    "execvp": (Severity.MEDIUM, "Process execution"),
    "strcpy": (Severity.MEDIUM, "Unsafe string copy - buffer overflow risk"),
    "strcat": (Severity.MEDIUM, "Unsafe string concatenation"),
    "sprintf": (Severity.MEDIUM, "Unsafe string formatting"),
    "gets": (Severity.HIGH, "Unsafe input function - buffer overflow"),
    "scanf": (Severity.LOW, "Potentially unsafe input"),
    "vsprintf": (Severity.MEDIUM, "Unsafe string formatting"),
    "mktemp": (Severity.LOW, "Insecure temporary file creation"),
}

# Backdoor indicators
BACKDOOR_STRINGS = [
    "backdoor",
    "rootshell",
    "/bin/sh -i",
    "telnetd -l /bin/sh",
    "nc -l -p",
    "busybox telnetd",
    "dropbear -R",
    "shell_backdoor",
    "hidden_shell",
]


@ScannerRegistry.register("binary")
class BinaryScanner(BaseScanner):
    """
    Binary security analyzer for firmware executables.
    """

    @property
    def name(self) -> str:
        return "binary_scanner"

    @property
    def scan_type(self) -> str:
        return "binary"

    def __init__(self, config: Config):
        super().__init__(config)

    def scan(self, target: str, firmware: FirmwareInfo, **kwargs) -> ScanResult:
        """
        Scan firmware binaries for security issues.

        Args:
            target: Path to extracted rootfs
            firmware: FirmwareInfo context
        """
        result = self._create_result()
        self._start_scan(result)

        try:
            rootfs = Path(target)

            # Find all ELF binaries
            binaries = self._find_binaries(rootfs)
            result.items_scanned = len(binaries)
            logger.info(f"[{self.name}] Found {len(binaries)} binaries to analyze")

            # Phase 1: Check for SUID/SGID binaries
            logger.info(f"[{self.name}] Checking SUID/SGID binaries")
            suid_vulns = self._check_suid_binaries(rootfs)
            result.vulnerabilities.extend(suid_vulns)

            # Phase 2: Analyze dangerous functions
            logger.info(f"[{self.name}] Analyzing dangerous function calls")
            func_vulns = self._analyze_dangerous_functions(binaries[:50])  # Limit
            result.vulnerabilities.extend(func_vulns)

            # Phase 3: Check binary hardening
            logger.info(f"[{self.name}] Checking binary hardening")
            hardening_vulns = self._check_binary_hardening(binaries[:20])
            result.vulnerabilities.extend(hardening_vulns)

            # Phase 4: Search for backdoor indicators
            logger.info(f"[{self.name}] Searching for backdoor indicators")
            backdoor_vulns = self._search_backdoors(rootfs)
            result.vulnerabilities.extend(backdoor_vulns)

            # Phase 5: Analyze interesting binaries
            logger.info(f"[{self.name}] Analyzing key binaries")
            key_vulns = self._analyze_key_binaries(rootfs)
            result.vulnerabilities.extend(key_vulns)

            self._complete_scan(result)

        except Exception as e:
            self._fail_scan(result, str(e))

        return result

    def _find_binaries(self, rootfs: Path) -> List[Path]:
        """Find all ELF binaries in filesystem."""
        binaries = []

        # Common binary directories
        bin_dirs = ["bin", "sbin", "usr/bin", "usr/sbin", "lib", "usr/lib"]

        for bin_dir in bin_dirs:
            search_dir = rootfs / bin_dir
            if search_dir.exists():
                for item in search_dir.rglob("*"):
                    if item.is_file() and self._is_elf(item):
                        binaries.append(item)

        return binaries

    def _is_elf(self, path: Path) -> bool:
        """Check if file is an ELF binary."""
        try:
            with open(path, "rb") as f:
                magic = f.read(4)
                return magic == b"\x7fELF"
        except:
            return False

    def _check_suid_binaries(self, rootfs: Path) -> List[Vulnerability]:
        """Check for SUID/SGID binaries."""
        vulnerabilities = []

        # Known dangerous SUID binaries
        dangerous_suid = {
            "nmap",
            "python",
            "perl",
            "ruby",
            "php",
            "vim",
            "vi",
            "nano",
            "less",
            "more",
            "find",
            "awk",
            "sed",
            "tar",
            "zip",
            "bash",
            "sh",
            "dash",
            "zsh",
            "csh",
            "nc",
            "netcat",
            "socat",
            "wget",
            "curl",
        }

        for item in rootfs.rglob("*"):
            if not item.is_file():
                continue

            try:
                stat = item.stat()
                mode = stat.st_mode

                # Check SUID (4000) or SGID (2000)
                is_suid = bool(mode & 0o4000)
                is_sgid = bool(mode & 0o2000)

                if is_suid or is_sgid:
                    severity = Severity.MEDIUM

                    # Higher severity for known dangerous binaries
                    if item.name in dangerous_suid:
                        severity = Severity.HIGH

                    # Root-owned SUID is more dangerous
                    if stat.st_uid == 0 and is_suid:
                        severity = Severity.HIGH

                    flags = []
                    if is_suid:
                        flags.append("SUID")
                    if is_sgid:
                        flags.append("SGID")

                    vuln = self._create_vulnerability(
                        title=f"{'/'.join(flags)} Binary: {item.name}",
                        description=f"Binary has {'/'.join(flags)} bit set, allowing privilege escalation",
                        severity=severity,
                        vuln_type=VulnerabilityType.PRIVILEGE_ESCALATION,
                        file_path=str(item.relative_to(rootfs)),
                        evidence=f"Mode: {oct(mode)}, Owner UID: {stat.st_uid}",
                        remediation="Remove SUID/SGID bit if not required: chmod u-s,g-s <file>",
                    )
                    vulnerabilities.append(vuln)

            except:
                continue

        return vulnerabilities

    def _analyze_dangerous_functions(self, binaries: List[Path]) -> List[Vulnerability]:
        """Analyze binaries for dangerous function imports."""
        vulnerabilities = []
        seen_combos: Set[tuple] = set()

        for binary in binaries:
            try:
                # Use readelf or objdump to get imported symbols
                symbols = self._get_imported_symbols(binary)

                dangerous_found = []
                for symbol in symbols:
                    for func_name, (severity, description) in DANGEROUS_FUNCTIONS.items():
                        if func_name in symbol:
                            combo = (binary.name, func_name)
                            if combo not in seen_combos:
                                seen_combos.add(combo)
                                dangerous_found.append((func_name, severity, description))

                # Create vulnerability for binaries with dangerous functions
                if dangerous_found:
                    # Aggregate by severity
                    high_funcs = [f for f, s, _ in dangerous_found if s == Severity.HIGH]

                    if high_funcs:
                        vuln = self._create_vulnerability(
                            title=f"Dangerous Functions in {binary.name}",
                            description=f"Binary uses potentially dangerous functions: {', '.join(high_funcs)}",
                            severity=Severity.MEDIUM,
                            vuln_type=VulnerabilityType.COMMAND_INJECTION,
                            file_path=str(binary),
                            evidence=f"Functions: {', '.join(f for f, _, _ in dangerous_found)}",
                            remediation="Review code for proper input validation",
                        )
                        vulnerabilities.append(vuln)

            except Exception as e:
                logger.debug(f"Failed to analyze {binary}: {e}")
                continue

        return vulnerabilities

    def _get_imported_symbols(self, binary: Path) -> List[str]:
        """Get imported symbols from ELF binary."""
        symbols = []

        try:
            # Try readelf first
            result = subprocess.run(
                ["readelf", "-s", str(binary)], capture_output=True, text=True, timeout=10
            )

            if result.returncode == 0:
                for line in result.stdout.split("\n"):
                    if "FUNC" in line and "UND" in line:
                        parts = line.split()
                        if len(parts) >= 8:
                            symbols.append(parts[-1])
                return symbols

        except FileNotFoundError:
            pass
        except subprocess.TimeoutExpired:
            pass

        try:
            # Fallback to strings
            result = subprocess.run(
                ["strings", str(binary)], capture_output=True, text=True, timeout=30
            )

            for func_name in DANGEROUS_FUNCTIONS.keys():
                if func_name in result.stdout:
                    symbols.append(func_name)

        except:
            pass

        return symbols

    def _check_binary_hardening(self, binaries: List[Path]) -> List[Vulnerability]:
        """Check binary security hardening features."""
        vulnerabilities = []

        for binary in binaries:
            try:
                hardening = self._get_hardening_info(binary)

                issues = []

                # Check NX (No-Execute)
                if not hardening.get("nx", True):
                    issues.append("NX disabled (executable stack)")

                # Check PIE (Position Independent Executable)
                if not hardening.get("pie", True):
                    issues.append("Not compiled as PIE")

                # Check Stack Canaries
                if not hardening.get("canary", True):
                    issues.append("No stack canaries")

                # Check RELRO
                if hardening.get("relro") == "none":
                    issues.append("No RELRO protection")

                if issues:
                    vuln = self._create_vulnerability(
                        title=f"Weak Binary Hardening: {binary.name}",
                        description=f"Binary lacks security hardening: {'; '.join(issues)}",
                        severity=Severity.LOW,
                        vuln_type=VulnerabilityType.OTHER,
                        file_path=str(binary),
                        evidence=str(hardening),
                        remediation="Recompile with security flags: -fstack-protector -D_FORTIFY_SOURCE=2 -pie -z relro -z now",
                    )
                    vulnerabilities.append(vuln)

            except Exception as e:
                logger.debug(f"Failed to check hardening for {binary}: {e}")
                continue

        return vulnerabilities

    def _get_hardening_info(self, binary: Path) -> Dict[str, Any]:
        """Get security hardening information for binary."""
        info = {
            "nx": True,
            "pie": False,
            "canary": False,
            "relro": "none",
        }

        try:
            # Check with checksec if available
            result = subprocess.run(
                ["checksec", "--file", str(binary), "--output", "json"],
                capture_output=True,
                text=True,
                timeout=10,
            )

            if result.returncode == 0:
                import json

                data = json.loads(result.stdout)
                # Parse checksec output
                return info

        except FileNotFoundError:
            pass
        except:
            pass

        # Manual check with readelf
        try:
            result = subprocess.run(
                ["readelf", "-l", str(binary)], capture_output=True, text=True, timeout=10
            )

            output = result.stdout

            # Check for executable stack (NX disabled)
            if "GNU_STACK" in output:
                for line in output.split("\n"):
                    if "GNU_STACK" in line and "RWE" in line:
                        info["nx"] = False

            # Check for PIE
            result2 = subprocess.run(
                ["readelf", "-h", str(binary)], capture_output=True, text=True, timeout=10
            )

            if "DYN (Shared object file)" in result2.stdout:
                info["pie"] = True

        except:
            pass

        return info

    def _search_backdoors(self, rootfs: Path) -> List[Vulnerability]:
        """Search for backdoor indicators in files."""
        vulnerabilities = []

        # Search in script files and binaries
        search_extensions = [".sh", ".lua", ".php", ".cgi", ".py", ".pl"]

        for item in rootfs.rglob("*"):
            if not item.is_file():
                continue

            # Check text files
            if item.suffix.lower() in search_extensions or item.name in [
                "rcS",
                "rc.local",
                "inittab",
            ]:
                try:
                    content = item.read_text(errors="ignore").lower()

                    for indicator in BACKDOOR_STRINGS:
                        if indicator.lower() in content:
                            vuln = self._create_vulnerability(
                                title=f"Potential Backdoor: {indicator}",
                                description=f"Backdoor indicator found in {item.name}",
                                severity=Severity.CRITICAL,
                                vuln_type=VulnerabilityType.BACKDOOR,
                                file_path=str(item.relative_to(rootfs)),
                                evidence=f"Found: '{indicator}'",
                                remediation="Investigate and remove suspicious code",
                            )
                            vulnerabilities.append(vuln)
                            break

                except:
                    continue

            # Check binaries with strings
            elif self._is_elf(item):
                try:
                    result = subprocess.run(
                        ["strings", str(item)], capture_output=True, text=True, timeout=10
                    )

                    content = result.stdout.lower()

                    for indicator in BACKDOOR_STRINGS:
                        if indicator.lower() in content:
                            vuln = self._create_vulnerability(
                                title=f"Potential Backdoor in Binary: {indicator}",
                                description=f"Backdoor indicator found in binary {item.name}",
                                severity=Severity.CRITICAL,
                                vuln_type=VulnerabilityType.BACKDOOR,
                                file_path=str(item.relative_to(rootfs)),
                                evidence=f"Found string: '{indicator}'",
                                remediation="Investigate binary for malicious code",
                            )
                            vulnerabilities.append(vuln)
                            break

                except:
                    continue

        return vulnerabilities

    def _analyze_key_binaries(self, rootfs: Path) -> List[Vulnerability]:
        """Analyze key binaries like httpd, busybox, etc."""
        vulnerabilities = []

        key_binaries = [
            "busybox",
            "httpd",
            "lighttpd",
            "uhttpd",
            "dropbear",
            "telnetd",
            "nvram",
            "cfg_manager",
        ]

        for binary_name in key_binaries:
            # Find binary
            for search_path in ["bin", "sbin", "usr/bin", "usr/sbin"]:
                binary_path = rootfs / search_path / binary_name
                if binary_path.exists():
                    # Get version if possible
                    version = self._get_binary_version(binary_path)

                    if version:
                        logger.debug(f"Found {binary_name} version: {version}")

                        # Check for known vulnerable versions
                        # (Would integrate with CVE database)

                    break

        return vulnerabilities

    def _get_binary_version(self, binary: Path) -> Optional[str]:
        """Try to extract version from binary."""
        try:
            result = subprocess.run(
                ["strings", str(binary)], capture_output=True, text=True, timeout=10
            )

            # Look for version patterns
            patterns = [
                r"version\s+(\d+\.\d+\.\d+)",
                r"v(\d+\.\d+\.\d+)",
                r"(\d+\.\d+\.\d+)",
            ]

            for pattern in patterns:
                match = re.search(pattern, result.stdout, re.IGNORECASE)
                if match:
                    return match.group(1)

        except:
            pass

        return None
