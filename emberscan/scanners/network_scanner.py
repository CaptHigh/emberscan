"""
Network Vulnerability Scanner.

Scans network services for vulnerabilities including:
- Open ports and services
- Weak service configurations
- Known vulnerable service versions
- Telnet/SSH issues
- SNMP community strings
"""

import socket
import subprocess
from datetime import datetime
from typing import Any, Dict, List, Optional

import defusedxml.ElementTree as ET

from ..core.config import Config
from ..core.logger import get_logger
from ..core.models import (
    FirmwareInfo,
    ScanResult,
    ScanStatus,
    Severity,
    Vulnerability,
    VulnerabilityType,
)
from .base import BaseScanner, ScannerRegistry

logger = get_logger(__name__)


# Default/weak SNMP community strings
SNMP_COMMUNITIES = [
    "public",
    "private",
    "admin",
    "manager",
    "default",
    "cisco",
    "secret",
    "monitor",
    "security",
    "snmp",
]

# Weak SSH configurations
WEAK_SSH_CIPHERS = [
    "arcfour",
    "arcfour128",
    "arcfour256",
    "3des-cbc",
    "blowfish-cbc",
    "cast128-cbc",
]

WEAK_SSH_MACS = [
    "hmac-md5",
    "hmac-md5-96",
    "hmac-sha1-96",
]


@ScannerRegistry.register("network")
class NetworkScanner(BaseScanner):
    """
    Network service vulnerability scanner.
    """

    @property
    def name(self) -> str:
        return "network_scanner"

    @property
    def scan_type(self) -> str:
        return "network"

    def __init__(self, config: Config):
        super().__init__(config)
        self.timeout = 10

    def scan(
        self, target: str, firmware: FirmwareInfo, ports: List[int] = None, **kwargs
    ) -> ScanResult:
        """
        Scan network services for vulnerabilities.

        Args:
            target: Target IP address
            firmware: FirmwareInfo context
            ports: Specific ports to scan (default: common ports)
        """
        result = self._create_result()
        self._start_scan(result)

        try:
            # Phase 1: Port scanning
            logger.info(f"[{self.name}] Scanning ports on {target}")
            open_ports = self._scan_ports(target, ports)
            result.items_scanned = len(open_ports)

            # Phase 2: Service detection
            logger.info(f"[{self.name}] Detecting services")
            services = self._detect_services(target, open_ports)

            # Phase 3: Run nmap if available
            nmap_results = self._run_nmap(target, ports)
            if nmap_results:
                services.update(nmap_results.get("services", {}))

            # Phase 4: Check for specific vulnerabilities

            # Check Telnet
            if 23 in open_ports:
                logger.info(f"[{self.name}] Checking Telnet service")
                telnet_vulns = self._check_telnet(target)
                result.vulnerabilities.extend(telnet_vulns)

            # Check SSH
            if 22 in open_ports:
                logger.info(f"[{self.name}] Checking SSH configuration")
                ssh_vulns = self._check_ssh(target)
                result.vulnerabilities.extend(ssh_vulns)

            # Check SNMP
            if 161 in open_ports:
                logger.info(f"[{self.name}] Checking SNMP")
                snmp_vulns = self._check_snmp(target)
                result.vulnerabilities.extend(snmp_vulns)

            # Check for dangerous open services
            dangerous_vulns = self._check_dangerous_services(target, open_ports, services)
            result.vulnerabilities.extend(dangerous_vulns)

            # Phase 5: Version-based vulnerability checks
            version_vulns = self._check_service_versions(services)
            result.vulnerabilities.extend(version_vulns)

            self._complete_scan(result)

        except Exception as e:
            self._fail_scan(result, str(e))

        return result

    def _scan_ports(self, target: str, ports: List[int] = None) -> List[int]:
        """Scan for open ports."""
        open_ports = []

        if not ports:
            # Common embedded device ports
            ports = [
                21,
                22,
                23,
                25,
                53,
                69,
                80,
                81,
                443,
                161,
                162,
                443,
                554,
                1080,
                1883,
                5000,
                5060,
                8000,
                8080,
                8081,
                8443,
                8888,
                9000,
                9090,
                49152,
            ]

        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((target, port))
                sock.close()

                if result == 0:
                    open_ports.append(port)

            except:
                continue

        logger.info(f"Found {len(open_ports)} open ports: {open_ports}")
        return open_ports

    def _detect_services(self, target: str, ports: List[int]) -> Dict[int, Dict]:
        """Detect services on open ports."""
        services = {}

        service_map = {
            21: ("ftp", "FTP"),
            22: ("ssh", "SSH"),
            23: ("telnet", "Telnet"),
            25: ("smtp", "SMTP"),
            53: ("dns", "DNS"),
            69: ("tftp", "TFTP"),
            80: ("http", "HTTP"),
            81: ("http", "HTTP-Alt"),
            161: ("snmp", "SNMP"),
            443: ("https", "HTTPS"),
            554: ("rtsp", "RTSP"),
            1883: ("mqtt", "MQTT"),
            8080: ("http-proxy", "HTTP Proxy"),
            8443: ("https-alt", "HTTPS-Alt"),
        }

        for port in ports:
            service_info = service_map.get(port, ("unknown", "Unknown"))

            # Try to grab banner
            banner = self._grab_banner(target, port)

            services[port] = {
                "name": service_info[0],
                "description": service_info[1],
                "banner": banner,
                "version": self._parse_version(banner),
            }

        return services

    def _grab_banner(self, target: str, port: int) -> str:
        """Grab service banner."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((target, port))

            # Some services need a prompt
            if port in [80, 8080, 8081]:
                sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
            elif port == 21:
                pass  # FTP sends banner on connect
            elif port == 22:
                pass  # SSH sends banner on connect
            else:
                sock.send(b"\r\n")

            banner = sock.recv(1024).decode("utf-8", errors="ignore")
            sock.close()
            return banner.strip()

        except:
            return ""

    def _parse_version(self, banner: str) -> str:
        """Extract version from banner."""
        import re

        version_patterns = [
            r"(\d+\.\d+\.\d+)",
            r"version\s+(\d+\.\d+)",
            r"v(\d+\.\d+)",
        ]

        for pattern in version_patterns:
            match = re.search(pattern, banner, re.IGNORECASE)
            if match:
                return match.group(1)

        return ""

    def _run_nmap(self, target: str, ports: List[int] = None) -> Optional[Dict]:
        """Run nmap scan if available."""
        import shutil

        if not shutil.which("nmap"):
            return None

        try:
            cmd = ["nmap", "-sV", "-oX", "-", target]

            if ports:
                cmd.extend(["-p", ",".join(str(p) for p in ports)])

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

            # Parse XML output
            root = ET.fromstring(result.stdout)

            services = {}
            for port_elem in root.findall(".//port"):
                port_id = int(port_elem.get("portid"))
                state = port_elem.find("state")
                service = port_elem.find("service")

                if state is not None and state.get("state") == "open":
                    services[port_id] = {
                        "name": (
                            service.get("name", "unknown") if service is not None else "unknown"
                        ),
                        "product": service.get("product", "") if service is not None else "",
                        "version": service.get("version", "") if service is not None else "",
                    }

            return {"services": services}

        except subprocess.TimeoutExpired:
            logger.warning("Nmap scan timed out")
            return None
        except Exception as e:
            logger.warning(f"Nmap scan failed: {e}")
            return None

    def _check_telnet(self, target: str) -> List[Vulnerability]:
        """Check for Telnet vulnerabilities."""
        vulnerabilities = []

        # Telnet is inherently insecure
        vuln = self._create_vulnerability(
            title="Telnet Service Enabled",
            description="Telnet transmits data in cleartext, including credentials. This is a significant security risk.",
            severity=Severity.HIGH,
            vuln_type=VulnerabilityType.INSECURE_PROTOCOL,
            endpoint=f"{target}:23",
            remediation="Disable Telnet and use SSH for remote administration",
        )
        vulnerabilities.append(vuln)

        # Try anonymous/default login
        banner = self._grab_banner(target, 23)
        if banner:
            # Check for open Telnet (no auth)
            if "login:" not in banner.lower() and "#" in banner:
                vuln = self._create_vulnerability(
                    title="Telnet Without Authentication",
                    description="Telnet service allows access without authentication",
                    severity=Severity.CRITICAL,
                    vuln_type=VulnerabilityType.AUTHENTICATION_BYPASS,
                    endpoint=f"{target}:23",
                    evidence=banner[:200],
                    remediation="Enable authentication or disable Telnet",
                )
                vulnerabilities.append(vuln)

        return vulnerabilities

    def _check_ssh(self, target: str) -> List[Vulnerability]:
        """Check SSH configuration for weaknesses."""
        vulnerabilities = []

        try:
            # Try to get SSH key exchange info
            result = subprocess.run(
                [
                    "ssh",
                    "-vv",
                    "-o",
                    "BatchMode=yes",
                    "-o",
                    "ConnectTimeout=5",
                    f"{target}",
                    "exit",
                ],
                capture_output=True,
                text=True,
                timeout=10,
            )

            output = result.stderr

            # Check for weak ciphers
            for cipher in WEAK_SSH_CIPHERS:
                if cipher in output:
                    vuln = self._create_vulnerability(
                        title=f"Weak SSH Cipher: {cipher}",
                        description=f"SSH server supports weak cipher: {cipher}",
                        severity=Severity.MEDIUM,
                        vuln_type=VulnerabilityType.WEAK_CRYPTO,
                        endpoint=f"{target}:22",
                        remediation="Disable weak ciphers in SSH configuration",
                    )
                    vulnerabilities.append(vuln)

            # Check for weak MACs
            for mac in WEAK_SSH_MACS:
                if mac in output:
                    vuln = self._create_vulnerability(
                        title=f"Weak SSH MAC: {mac}",
                        description=f"SSH server supports weak MAC: {mac}",
                        severity=Severity.LOW,
                        vuln_type=VulnerabilityType.WEAK_CRYPTO,
                        endpoint=f"{target}:22",
                        remediation="Disable weak MACs in SSH configuration",
                    )
                    vulnerabilities.append(vuln)

            # Check for SSH v1
            if "SSH-1" in output:
                vuln = self._create_vulnerability(
                    title="SSH Protocol Version 1 Enabled",
                    description="SSH v1 is deprecated and has known vulnerabilities",
                    severity=Severity.HIGH,
                    vuln_type=VulnerabilityType.INSECURE_PROTOCOL,
                    endpoint=f"{target}:22",
                    remediation="Disable SSH v1, use SSH v2 only",
                )
                vulnerabilities.append(vuln)

        except subprocess.TimeoutExpired:
            pass
        except Exception as e:
            logger.debug(f"SSH check failed: {e}")

        return vulnerabilities

    def _check_snmp(self, target: str) -> List[Vulnerability]:
        """Check SNMP for default community strings."""
        vulnerabilities = []

        for community in SNMP_COMMUNITIES:
            if self._try_snmp_community(target, community):
                vuln = self._create_vulnerability(
                    title=f"SNMP Default Community: {community}",
                    description=f"SNMP service accepts default community string '{community}'",
                    severity=Severity.HIGH,
                    vuln_type=VulnerabilityType.DEFAULT_CONFIG,
                    endpoint=f"{target}:161",
                    evidence=f"Community string '{community}' accepted",
                    remediation="Change SNMP community strings and consider using SNMPv3",
                )
                vulnerabilities.append(vuln)

        return vulnerabilities

    def _try_snmp_community(self, target: str, community: str) -> bool:
        """Try SNMP community string."""
        try:
            # Use snmpget if available
            import shutil

            if shutil.which("snmpget"):
                result = subprocess.run(
                    ["snmpget", "-v2c", "-c", community, target, "SNMPv2-MIB::sysDescr.0"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                return result.returncode == 0
        except:
            pass

        return False

    def _check_dangerous_services(
        self, target: str, ports: List[int], services: Dict
    ) -> List[Vulnerability]:
        """Check for dangerous open services."""
        vulnerabilities = []

        dangerous_ports = {
            21: ("FTP", "File transfer without encryption"),
            69: ("TFTP", "Trivial file transfer - no authentication"),
            512: ("rexec", "Remote execution service"),
            513: ("rlogin", "Remote login service"),
            514: ("rsh", "Remote shell service"),
            1433: ("MSSQL", "Database port exposed"),
            3306: ("MySQL", "Database port exposed"),
            5432: ("PostgreSQL", "Database port exposed"),
            6379: ("Redis", "Database port exposed"),
            27017: ("MongoDB", "Database port exposed"),
        }

        for port in ports:
            if port in dangerous_ports:
                service_name, description = dangerous_ports[port]
                vuln = self._create_vulnerability(
                    title=f"Dangerous Service Exposed: {service_name}",
                    description=f"{service_name} on port {port}: {description}",
                    severity=Severity.MEDIUM,
                    vuln_type=VulnerabilityType.INSECURE_PROTOCOL,
                    endpoint=f"{target}:{port}",
                    remediation=f"Disable {service_name} or restrict access with firewall",
                )
                vulnerabilities.append(vuln)

        return vulnerabilities

    def _check_service_versions(self, services: Dict[int, Dict]) -> List[Vulnerability]:
        """Check service versions against known vulnerabilities."""
        vulnerabilities = []

        # Known vulnerable versions (simplified - would use CVE database in production)
        known_vulnerable = {
            "dropbear": [
                ("0.", Severity.HIGH, "Outdated Dropbear SSH"),
            ],
            "lighttpd": [
                ("1.4.", Severity.MEDIUM, "Potentially vulnerable Lighttpd"),
            ],
            "busybox": [
                ("1.", Severity.LOW, "Old BusyBox version"),
            ],
        }

        for port, service in services.items():
            product = service.get("product", "").lower()
            version = service.get("version", "")

            for software, vuln_list in known_vulnerable.items():
                if software in product:
                    for ver_prefix, severity, description in vuln_list:
                        if version.startswith(ver_prefix):
                            vuln = self._create_vulnerability(
                                title=f"Outdated {software.title()} Version",
                                description=f"{description}: version {version}",
                                severity=severity,
                                vuln_type=VulnerabilityType.CVE,
                                endpoint=f"port {port}",
                                evidence=f"Detected: {product} {version}",
                                remediation="Update to latest version",
                            )
                            vulnerabilities.append(vuln)

        return vulnerabilities
