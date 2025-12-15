"""
Data models for EmberScan.

Defines dataclasses and enums for representing firmware,
vulnerabilities, scan results, and other core entities.
"""

import uuid
import hashlib
from enum import Enum, auto
from datetime import datetime
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from pathlib import Path


class Architecture(Enum):
    """Supported CPU architectures."""

    MIPS_BE = "mips"
    MIPS_LE = "mipsel"
    ARM = "arm"
    ARM64 = "aarch64"
    X86 = "i386"
    X86_64 = "x86_64"
    PPC = "ppc"
    PPC64 = "ppc64"
    UNKNOWN = "unknown"

    @classmethod
    def from_string(cls, arch_str: str) -> "Architecture":
        """Parse architecture from string."""
        mappings = {
            "mips": cls.MIPS_BE,
            "mipseb": cls.MIPS_BE,
            "mipsel": cls.MIPS_LE,
            "mipsle": cls.MIPS_LE,
            "arm": cls.ARM,
            "armel": cls.ARM,
            "armhf": cls.ARM,
            "aarch64": cls.ARM64,
            "arm64": cls.ARM64,
            "i386": cls.X86,
            "i686": cls.X86,
            "x86": cls.X86,
            "x86_64": cls.X86_64,
            "amd64": cls.X86_64,
            "ppc": cls.PPC,
            "powerpc": cls.PPC,
            "ppc64": cls.PPC64,
        }
        return mappings.get(arch_str.lower(), cls.UNKNOWN)


class Endianness(Enum):
    """Byte order."""

    LITTLE = "little"
    BIG = "big"
    UNKNOWN = "unknown"


class FilesystemType(Enum):
    """Supported filesystem types."""

    SQUASHFS = "squashfs"
    CRAMFS = "cramfs"
    JFFS2 = "jffs2"
    UBIFS = "ubifs"
    ROMFS = "romfs"
    EXT2 = "ext2"
    EXT4 = "ext4"
    YAFFS2 = "yaffs2"
    UNKNOWN = "unknown"


class Severity(Enum):
    """Vulnerability severity levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def score_range(self) -> tuple:
        """CVSS score range for this severity."""
        ranges = {
            self.CRITICAL: (9.0, 10.0),
            self.HIGH: (7.0, 8.9),
            self.MEDIUM: (4.0, 6.9),
            self.LOW: (0.1, 3.9),
            self.INFO: (0.0, 0.0),
        }
        return ranges[self]

    def __lt__(self, other):
        order = [self.INFO, self.LOW, self.MEDIUM, self.HIGH, self.CRITICAL]
        return order.index(self) < order.index(other)


class ScanStatus(Enum):
    """Scan status states."""

    PENDING = auto()
    RUNNING = auto()
    COMPLETED = auto()
    FAILED = auto()
    CANCELLED = auto()
    TIMEOUT = auto()


class VulnerabilityType(Enum):
    """Types of vulnerabilities."""

    COMMAND_INJECTION = "command_injection"
    BUFFER_OVERFLOW = "buffer_overflow"
    AUTHENTICATION_BYPASS = "auth_bypass"
    INFORMATION_DISCLOSURE = "info_disclosure"
    HARDCODED_CREDENTIALS = "hardcoded_creds"
    WEAK_CRYPTO = "weak_crypto"
    BACKDOOR = "backdoor"
    INSECURE_PROTOCOL = "insecure_protocol"
    PRIVILEGE_ESCALATION = "priv_esc"
    XSS = "xss"
    SQLI = "sqli"
    PATH_TRAVERSAL = "path_traversal"
    FILE_INCLUSION = "file_inclusion"
    CSRF = "csrf"
    SSRF = "ssrf"
    DEFAULT_CONFIG = "default_config"
    CVE = "cve"
    OTHER = "other"


@dataclass
class FirmwareInfo:
    """Information about a firmware image."""

    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    name: str = ""
    version: str = ""
    vendor: str = ""
    device_type: str = ""  # router, switch, camera, etc.

    # File information
    file_path: str = ""
    file_size: int = 0
    md5: str = ""
    sha256: str = ""

    # Architecture info
    architecture: Architecture = Architecture.UNKNOWN
    endianness: Endianness = Endianness.UNKNOWN

    # Filesystem info
    filesystem_type: FilesystemType = FilesystemType.UNKNOWN
    rootfs_path: Optional[str] = None

    # Extraction info
    extracted: bool = False
    extraction_path: Optional[str] = None

    # Components detected
    components: List[Dict[str, Any]] = field(default_factory=list)

    # Metadata
    analysis_date: datetime = field(default_factory=datetime.now)

    def calculate_hashes(self):
        """Calculate file hashes."""
        if not self.file_path or not Path(self.file_path).exists():
            return

        with open(self.file_path, "rb") as f:
            data = f.read()
            self.file_size = len(data)
            self.md5 = hashlib.md5(data, usedforsecurity=False).hexdigest()
            self.sha256 = hashlib.sha256(data).hexdigest()

    def to_dict(self) -> Dict:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "name": self.name,
            "version": self.version,
            "vendor": self.vendor,
            "device_type": self.device_type,
            "file_path": self.file_path,
            "file_size": self.file_size,
            "md5": self.md5,
            "sha256": self.sha256,
            "architecture": self.architecture.value,
            "endianness": self.endianness.value,
            "filesystem_type": self.filesystem_type.value,
            "rootfs_path": self.rootfs_path,
            "extracted": self.extracted,
            "extraction_path": self.extraction_path,
            "components": self.components,
            "analysis_date": self.analysis_date.isoformat(),
        }


@dataclass
class Vulnerability:
    """Represents a discovered vulnerability."""

    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])

    # Classification
    vuln_type: VulnerabilityType = VulnerabilityType.OTHER
    severity: Severity = Severity.INFO
    cvss_score: float = 0.0
    cve_ids: List[str] = field(default_factory=list)
    cwe_ids: List[str] = field(default_factory=list)

    # Description
    title: str = ""
    description: str = ""

    # Location
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    function_name: Optional[str] = None
    endpoint: Optional[str] = None
    parameter: Optional[str] = None

    # Evidence
    evidence: str = ""
    request: Optional[str] = None
    response: Optional[str] = None

    # Remediation
    remediation: str = ""
    references: List[str] = field(default_factory=list)

    # Scanner info
    scanner_name: str = ""
    confidence: float = 1.0  # 0.0 to 1.0
    false_positive: bool = False

    # Timestamps
    discovered_at: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> Dict:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "vuln_type": self.vuln_type.value,
            "severity": self.severity.value,
            "cvss_score": self.cvss_score,
            "cve_ids": self.cve_ids,
            "cwe_ids": self.cwe_ids,
            "title": self.title,
            "description": self.description,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "function_name": self.function_name,
            "endpoint": self.endpoint,
            "parameter": self.parameter,
            "evidence": self.evidence,
            "request": self.request,
            "response": self.response,
            "remediation": self.remediation,
            "references": self.references,
            "scanner_name": self.scanner_name,
            "confidence": self.confidence,
            "false_positive": self.false_positive,
            "discovered_at": self.discovered_at.isoformat(),
        }


@dataclass
class ScanResult:
    """Results from a single scanner run."""

    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    scanner_name: str = ""
    scan_type: str = ""  # web, network, binary, etc.

    # Status
    status: ScanStatus = ScanStatus.PENDING
    error_message: Optional[str] = None

    # Timing
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None

    # Results
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    raw_output: Optional[str] = None

    # Statistics
    items_scanned: int = 0

    @property
    def duration(self) -> Optional[float]:
        """Scan duration in seconds."""
        if self.started_at and self.completed_at:
            return (self.completed_at - self.started_at).total_seconds()
        return None

    @property
    def vulnerability_count(self) -> Dict[str, int]:
        """Count vulnerabilities by severity."""
        counts = {s.value: 0 for s in Severity}
        for vuln in self.vulnerabilities:
            counts[vuln.severity.value] += 1
        return counts

    def to_dict(self) -> Dict:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "scanner_name": self.scanner_name,
            "scan_type": self.scan_type,
            "status": self.status.name,
            "error_message": self.error_message,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "duration": self.duration,
            "vulnerabilities": [v.to_dict() for v in self.vulnerabilities],
            "items_scanned": self.items_scanned,
            "vulnerability_count": self.vulnerability_count,
        }


@dataclass
class ScanSession:
    """Complete scan session containing all results."""

    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""

    # Target
    firmware: Optional[FirmwareInfo] = None
    target_ip: Optional[str] = None
    target_port: Optional[int] = None

    # Configuration
    config: Dict[str, Any] = field(default_factory=dict)

    # Status
    status: ScanStatus = ScanStatus.PENDING

    # Timing
    created_at: datetime = field(default_factory=datetime.now)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None

    # Results
    scan_results: List[ScanResult] = field(default_factory=list)

    @property
    def all_vulnerabilities(self) -> List[Vulnerability]:
        """Get all vulnerabilities from all scan results."""
        vulns = []
        for result in self.scan_results:
            vulns.extend(result.vulnerabilities)
        return vulns

    @property
    def critical_count(self) -> int:
        """Count critical vulnerabilities."""
        return sum(1 for v in self.all_vulnerabilities if v.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        """Count high severity vulnerabilities."""
        return sum(1 for v in self.all_vulnerabilities if v.severity == Severity.HIGH)

    def get_summary(self) -> Dict[str, Any]:
        """Generate scan summary."""
        all_vulns = self.all_vulnerabilities
        return {
            "session_id": self.id,
            "name": self.name,
            "status": self.status.name,
            "firmware": self.firmware.to_dict() if self.firmware else None,
            "target": f"{self.target_ip}:{self.target_port}" if self.target_ip else None,
            "duration": (
                (self.completed_at - self.started_at).total_seconds()
                if self.completed_at and self.started_at
                else None
            ),
            "scanners_run": len(self.scan_results),
            "total_vulnerabilities": len(all_vulns),
            "by_severity": {
                "critical": sum(1 for v in all_vulns if v.severity == Severity.CRITICAL),
                "high": sum(1 for v in all_vulns if v.severity == Severity.HIGH),
                "medium": sum(1 for v in all_vulns if v.severity == Severity.MEDIUM),
                "low": sum(1 for v in all_vulns if v.severity == Severity.LOW),
                "info": sum(1 for v in all_vulns if v.severity == Severity.INFO),
            },
        }

    def to_dict(self) -> Dict:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "name": self.name,
            "firmware": self.firmware.to_dict() if self.firmware else None,
            "target_ip": self.target_ip,
            "target_port": self.target_port,
            "config": self.config,
            "status": self.status.name,
            "created_at": self.created_at.isoformat(),
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "scan_results": [r.to_dict() for r in self.scan_results],
            "summary": self.get_summary(),
        }


@dataclass
class EmulationState:
    """State of an emulated firmware instance."""

    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    firmware_id: str = ""

    # QEMU process info
    pid: Optional[int] = None
    qemu_command: str = ""

    # Network info
    ip_address: str = "127.0.0.1"
    http_port: int = 8080
    ssh_port: int = 2222
    telnet_port: int = 2323
    debug_port: int = 1234

    # Status
    running: bool = False
    boot_successful: bool = False
    services_detected: List[str] = field(default_factory=list)

    # Timing
    started_at: Optional[datetime] = None
    boot_time: Optional[float] = None  # seconds

    def get_web_url(self) -> str:
        """Get web interface URL."""
        return f"http://{self.ip_address}:{self.http_port}"

    def get_ssh_command(self) -> str:
        """Get SSH connection command."""
        return f"ssh -p {self.ssh_port} root@{self.ip_address}"
