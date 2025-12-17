# Python API Reference

EmberScan can be used as a Python library for custom integrations.

## Quick Start

```python
from emberscan import EmberScanner, Config

# Load configuration
config = Config.load('emberscan.yaml')  # or use defaults

# Initialize scanner
scanner = EmberScanner(config)

# Run scan
session = scanner.scan_firmware(
    firmware_path='firmware.bin',
    session_name='My Security Audit',
    scanners=['credentials', 'binary', 'crypto'],
    skip_emulation=True
)

# Access results
print(f"Found {len(session.all_vulnerabilities)} vulnerabilities")
for vuln in session.all_vulnerabilities:
    print(f"[{vuln.severity.value}] {vuln.title}")
```

## Core Classes

### EmberScanner

Main orchestrator for firmware security scanning.

```python
from emberscan import EmberScanner, Config

class EmberScanner:
    def __init__(self, config: Config = None):
        """
        Initialize EmberScanner with configuration.

        Args:
            config: Configuration object (uses defaults if None)
        """

    def scan_firmware(
        self,
        firmware_path: str,
        session_name: str = None,
        scanners: List[str] = None,
        skip_emulation: bool = False,
        generate_report: bool = True,
    ) -> ScanSession:
        """
        Execute complete firmware security scan.

        Args:
            firmware_path: Path to firmware binary
            session_name: Optional name for scan session
            scanners: List of scanner names to run (default: all)
            skip_emulation: Skip QEMU emulation
            generate_report: Generate reports after scanning

        Returns:
            ScanSession with all results
        """

    def check_dependencies(self) -> Dict[str, bool]:
        """Check if required tools are installed."""
```

### Config

Configuration management.

```python
from emberscan.core.config import Config

class Config:
    # General settings
    workspace_dir: str = "./workspace"
    log_level: str = "INFO"

    # Sub-configurations
    qemu: QEMUConfig
    scanner: ScannerConfig
    extractor: ExtractorConfig
    reporter: ReporterConfig

    @classmethod
    def load(cls, config_path: str = None) -> "Config":
        """Load configuration from YAML file."""
```

### ScanSession

Represents a scan session with results.

```python
from emberscan.core.models import ScanSession

class ScanSession:
    id: str                          # Unique session ID
    name: str                        # Session name
    status: ScanStatus               # PENDING, RUNNING, COMPLETED, FAILED
    firmware: FirmwareInfo           # Firmware metadata
    scan_results: List[ScanResult]   # Results from each scanner
    started_at: datetime
    completed_at: datetime

    @property
    def all_vulnerabilities(self) -> List[Vulnerability]:
        """Get all vulnerabilities from all scan results."""

    def get_summary(self) -> Dict:
        """Get summary of scan results."""
```

### Vulnerability

Represents a detected vulnerability.

```python
from emberscan.core.models import Vulnerability, Severity

class Vulnerability:
    id: str                       # Unique ID
    title: str                    # Short title
    description: str              # Detailed description
    severity: Severity            # CRITICAL, HIGH, MEDIUM, LOW, INFO
    vuln_type: VulnerabilityType  # Type of vulnerability
    file_path: str                # Affected file
    line_number: int              # Line number (if applicable)
    evidence: str                 # Supporting evidence
    remediation: str              # How to fix
    cve_ids: List[str]            # Associated CVEs
    scanner_name: str             # Which scanner found it

class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
```

### FirmwareInfo

Metadata about analyzed firmware.

```python
from emberscan.core.models import FirmwareInfo, Architecture

class FirmwareInfo:
    id: str
    name: str
    file_path: str
    file_size: int
    md5: str
    sha256: str
    architecture: Architecture
    endianness: Endianness
    filesystem_type: FilesystemType
    extraction_path: str
    rootfs_path: str
    vendor: str
    version: str
    device_type: str

class Architecture(Enum):
    MIPS_LE = "mipsel"
    MIPS_BE = "mips"
    ARM = "arm"
    ARM64 = "aarch64"
    X86 = "x86"
    X86_64 = "x86_64"
    UNKNOWN = "unknown"
```

## Firmware Extraction

```python
from emberscan.extractors.firmware_extractor import FirmwareExtractor

extractor = FirmwareExtractor(config)

# Analyze without extraction
analysis = extractor.analyze('firmware.bin')
print(f"Architecture: {analysis['architecture']}")
print(f"Filesystem: {analysis['filesystem_type']}")
print(f"Components: {len(analysis['components'])}")

# Extract filesystem
rootfs_path = extractor.extract('firmware.bin', './extracted')
print(f"Extracted to: {rootfs_path}")

# Extract metadata
metadata = extractor.extract_metadata('firmware.bin')
print(f"Vendor: {metadata['vendor']}")
print(f"Version: {metadata['version']}")
```

## QEMU Emulation

```python
from emberscan.emulators.qemu_manager import QEMUManager

manager = QEMUManager(config)

# Download kernels
results = manager.download_kernels(['mipsel', 'arm'])
for arch, success in results.items():
    print(f"{arch}: {'OK' if success else 'FAILED'}")

# Start emulation
state = manager.start(
    firmware_info,
    http_port=8080,
    ssh_port=2222
)

# Wait for boot
if manager.wait_for_boot(state, timeout=300):
    print(f"Web interface: http://localhost:{state.http_port}")

# Stop emulation
manager.stop(state)
```

## Custom Scanners

Create custom scanners by extending `BaseScanner`:

```python
from emberscan.scanners.base import BaseScanner, ScannerRegistry
from emberscan.core.models import ScanResult, Vulnerability, Severity

@ScannerRegistry.register("custom")
class CustomScanner(BaseScanner):

    @property
    def name(self) -> str:
        return "custom_scanner"

    @property
    def scan_type(self) -> str:
        return "custom"

    def scan(self, target: str, firmware: FirmwareInfo, **kwargs) -> ScanResult:
        result = self._create_result()
        self._start_scan(result)

        try:
            # Your scanning logic here
            vulns = self._scan_for_issues(target)
            result.vulnerabilities.extend(vulns)

            self._complete_scan(result)
        except Exception as e:
            self._fail_scan(result, str(e))

        return result

    def _scan_for_issues(self, target: str) -> List[Vulnerability]:
        vulnerabilities = []

        # Example: Check for specific file
        target_path = Path(target)
        if (target_path / "etc/dangerous_config").exists():
            vuln = self._create_vulnerability(
                title="Dangerous Configuration Found",
                description="A dangerous configuration file exists",
                severity=Severity.HIGH,
                file_path="etc/dangerous_config",
                remediation="Remove or secure the configuration file"
            )
            vulnerabilities.append(vuln)

        return vulnerabilities
```

## Report Generation

```python
from emberscan.reporters.html_reporter import HTMLReporter
from emberscan.reporters.json_reporter import JSONReporter

# Generate HTML report
html_reporter = HTMLReporter(config)
html_path = html_reporter.generate(session, './reports')

# Generate JSON report
json_reporter = JSONReporter(config)
json_path = json_reporter.generate(session, './reports')

# Access report data programmatically
import json
with open(json_path) as f:
    report_data = json.load(f)

for vuln in report_data['vulnerabilities']:
    if vuln['severity'] == 'critical':
        print(f"CRITICAL: {vuln['title']}")
```

## Exception Handling

```python
from emberscan.core.exceptions import (
    EmberScanError,
    ExtractionError,
    FilesystemExtractionError,
    EncryptedFirmwareError,
    EmulationError,
    KernelNotFoundError,
    ScannerError,
)

try:
    session = scanner.scan_firmware('firmware.bin')
except FilesystemExtractionError as e:
    print(f"Extraction failed: {e}")
    # Try static analysis only
    session = scanner.scan_firmware('firmware.bin', skip_emulation=True)
except EncryptedFirmwareError as e:
    print(f"Firmware appears encrypted: {e}")
except EmulationError as e:
    print(f"Emulation failed: {e}")
except EmberScanError as e:
    print(f"Scan error: {e}")
```

## Complete Example

```python
#!/usr/bin/env python3
"""Complete EmberScan API usage example."""

from pathlib import Path
from emberscan import EmberScanner, Config
from emberscan.core.models import Severity

def main():
    # Configuration
    config = Config.load()
    config.reporter.output_dir = "./my_reports"

    # Initialize scanner
    scanner = EmberScanner(config)

    # Check dependencies
    deps = scanner.check_dependencies()
    missing = [k for k, v in deps.items() if not v]
    if missing:
        print(f"Warning: Missing tools: {missing}")

    # Run scan
    print("Starting firmware scan...")
    session = scanner.scan_firmware(
        firmware_path="router_firmware.bin",
        session_name="Router Security Audit",
        scanners=["credentials", "binary", "crypto"],
        skip_emulation=True,
        generate_report=True
    )

    # Summary
    summary = session.get_summary()
    print(f"\nScan Complete: {session.name}")
    print(f"Duration: {summary['duration']:.1f}s")
    print(f"Total findings: {summary['total_vulnerabilities']}")

    # Critical findings
    critical = [v for v in session.all_vulnerabilities
                if v.severity == Severity.CRITICAL]

    if critical:
        print(f"\n⚠️  {len(critical)} CRITICAL findings:")
        for vuln in critical:
            print(f"  - {vuln.title}")
            print(f"    File: {vuln.file_path}")
            print(f"    Fix: {vuln.remediation}")

    # Report location
    report_dir = Path(config.reporter.output_dir) / session.id
    print(f"\nReports: {report_dir.absolute()}")

if __name__ == "__main__":
    main()
```

## Integration Examples

### CI/CD Integration

```python
import sys
from emberscan import EmberScanner, Config

def ci_scan(firmware_path: str) -> int:
    """Run scan and return exit code for CI."""
    scanner = EmberScanner()
    session = scanner.scan_firmware(
        firmware_path,
        skip_emulation=True
    )

    summary = session.get_summary()

    if summary['by_severity']['critical'] > 0:
        return 2  # Critical findings
    elif summary['by_severity']['high'] > 0:
        return 1  # High findings
    return 0  # No high/critical

if __name__ == "__main__":
    sys.exit(ci_scan(sys.argv[1]))
```

### Batch Processing

```python
from pathlib import Path
from emberscan import EmberScanner

scanner = EmberScanner()

firmware_dir = Path("./firmware_samples")
for firmware_file in firmware_dir.glob("*.bin"):
    print(f"Scanning: {firmware_file.name}")

    try:
        session = scanner.scan_firmware(
            str(firmware_file),
            session_name=firmware_file.stem,
            skip_emulation=True
        )

        summary = session.get_summary()
        print(f"  Vulnerabilities: {summary['total_vulnerabilities']}")
        print(f"  Critical: {summary['by_severity']['critical']}")

    except Exception as e:
        print(f"  Error: {e}")
```
