"""
EmberScanner - Main orchestrator for firmware security scanning.

Coordinates firmware extraction, emulation, vulnerability scanning,
and report generation.
"""

import os
import time
import asyncio
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Type
from concurrent.futures import ThreadPoolExecutor, as_completed

from .config import Config
from .logger import get_logger, setup_logging, ProgressLogger
from .models import (
    FirmwareInfo,
    ScanSession,
    ScanResult,
    ScanStatus,
    Vulnerability,
    EmulationState,
    Architecture,
)
from .exceptions import (
    EmberScanError,
    ExtractionError,
    EmulationError,
    ScannerError,
    ConfigurationError,
)

logger = get_logger(__name__)


class EmberScanner:
    """
    Main orchestrator for EmberScan firmware security testing.

    Workflow:
    1. Load and validate firmware
    2. Extract firmware contents
    3. Analyze architecture and filesystem
    4. Setup QEMU emulation
    5. Run vulnerability scanners
    6. Correlate with CVE database
    7. Generate reports
    """

    def __init__(self, config: Config = None):
        """Initialize EmberScanner with configuration."""
        self.config = config or Config.load()

        # Setup logging
        setup_logging(level=self.config.log_level, log_file=self.config.log_file)

        # Validate configuration
        errors = self.config.validate()
        if errors:
            for error in errors:
                logger.warning(f"Config warning: {error}")

        # Initialize components
        self._init_workspace()
        self._init_components()

        # Active sessions
        self.active_sessions: Dict[str, ScanSession] = {}
        self.active_emulations: Dict[str, EmulationState] = {}

        logger.info(f"EmberScanner initialized - Workspace: {self.config.workspace_dir}")

    def _init_workspace(self):
        """Initialize workspace directories."""
        workspace = Path(self.config.workspace_dir)

        self.dirs = {
            "workspace": workspace,
            "firmware": workspace / "firmware",
            "extracted": workspace / "extracted",
            "emulation": workspace / "emulation",
            "reports": workspace / "reports",
            "logs": workspace / "logs",
            "temp": workspace / "temp",
        }

        for dir_path in self.dirs.values():
            dir_path.mkdir(parents=True, exist_ok=True)

    def _init_components(self):
        """Initialize scanner components (lazy loading)."""
        self._extractor = None
        self._emulator = None
        self._scanners = {}
        self._reporters = {}

    @property
    def extractor(self):
        """Lazy load firmware extractor."""
        if self._extractor is None:
            from ..extractors.firmware_extractor import FirmwareExtractor

            self._extractor = FirmwareExtractor(self.config)
        return self._extractor

    @property
    def emulator(self):
        """Lazy load QEMU emulator."""
        if self._emulator is None:
            from ..emulators.qemu_manager import QEMUManager

            self._emulator = QEMUManager(self.config)
        return self._emulator

    def get_scanner(self, scanner_name: str):
        """Get or create scanner instance."""
        if scanner_name not in self._scanners:
            scanner_class = self._load_scanner_class(scanner_name)
            self._scanners[scanner_name] = scanner_class(self.config)
        return self._scanners[scanner_name]

    def _load_scanner_class(self, scanner_name: str):
        """Dynamically load scanner class."""
        scanner_map = {
            "web": ("..scanners.web_scanner", "WebScanner"),
            "network": ("..scanners.network_scanner", "NetworkScanner"),
            "binary": ("..scanners.binary_scanner", "BinaryScanner"),
            "cve": ("..scanners.cve_scanner", "CVEScanner"),
            "credentials": ("..scanners.credential_scanner", "CredentialScanner"),
            "crypto": ("..scanners.crypto_scanner", "CryptoScanner"),
        }

        if scanner_name not in scanner_map:
            raise ScannerError(f"Unknown scanner: {scanner_name}")

        module_path, class_name = scanner_map[scanner_name]

        try:
            import importlib

            module = importlib.import_module(module_path, package="emberscan.core")
            return getattr(module, class_name)
        except (ImportError, AttributeError) as e:
            raise ScannerError(f"Failed to load scanner '{scanner_name}': {e}")

    # ========================================================================
    # Main Scanning Workflow
    # ========================================================================

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
            firmware_path: Path to firmware binary or SPI dump
            session_name: Optional name for this scan session
            scanners: List of scanners to run (default: all enabled)
            skip_emulation: Skip QEMU emulation (static analysis only)
            generate_report: Generate reports after scanning

        Returns:
            ScanSession with all results
        """
        # Create session
        session = ScanSession(
            name=session_name or f"Scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            status=ScanStatus.PENDING,
        )
        self.active_sessions[session.id] = session

        logger.info(f"Starting scan session: {session.name} (ID: {session.id})")

        try:
            session.status = ScanStatus.RUNNING
            session.started_at = datetime.now()

            # Phase 1: Analyze and extract firmware
            with ProgressLogger(logger, "Firmware Analysis"):
                firmware_info = self._analyze_firmware(firmware_path)
                session.firmware = firmware_info

            # Phase 2: Extract filesystem
            with ProgressLogger(logger, "Firmware Extraction"):
                extraction_path = self._extract_firmware(firmware_info)
                firmware_info.extraction_path = str(extraction_path)
                firmware_info.extracted = True

            # Phase 3: Static analysis (always performed)
            with ProgressLogger(logger, "Static Analysis"):
                static_results = self._run_static_analysis(firmware_info)
                session.scan_results.extend(static_results)

            # Phase 4: Emulation and dynamic analysis
            if not skip_emulation:
                with ProgressLogger(logger, "Dynamic Analysis"):
                    emulation_state = self._start_emulation(firmware_info)
                    if emulation_state and emulation_state.boot_successful:
                        session.target_ip = emulation_state.ip_address
                        session.target_port = emulation_state.http_port

                        dynamic_results = self._run_dynamic_analysis(
                            firmware_info, emulation_state, scanners
                        )
                        session.scan_results.extend(dynamic_results)

                        # Cleanup emulation
                        self._stop_emulation(emulation_state)

            # Phase 5: CVE correlation
            with ProgressLogger(logger, "CVE Correlation"):
                self._correlate_cves(session)

            # Phase 6: Generate reports
            if generate_report:
                with ProgressLogger(logger, "Report Generation"):
                    self._generate_reports(session)

            session.status = ScanStatus.COMPLETED
            session.completed_at = datetime.now()

            # Log summary
            summary = session.get_summary()
            logger.info(
                f"Scan completed - {summary['total_vulnerabilities']} vulnerabilities found"
            )
            logger.info(f"  CRITICAL: {summary['by_severity']['critical']}")
            logger.info(f"  HIGH: {summary['by_severity']['high']}")
            logger.info(f"  MEDIUM: {summary['by_severity']['medium']}")
            logger.info(f"  LOW: {summary['by_severity']['low']}")

        except EmberScanError as e:
            logger.error(f"Scan failed: {e}")
            session.status = ScanStatus.FAILED
            session.completed_at = datetime.now()
            raise

        except Exception as e:
            logger.exception(f"Unexpected error during scan: {e}")
            session.status = ScanStatus.FAILED
            session.completed_at = datetime.now()
            raise EmberScanError(f"Scan failed: {e}")

        finally:
            # Cleanup any running emulations
            for emu_id in list(self.active_emulations.keys()):
                try:
                    self._stop_emulation(self.active_emulations[emu_id])
                except:
                    pass

        return session

    # ========================================================================
    # Analysis Phases
    # ========================================================================

    def _analyze_firmware(self, firmware_path: str) -> FirmwareInfo:
        """Analyze firmware file and extract metadata."""
        logger.info(f"Analyzing firmware: {firmware_path}")

        firmware = FirmwareInfo(file_path=firmware_path)
        firmware.calculate_hashes()

        # Detect architecture and filesystem
        analysis = self.extractor.analyze(firmware_path)

        firmware.architecture = analysis.get("architecture", Architecture.UNKNOWN)
        firmware.endianness = analysis.get("endianness")
        firmware.filesystem_type = analysis.get("filesystem_type")
        firmware.components = analysis.get("components", [])

        # Try to detect vendor/version from strings
        metadata = self.extractor.extract_metadata(firmware_path)
        firmware.vendor = metadata.get("vendor", "")
        firmware.version = metadata.get("version", "")
        firmware.device_type = metadata.get("device_type", "")
        firmware.name = metadata.get("name", Path(firmware_path).stem)

        logger.info(f"Detected: {firmware.architecture.value} / {firmware.filesystem_type.value}")

        return firmware

    def _extract_firmware(self, firmware: FirmwareInfo) -> Path:
        """Extract firmware filesystem."""
        logger.info(f"Extracting firmware: {firmware.name}")

        extraction_dir = self.dirs["extracted"] / firmware.id
        extraction_dir.mkdir(exist_ok=True)

        rootfs_path = self.extractor.extract(firmware.file_path, str(extraction_dir))

        firmware.rootfs_path = str(rootfs_path)

        logger.info(f"Extracted to: {rootfs_path}")
        return rootfs_path

    def _run_static_analysis(self, firmware: FirmwareInfo) -> List[ScanResult]:
        """Run static analysis on extracted filesystem."""
        results = []

        if not firmware.rootfs_path:
            logger.warning("No rootfs path - skipping static analysis")
            return results

        # Binary analysis
        try:
            binary_scanner = self.get_scanner("binary")
            result = binary_scanner.scan(firmware.rootfs_path, firmware)
            results.append(result)
        except Exception as e:
            logger.error(f"Binary scanner failed: {e}")

        # Credential scanner
        try:
            cred_scanner = self.get_scanner("credentials")
            result = cred_scanner.scan(firmware.rootfs_path, firmware)
            results.append(result)
        except Exception as e:
            logger.error(f"Credential scanner failed: {e}")

        # Crypto analysis
        try:
            crypto_scanner = self.get_scanner("crypto")
            result = crypto_scanner.scan(firmware.rootfs_path, firmware)
            results.append(result)
        except Exception as e:
            logger.error(f"Crypto scanner failed: {e}")

        return results

    def _start_emulation(self, firmware: FirmwareInfo) -> Optional[EmulationState]:
        """Start QEMU emulation of firmware."""
        logger.info(f"Starting emulation for: {firmware.name}")

        try:
            state = self.emulator.start(
                firmware,
                http_port=self.config.qemu.http_forward_port,
                ssh_port=self.config.qemu.ssh_forward_port,
                telnet_port=self.config.qemu.telnet_forward_port,
            )

            self.active_emulations[state.id] = state

            # Wait for boot
            if self.emulator.wait_for_boot(state, timeout=self.config.qemu.timeout):
                logger.info(f"Firmware booted successfully - Web: {state.get_web_url()}")
                return state
            else:
                logger.warning("Firmware failed to boot - skipping dynamic analysis")
                return None

        except EmulationError as e:
            logger.error(f"Emulation failed: {e}")
            return None

    def _stop_emulation(self, state: EmulationState):
        """Stop QEMU emulation."""
        try:
            self.emulator.stop(state)
            if state.id in self.active_emulations:
                del self.active_emulations[state.id]
            logger.info(f"Emulation stopped: {state.id}")
        except Exception as e:
            logger.error(f"Failed to stop emulation: {e}")

    def _run_dynamic_analysis(
        self, firmware: FirmwareInfo, emulation: EmulationState, scanners: List[str] = None
    ) -> List[ScanResult]:
        """Run dynamic analysis against emulated firmware."""
        results = []

        # Determine which scanners to run
        scanner_list = scanners or self.config.scanner.enabled_scanners
        dynamic_scanners = [s for s in scanner_list if s in ["web", "network"]]

        target_url = emulation.get_web_url()
        target_ip = emulation.ip_address

        # Run scanners in parallel
        with ThreadPoolExecutor(max_workers=self.config.scanner.parallel_scans) as executor:
            futures = {}

            for scanner_name in dynamic_scanners:
                try:
                    scanner = self.get_scanner(scanner_name)

                    if scanner_name == "web":
                        future = executor.submit(scanner.scan, target_url, firmware)
                    elif scanner_name == "network":
                        future = executor.submit(
                            scanner.scan,
                            target_ip,
                            firmware,
                            ports=[emulation.http_port, emulation.ssh_port, emulation.telnet_port],
                        )
                    else:
                        continue

                    futures[future] = scanner_name

                except Exception as e:
                    logger.error(f"Failed to start {scanner_name} scanner: {e}")

            # Collect results
            for future in as_completed(futures, timeout=self.config.scanner.timeout_per_scan):
                scanner_name = futures[future]
                try:
                    result = future.result()
                    results.append(result)
                    logger.info(
                        f"{scanner_name} scanner completed: {len(result.vulnerabilities)} findings"
                    )
                except Exception as e:
                    logger.error(f"{scanner_name} scanner failed: {e}")

        return results

    def _correlate_cves(self, session: ScanSession):
        """Correlate findings with CVE database."""
        try:
            cve_scanner = self.get_scanner("cve")

            # Get all vulnerabilities
            all_vulns = session.all_vulnerabilities

            # Correlate with CVE database
            for vuln in all_vulns:
                matches = cve_scanner.find_cves(vuln, session.firmware)
                if matches:
                    vuln.cve_ids.extend(matches)
                    logger.debug(f"CVE match: {vuln.title} -> {matches}")

        except Exception as e:
            logger.error(f"CVE correlation failed: {e}")

    def _generate_reports(self, session: ScanSession):
        """Generate scan reports in configured formats."""
        from ..reporters.html_reporter import HTMLReporter
        from ..reporters.json_reporter import JSONReporter

        # Use configured output directory instead of workspace reports
        output_base = Path(self.config.reporter.output_dir)
        report_dir = output_base / session.id
        report_dir.mkdir(parents=True, exist_ok=True)

        for format_name in self.config.reporter.output_formats:
            try:
                if format_name == "html":
                    reporter = HTMLReporter(self.config)
                elif format_name == "json":
                    reporter = JSONReporter(self.config)
                else:
                    logger.warning(f"Unknown report format: {format_name}")
                    continue

                output_path = reporter.generate(session, str(report_dir))
                logger.info(f"Report generated: {output_path}")

            except Exception as e:
                logger.error(f"Failed to generate {format_name} report: {e}")

    # ========================================================================
    # Utility Methods
    # ========================================================================

    def get_session(self, session_id: str) -> Optional[ScanSession]:
        """Get scan session by ID."""
        return self.active_sessions.get(session_id)

    def list_sessions(self) -> List[Dict]:
        """List all scan sessions."""
        return [s.get_summary() for s in self.active_sessions.values()]

    def cancel_session(self, session_id: str) -> bool:
        """Cancel a running scan session."""
        session = self.active_sessions.get(session_id)
        if session and session.status == ScanStatus.RUNNING:
            session.status = ScanStatus.CANCELLED
            logger.info(f"Session cancelled: {session_id}")
            return True
        return False

    def check_dependencies(self) -> Dict[str, bool]:
        """Check if required dependencies are installed."""
        import shutil

        dependencies = {
            "binwalk": shutil.which("binwalk") is not None,
            "unsquashfs": shutil.which("unsquashfs") is not None,
            "qemu-system-mipsel": shutil.which("qemu-system-mipsel") is not None,
            "qemu-system-arm": shutil.which("qemu-system-arm") is not None,
            "nmap": shutil.which("nmap") is not None,
            "nikto": shutil.which("nikto") is not None,
        }

        return dependencies
