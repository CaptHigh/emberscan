#!/usr/bin/env python3
"""
EmberScan Command Line Interface.

Usage:
    emberscan scan <firmware> [options]
    emberscan extract <firmware> [options]
    emberscan emulate <firmware> [options]
    emberscan analyze <binary|rootfs> [options]
    emberscan report <session-id> [options]
    emberscan spi-read [options]
    emberscan check-deps
    emberscan install-deps
    emberscan --version
"""

import argparse
import os
import sys
from pathlib import Path
from typing import Optional

# Quiet Unicorn's direct-to-stderr "register accessing" deprecation notice
# before any emulation backend (Unicorn/Qiling) spins up.
os.environ.setdefault("UC_IGNORE_REG_BREAK", "1")

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from emberscan import __version__
from emberscan.core.config import Config
from emberscan.core.logger import get_logger, setup_logging
from emberscan.core.scanner import EmberScanner
from emberscan.core.ui import SEVERITY_ORDER, ui
from emberscan.emulators.qemu_manager import QEMUManager
from emberscan.extractors.firmware_extractor import FirmwareExtractor, SPIExtractor
from emberscan.utils import check_dependencies, install_python_deps, print_dependency_status


# Minimal ANSI codes kept only for a couple of plain-text spots; all rich
# presentation goes through emberscan.core.ui.
class Colors:
    CYAN = "\033[96m"
    GREEN = "\033[92m"
    WARNING = "\033[93m"
    FAIL = "\033[91m"
    BLUE = "\033[94m"
    END = "\033[0m"
    BOLD = "\033[1m"


def _vulns_to_rows(vulns):
    """Convert Vulnerability objects to the dict rows the UI table expects,
    sorted most-severe first."""
    order = {s: i for i, s in enumerate(SEVERITY_ORDER)}
    rows = []
    for v in sorted(vulns, key=lambda x: order.get(_sev(x), 9)):
        loc = getattr(v, "file_path", "") or ""
        fn = getattr(v, "function_name", "") or ""
        if fn:
            loc = f"{loc} ({fn})" if loc else fn
        vt = getattr(v, "vuln_type", None)
        occ = getattr(v, "occurrences", 1) or 1
        extra = getattr(v, "extra_locations", []) or []
        if occ > 1:
            more = len(extra)
            loc = (loc or "(multiple)") + f"  (+{more} more file{'s' if more != 1 else ''})"
        rows.append(
            {
                "severity": _sev(v),
                "vuln_type": getattr(vt, "value", "") if vt is not None else "",
                "title": getattr(v, "title", ""),
                "location": loc,
                "evidence": getattr(v, "evidence", "") or "",
            }
        )
    return rows


def _sev(v):
    s = getattr(v, "severity", None)
    return getattr(s, "value", s) or "info"


def create_parser() -> argparse.ArgumentParser:
    """Create argument parser."""
    parser = argparse.ArgumentParser(
        prog="emberscan",
        description="Automated Embedded Hardware Firmware Security Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  emberscan scan firmware.bin
  emberscan scan firmware.bin --scanners web,network --output ./reports
  emberscan extract firmware.bin --output ./extracted
  emberscan emulate firmware.bin --http-port 8080
  emberscan analyze ./extracted/squashfs-root --detectors taint,memory_safety
  emberscan analyze ./bin/httpd --backend qiling
  emberscan spi-read --programmer ch341a_spi --output dump.bin
  emberscan check-deps
  emberscan install-deps
        """,
    )

    parser.add_argument("-v", "--version", action="version", version=f"EmberScan {__version__}")

    parser.add_argument("-c", "--config", help="Path to configuration file", default=None)

    parser.add_argument(
        "--quiet", "-q", action="store_true", help="Suppress banner and non-essential output"
    )

    parser.add_argument("--debug", action="store_true", help="Enable debug logging")

    # Subcommands
    subparsers = parser.add_subparsers(dest="command", help="Commands")

    # =========================================================================
    # Scan command
    # =========================================================================
    scan_parser = subparsers.add_parser("scan", help="Scan firmware for vulnerabilities")
    scan_parser.add_argument("firmware", help="Path to firmware file")
    scan_parser.add_argument(
        "-o", "--output", help="Output directory for reports", default="./emberscan_reports"
    )
    scan_parser.add_argument("-n", "--name", help="Name for this scan session", default=None)
    scan_parser.add_argument(
        "--scanners",
        help="Comma-separated list of scanners to run (web,network,binary,cve,credentials,crypto)",
        default=None,
    )
    scan_parser.add_argument(
        "--static-only", action="store_true", help="Skip emulation, perform static analysis only"
    )
    scan_parser.add_argument("--no-report", action="store_true", help="Skip report generation")
    scan_parser.add_argument(
        "--format", help="Report format (html,json,sarif)", default="html,json"
    )
    scan_parser.add_argument("--timeout", type=int, help="Scan timeout in seconds", default=1800)

    # =========================================================================
    # Extract command
    # =========================================================================
    extract_parser = subparsers.add_parser("extract", help="Extract firmware filesystem")
    extract_parser.add_argument("firmware", help="Path to firmware file")
    extract_parser.add_argument("-o", "--output", help="Output directory", default="./extracted")
    extract_parser.add_argument(
        "--analyze-only", action="store_true", help="Only analyze, do not extract"
    )

    # =========================================================================
    # Emulate command
    # =========================================================================
    emulate_parser = subparsers.add_parser("emulate", help="Emulate firmware in QEMU")
    emulate_parser.add_argument("firmware", help="Path to firmware or extracted rootfs")
    emulate_parser.add_argument(
        "--arch",
        choices=["mipsel", "mips", "arm", "aarch64", "x86", "x86_64"],
        help="Target architecture (auto-detected if not specified)",
    )
    emulate_parser.add_argument(
        "--http-port", type=int, default=8080, help="Host port for HTTP forwarding (default: 8080)"
    )
    emulate_parser.add_argument(
        "--ssh-port", type=int, default=2222, help="Host port for SSH forwarding (default: 2222)"
    )
    emulate_parser.add_argument(
        "--telnet-port",
        type=int,
        default=2323,
        help="Host port for Telnet forwarding (default: 2323)",
    )
    emulate_parser.add_argument("--memory", type=int, default=256, help="RAM in MB (default: 256)")
    emulate_parser.add_argument(
        "--debug", action="store_true", help="Enable GDB debugging (port 1234)"
    )

    # =========================================================================
    # Analyze command (per-binary emulation + dynamic detectors)
    # =========================================================================
    analyze_parser = subparsers.add_parser(
        "analyze",
        help="Emulate binaries and run dynamic vulnerability detectors",
    )
    analyze_parser.add_argument(
        "target", help="Path to a single binary or an extracted rootfs directory"
    )
    analyze_parser.add_argument(
        "--rootfs",
        help="Sysroot for shared-library resolution (default: the rootfs dir, "
        "or the binary's parent directory)",
        default=None,
    )
    analyze_parser.add_argument(
        "--backend",
        choices=["auto", "qiling", "unicorn"],
        default="auto",
        help="Emulation backend (default: auto)",
    )
    analyze_parser.add_argument(
        "--arch",
        choices=["mipsel", "mips", "arm", "aarch64", "x86", "x86_64"],
        default=None,
        help="Force architecture (needed only for raw/bare-metal blobs)",
    )
    analyze_parser.add_argument(
        "--detectors",
        default=None,
        help="Comma list: memory_safety,taint,info_leak,weak_code (default: all)",
    )
    analyze_parser.add_argument(
        "--max-binaries",
        type=int,
        default=25,
        help="Max binaries to emulate when target is a rootfs (default: 25)",
    )
    analyze_parser.add_argument(
        "--timeout",
        type=int,
        default=30,
        help="Per-binary emulation timeout in seconds (default: 30)",
    )
    analyze_parser.add_argument(
        "--no-mem-events",
        action="store_true",
        help="Disable per-access memory events (faster; skips heap red-zone checks)",
    )

    # =========================================================================
    # SPI Read command
    # =========================================================================
    spi_parser = subparsers.add_parser("spi-read", help="Read firmware from SPI flash")
    spi_parser.add_argument("-o", "--output", help="Output file path", required=True)
    spi_parser.add_argument(
        "--programmer",
        help="Programmer type (ch341a_spi, buspirate_spi, etc.)",
        default="ch341a_spi",
    )
    spi_parser.add_argument("--verify", action="store_true", help="Verify after reading")

    # =========================================================================
    # Report command
    # =========================================================================
    report_parser = subparsers.add_parser("report", help="Generate report from saved session")
    report_parser.add_argument("session_id", help="Session ID or session file path")
    report_parser.add_argument("-o", "--output", help="Output directory", default="./reports")
    report_parser.add_argument("--format", help="Report format (html,json,sarif)", default="html")

    # =========================================================================
    # Check dependencies command
    # =========================================================================
    deps_parser = subparsers.add_parser("check-deps", help="Check installed dependencies")

    # =========================================================================
    # Install dependencies command
    # =========================================================================
    install_parser = subparsers.add_parser(
        "install-deps",
        help="Install the Python emulation libraries (unicorn/capstone/keystone/qiling)",
    )
    install_parser.add_argument(
        "--no-pip-upgrade", action="store_true", help="Do not upgrade pip first"
    )

    # =========================================================================
    # Download kernels command
    # =========================================================================
    kernels_parser = subparsers.add_parser("download-kernels", help="Download emulation kernels")
    kernels_parser.add_argument(
        "--arch", help="Architecture to download (mipsel,mips,arm), default: all", default=None
    )
    kernels_parser.add_argument("-o", "--output", help="Output directory", default="./kernels")

    return parser


def cmd_scan(args, config: Config):
    """Execute scan command."""
    logger = get_logger("cli")

    # Validate firmware path
    firmware_path = Path(args.firmware)
    if not firmware_path.exists():
        ui.error(f"Firmware file not found: {args.firmware}")
        sys.exit(1)

    # Parse scanners
    scanners = None
    if args.scanners:
        scanners = [s.strip() for s in args.scanners.split(",")]

    # Update config
    if args.format:
        config.reporter.output_formats = [f.strip() for f in args.format.split(",")]
    config.reporter.output_dir = args.output

    ui.kv_panel(
        "Scan",
        [
            ("target", firmware_path),
            ("size", f"{firmware_path.stat().st_size:,} bytes"),
            ("output", args.output),
            ("mode", "static-only" if args.static_only else "static + emulation"),
        ],
    )

    try:
        scanner = EmberScanner(config)

        # Check dependencies
        deps = scanner.check_dependencies()
        missing = [k for k, v in deps.items() if not v]
        if missing:
            ui.warn(
                f"Missing optional tools: {', '.join(missing)} "
                "(some scans limited; see 'emberscan check-deps')"
            )

        # Run scan
        session = scanner.scan_firmware(
            firmware_path=str(firmware_path),
            session_name=args.name,
            scanners=scanners,
            skip_emulation=args.static_only,
            generate_report=not args.no_report,
        )

        # Target / firmware summary
        fw = session.firmware
        if fw is not None:
            ui.blank()
            ui.kv_panel(
                "Firmware",
                [
                    ("vendor", fw.vendor or "unknown"),
                    ("model", fw.name or "unknown"),
                    ("device", fw.device_type or "unknown"),
                    ("version", fw.version or "unknown"),
                    ("arch", getattr(fw.architecture, "value", "unknown")),
                    ("endianness", getattr(fw.endianness, "value", "unknown")),
                    ("filesystem", getattr(fw.filesystem_type, "value", "unknown")),
                ],
                border="magenta",
            )

        # Findings
        summary = session.get_summary()
        ui.blank()
        ui.rule("Findings")
        ui.severity_summary(summary["by_severity"], summary["total_vulnerabilities"])
        ui.blank()
        ui.findings_table(_vulns_to_rows(session.all_vulnerabilities))

        if summary["duration"]:
            ui.blank()
            ui.info(f"Completed in {summary['duration']:.1f}s")

        if not args.no_report:
            ui.success(f"Reports saved to: {args.output}/{session.report_slug}/")

        # Exit code based on findings
        if summary["by_severity"]["critical"] > 0:
            sys.exit(2)
        elif summary["by_severity"]["high"] > 0:
            sys.exit(1)

    except KeyboardInterrupt:
        ui.warn("Scan interrupted by user")
        sys.exit(130)
    except Exception as e:
        ui.error(f"Scan failed: {e}")
        if args.debug:
            import traceback

            traceback.print_exc()
        sys.exit(1)


def cmd_extract(args, config: Config):
    """Execute extract command."""
    firmware_path = Path(args.firmware)

    if not firmware_path.exists():
        print(f"{Colors.FAIL}Error: File not found: {args.firmware}{Colors.END}")
        sys.exit(1)

    extractor = FirmwareExtractor(config)

    print(f"\n{Colors.CYAN}[*] Analyzing firmware: {firmware_path}{Colors.END}")

    # Analyze
    analysis = extractor.analyze(str(firmware_path))

    print(f"\n{Colors.GREEN}Analysis Results:{Colors.END}")
    print(f"  File size:    {analysis['file_size']:,} bytes")
    print(f"  Architecture: {analysis['architecture'].value}")
    print(f"  Filesystem:   {analysis['filesystem_type'].value}")
    print(f"  Entropy:      {analysis['entropy']['average']:.2f}")

    if analysis["entropy"].get("likely_encrypted"):
        print(f"  {Colors.WARNING}Warning: High entropy suggests encryption{Colors.END}")

    print(f"\n  Components found: {len(analysis['components'])}")
    for comp in analysis["components"][:10]:
        print(f"    - {comp['offset_hex']}: {comp['description']}")

    if args.analyze_only:
        return

    # Extract
    print(f"\n{Colors.CYAN}[*] Extracting filesystem...{Colors.END}")

    try:
        rootfs = extractor.extract(str(firmware_path), args.output)
        print(f"\n{Colors.GREEN}Extraction complete: {rootfs}{Colors.END}")
    except Exception as e:
        print(f"\n{Colors.FAIL}Extraction failed: {e}{Colors.END}")
        sys.exit(1)


def cmd_emulate(args, config: Config):
    """Execute emulate command."""
    from emberscan.core.models import Architecture, FirmwareInfo

    firmware_path = Path(args.firmware)

    if not firmware_path.exists():
        print(f"{Colors.FAIL}Error: Path not found: {args.firmware}{Colors.END}")
        sys.exit(1)

    # Update config
    config.qemu.memory = args.memory

    # Create firmware info
    firmware = FirmwareInfo(file_path=str(firmware_path))
    extractor = FirmwareExtractor(config)
    is_dir = firmware_path.is_dir()

    # Resolve architecture (a directory can't be opened as a file, so detect
    # from its binaries instead of analysing the path as an image).
    if args.arch:
        firmware.architecture = Architecture.from_string(args.arch)
    elif is_dir:
        info = extractor.detect_arch_from_rootfs(str(firmware_path))
        if info:
            firmware.architecture = info["architecture"]
    else:
        try:
            analysis = extractor.analyze(str(firmware_path))
            firmware.architecture = analysis["architecture"]
        except Exception as e:
            ui.warn(f"Architecture detection failed: {e}")

    # Obtain a rootfs: use the directory directly, or extract the image first.
    if is_dir:
        firmware.rootfs_path = str(firmware_path)
        firmware.extracted = True
    else:
        ui.step("Extracting firmware...")
        try:
            rootfs = extractor.extract(str(firmware_path), "./emulation_temp")
        except Exception as e:
            ui.error(f"Cannot emulate: firmware could not be extracted ({e})")
            sys.exit(1)
        firmware.rootfs_path = str(rootfs)
        firmware.extracted = True

    if firmware.architecture == Architecture.UNKNOWN:
        ui.warn(
            "Architecture could not be determined; QEMU may fail to boot. "
            "Pass --arch to force one."
        )

    ui.kv_panel(
        "QEMU Emulation",
        [
            ("rootfs", firmware.rootfs_path),
            ("arch", firmware.architecture.value),
            ("http", args.http_port),
            ("ssh", args.ssh_port),
        ],
    )

    try:
        manager = QEMUManager(config)

        state = manager.start(
            firmware,
            http_port=args.http_port,
            ssh_port=args.ssh_port,
            telnet_port=args.telnet_port,
            enable_debug=args.debug,
        )

        print(f"\n{Colors.GREEN}QEMU started (PID: {state.pid}){Colors.END}")
        print(f"\nWaiting for boot...")

        if manager.wait_for_boot(state, timeout=300):
            print(f"\n{Colors.GREEN}Firmware booted successfully!{Colors.END}")
            print(f"\nAccess points:")
            print(f"  Web:    http://localhost:{args.http_port}")
            print(f"  SSH:    ssh -p {args.ssh_port} root@localhost")
            print(f"  Telnet: telnet localhost {args.telnet_port}")

            if args.debug:
                print(f"  GDB:    target remote localhost:1234")

            print(f"\nPress Ctrl+C to stop emulation...")

            # Wait for user interrupt
            try:
                while True:
                    import time

                    time.sleep(1)
            except KeyboardInterrupt:
                pass

        else:
            print(
                f"\n{Colors.WARNING}Boot timeout - firmware may not be fully functional{Colors.END}"
            )

        manager.stop(state)
        print(f"\n{Colors.CYAN}Emulation stopped{Colors.END}")

    except Exception as e:
        print(f"\n{Colors.FAIL}Emulation failed: {e}{Colors.END}")
        sys.exit(1)


def cmd_analyze(args, config: Config):
    """Execute per-binary emulation analysis."""
    from emberscan.core.models import Architecture, FirmwareInfo
    from emberscan.scanners.emulation_scanner import EmulationScanner

    target = Path(args.target)
    if not target.exists():
        print(f"{Colors.FAIL}Error: Path not found: {args.target}{Colors.END}")
        sys.exit(1)

    # Apply CLI overrides onto the emulation config
    config.emulation.enabled = True
    config.emulation.backend = args.backend
    config.emulation.rootfs = args.rootfs
    config.emulation.max_binaries = args.max_binaries
    config.emulation.timeout_per_binary = args.timeout
    config.emulation.mem_events = not args.no_mem_events
    if args.detectors:
        config.emulation.detectors = [d.strip() for d in args.detectors.split(",")]

    firmware = FirmwareInfo(file_path=str(target), name=target.name)
    if args.arch:
        firmware.architecture = Architecture.from_string(args.arch)

    ui.kv_panel(
        "Emulated Analysis",
        [
            ("target", target),
            ("backend", args.backend),
            ("detectors", args.detectors or "all"),
        ],
    )

    scanner = EmulationScanner(config)
    result = scanner.scan(str(target), firmware)
    vulns = result.vulnerabilities

    counts = {s: sum(1 for v in vulns if _sev(v) == s) for s in SEVERITY_ORDER}
    ui.blank()
    ui.rule("Findings")
    ui.info(
        f"Binaries emulated: {result.items_scanned}"
        + (f"  ·  Duration: {result.duration:.1f}s" if result.duration else "")
    )
    ui.blank()
    ui.severity_summary(counts, len(vulns))
    ui.blank()
    ui.findings_table(_vulns_to_rows(vulns))

    if counts["critical"]:
        sys.exit(2)
    elif counts["high"]:
        sys.exit(1)


def _session_from_report(data: dict):
    """Reconstruct a ScanSession from a saved EmberScan JSON report so reports
    can be regenerated without re-scanning."""
    from datetime import datetime as _dt

    from emberscan.core.models import (
        Architecture,
        Endianness,
        FilesystemType,
        FirmwareInfo,
        ScanResult,
        ScanSession,
        Severity,
        Vulnerability,
        VulnerabilityType,
    )

    def _ts(v):
        try:
            return _dt.fromisoformat(v) if v else None
        except Exception:
            return None

    def _enum(cls, val, default):
        try:
            return cls(val)
        except Exception:
            return default

    info = data.get("scan_info", {})
    session = ScanSession(name=info.get("session_name", "regenerated"))
    if info.get("session_id"):
        session.id = info["session_id"]
    session.started_at = _ts(info.get("started_at"))
    session.completed_at = _ts(info.get("completed_at"))

    fw = (data.get("target", {}) or {}).get("firmware")
    if fw:
        session.firmware = FirmwareInfo(
            name=fw.get("name", ""),
            version=fw.get("version", ""),
            vendor=fw.get("vendor", ""),
            device_type=fw.get("device_type", ""),
            file_path=fw.get("file_path", ""),
            architecture=_enum(Architecture, fw.get("architecture"), Architecture.UNKNOWN),
            endianness=_enum(Endianness, fw.get("endianness"), Endianness.UNKNOWN),
            filesystem_type=_enum(
                FilesystemType, fw.get("filesystem_type"), FilesystemType.UNKNOWN
            ),
        )

    for r in data.get("scan_results", []):
        result = ScanResult(
            scanner_name=r.get("scanner_name", ""), scan_type=r.get("scan_type", "")
        )
        for v in r.get("vulnerabilities", []):
            result.vulnerabilities.append(
                Vulnerability(
                    title=v.get("title", ""),
                    description=v.get("description", ""),
                    severity=_enum(Severity, v.get("severity"), Severity.INFO),
                    vuln_type=_enum(VulnerabilityType, v.get("vuln_type"), VulnerabilityType.OTHER),
                    file_path=v.get("file_path"),
                    line_number=v.get("line_number"),
                    function_name=v.get("function_name"),
                    evidence=v.get("evidence", "") or "",
                    remediation=v.get("remediation", "") or "",
                    cve_ids=v.get("cve_ids", []) or [],
                    cwe_ids=v.get("cwe_ids", []) or [],
                    scanner_name=v.get("scanner_name", ""),
                    occurrences=v.get("occurrences", 1) or 1,
                    extra_locations=v.get("extra_locations", []) or [],
                )
            )
        session.scan_results.append(result)
    return session


def cmd_report(args, config: Config):
    """Regenerate reports from a saved EmberScan JSON report."""
    import json

    path = Path(args.session_id)
    if path.is_dir():
        cands = sorted(path.glob("emberscan_*.json"))
        if not cands:
            ui.error(f"No EmberScan JSON report found in {path}")
            sys.exit(1)
        path = cands[0]
    if not path.exists():
        ui.error(
            f"Report not found: {args.session_id} "
            "(pass a saved emberscan_*.json file or its directory)"
        )
        sys.exit(1)

    try:
        data = json.loads(path.read_text())
    except Exception as e:
        ui.error(f"Could not parse JSON report: {e}")
        sys.exit(1)

    session = _session_from_report(data)
    config.reporter.output_formats = [f.strip() for f in args.format.split(",")]
    config.reporter.output_dir = args.output

    from emberscan.reporters.html_reporter import HTMLReporter
    from emberscan.reporters.json_reporter import JSONReporter

    out_dir = Path(args.output) / session.report_slug
    out_dir.mkdir(parents=True, exist_ok=True)

    ui.kv_panel(
        "Regenerate Report",
        [
            ("source", path),
            ("formats", ", ".join(config.reporter.output_formats)),
            ("findings", len(session.all_vulnerabilities)),
        ],
    )
    written = []
    for fmt in config.reporter.output_formats:
        try:
            if fmt == "html":
                written.append(HTMLReporter(config).generate(session, str(out_dir)))
            elif fmt in ("json", "sarif"):
                written.append(JSONReporter(config).generate(session, str(out_dir)))
            else:
                ui.warn(f"Unknown report format: {fmt}")
        except Exception as e:
            ui.error(f"Failed to generate {fmt}: {e}")
    for w in written:
        ui.success(f"Wrote {w}")


def cmd_spi_read(args, config: Config):
    """Execute SPI read command."""
    print(f"\n{Colors.CYAN}[*] SPI Flash Read{Colors.END}")
    print(f"    Programmer: {args.programmer}")
    print(f"    Output:     {args.output}")

    spi = SPIExtractor(config, programmer=args.programmer)

    # Detect chip
    print(f"\n{Colors.CYAN}[*] Detecting flash chip...{Colors.END}")
    chip = spi.detect_chip()

    if chip:
        print(f"    Found: {chip['name']}")
    else:
        print(f"{Colors.WARNING}    No chip detected - check connections{Colors.END}")
        sys.exit(1)

    # Read flash
    print(f"\n{Colors.CYAN}[*] Reading flash contents...{Colors.END}")

    if spi.read_flash(args.output, verify=args.verify):
        print(f"\n{Colors.GREEN}Flash read complete: {args.output}{Colors.END}")
    else:
        print(f"\n{Colors.FAIL}Flash read failed{Colors.END}")
        sys.exit(1)


def cmd_check_deps(args, config: Config):
    """Check and display dependency status."""
    print_dependency_status()


def cmd_install_deps(args, config: Config):
    """Install the Python emulation libraries into the current environment."""
    print(
        f"\n{Colors.CYAN}[*] Installing emulation libraries "
        f"(unicorn, capstone, keystone, qiling)...{Colors.END}"
    )
    rc = install_python_deps(upgrade_pip=not args.no_pip_upgrade)
    if rc == 0:
        print(f"\n{Colors.GREEN}[+] Done.{Colors.END}")
    else:
        print(
            f"\n{Colors.FAIL}[!] pip exited with code {rc}. "
            f"Check network/permissions, or run: python scripts/install.py{Colors.END}"
        )
    print_dependency_status()
    sys.exit(rc)


def cmd_download_kernels(args, config: Config):
    """Download emulation kernels."""
    config.qemu.kernel_dir = args.output
    manager = QEMUManager(config)

    archs = None
    if args.arch:
        archs = [args.arch]

    print(f"\n{Colors.CYAN}[*] Downloading emulation kernels...{Colors.END}")
    manager.download_kernels(archs)
    print(f"\n{Colors.GREEN}Kernels saved to: {args.output}{Colors.END}")


def main():
    """Main entry point."""
    parser = create_parser()
    args = parser.parse_args()

    ui.quiet = bool(getattr(args, "quiet", False))

    # Show banner unless quiet
    if args.command:
        ui.banner(__version__)

    # Setup logging. The file always captures DEBUG+; the console stays quiet
    # (WARNING+) unless --debug is passed, so logs never bury the CLI output.
    setup_logging(
        level="DEBUG",
        console_level="DEBUG" if args.debug else ("ERROR" if ui.quiet else "WARNING"),
        force=True,
    )

    # Load configuration
    config = Config.load(args.config)

    if args.debug:
        config.log_level = "DEBUG"

    # Route to command handler
    if args.command == "scan":
        cmd_scan(args, config)
    elif args.command == "extract":
        cmd_extract(args, config)
    elif args.command == "emulate":
        cmd_emulate(args, config)
    elif args.command == "analyze":
        cmd_analyze(args, config)
    elif args.command == "report":
        cmd_report(args, config)
    elif args.command == "spi-read":
        cmd_spi_read(args, config)
    elif args.command == "check-deps":
        cmd_check_deps(args, config)
    elif args.command == "install-deps":
        cmd_install_deps(args, config)
    elif args.command == "download-kernels":
        cmd_download_kernels(args, config)
    else:
        parser.print_help()
        sys.exit(0)


if __name__ == "__main__":
    main()
