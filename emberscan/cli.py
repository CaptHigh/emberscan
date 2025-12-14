#!/usr/bin/env python3
"""
EmberScan Command Line Interface.

Usage:
    emberscan scan <firmware> [options]
    emberscan extract <firmware> [options]
    emberscan emulate <firmware> [options]
    emberscan report <session-id> [options]
    emberscan spi-read [options]
    emberscan check-deps
    emberscan --version
"""

import os
import sys
import argparse
from pathlib import Path
from typing import Optional

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from emberscan import __version__
from emberscan.core.config import Config
from emberscan.core.scanner import EmberScanner
from emberscan.core.logger import setup_logging, get_logger
from emberscan.extractors.firmware_extractor import FirmwareExtractor, SPIExtractor
from emberscan.emulators.qemu_manager import QEMUManager
from emberscan.utils import print_dependency_status, check_dependencies


# ANSI Colors
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    END = '\033[0m'
    BOLD = '\033[1m'


BANNER = f"""
{Colors.CYAN}╔═══════════════════════════════════════════════════════════════╗
║                                                                  ║
║   {Colors.GREEN}███████╗███╗   ███╗██████╗ ███████╗██████╗ {Colors.CYAN}                  ║
║   {Colors.GREEN}██╔════╝████╗ ████║██╔══██╗██╔════╝██╔══██╗{Colors.CYAN}                  ║
║   {Colors.GREEN}█████╗  ██╔████╔██║██████╔╝█████╗  ██████╔╝{Colors.CYAN}                  ║
║   {Colors.GREEN}██╔══╝  ██║╚██╔╝██║██╔══██╗██╔══╝  ██╔══██╗{Colors.CYAN}                  ║
║   {Colors.GREEN}███████╗██║ ╚═╝ ██║██████╔╝███████╗██║  ██║{Colors.CYAN}                  ║
║   {Colors.GREEN}╚══════╝╚═╝     ╚═╝╚═════╝ ╚══════╝╚═╝  ╚═╝{Colors.CYAN}                  ║
║                                                                  ║
║   {Colors.WARNING}███████╗ ██████╗ █████╗ ███╗   ██╗{Colors.CYAN}                        ║
║   {Colors.WARNING}██╔════╝██╔════╝██╔══██╗████╗  ██║{Colors.CYAN}                        ║
║   {Colors.WARNING}███████╗██║     ███████║██╔██╗ ██║{Colors.CYAN}                        ║
║   {Colors.WARNING}╚════██║██║     ██╔══██║██║╚██╗██║{Colors.CYAN}                        ║
║   {Colors.WARNING}███████║╚██████╗██║  ██║██║ ╚████║{Colors.CYAN}                        ║
║   {Colors.WARNING}╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝{Colors.CYAN}                        ║
║                                                                  ║
║   {Colors.END}Embedded Hardware Firmware Security Scanner{Colors.CYAN}                  ║
║   {Colors.END}Version: {__version__}{Colors.CYAN}                                              ║
║                                                                  ║
╚═══════════════════════════════════════════════════════════════╝{Colors.END}
"""


def create_parser() -> argparse.ArgumentParser:
    """Create argument parser."""
    parser = argparse.ArgumentParser(
        prog='emberscan',
        description='Automated Embedded Hardware Firmware Security Scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  emberscan scan firmware.bin
  emberscan scan firmware.bin --scanners web,network --output ./reports
  emberscan extract firmware.bin --output ./extracted
  emberscan emulate firmware.bin --http-port 8080
  emberscan spi-read --programmer ch341a_spi --output dump.bin
  emberscan check-deps
        """
    )
    
    parser.add_argument(
        '-v', '--version',
        action='version',
        version=f'EmberScan {__version__}'
    )
    
    parser.add_argument(
        '-c', '--config',
        help='Path to configuration file',
        default=None
    )
    
    parser.add_argument(
        '--quiet', '-q',
        action='store_true',
        help='Suppress banner and non-essential output'
    )
    
    parser.add_argument(
        '--debug',
        action='store_true',
        help='Enable debug logging'
    )
    
    # Subcommands
    subparsers = parser.add_subparsers(dest='command', help='Commands')
    
    # =========================================================================
    # Scan command
    # =========================================================================
    scan_parser = subparsers.add_parser('scan', help='Scan firmware for vulnerabilities')
    scan_parser.add_argument('firmware', help='Path to firmware file')
    scan_parser.add_argument(
        '-o', '--output',
        help='Output directory for reports',
        default='./emberscan_reports'
    )
    scan_parser.add_argument(
        '-n', '--name',
        help='Name for this scan session',
        default=None
    )
    scan_parser.add_argument(
        '--scanners',
        help='Comma-separated list of scanners to run (web,network,binary,cve,credentials,crypto)',
        default=None
    )
    scan_parser.add_argument(
        '--static-only',
        action='store_true',
        help='Skip emulation, perform static analysis only'
    )
    scan_parser.add_argument(
        '--no-report',
        action='store_true',
        help='Skip report generation'
    )
    scan_parser.add_argument(
        '--format',
        help='Report format (html,json,sarif)',
        default='html,json'
    )
    scan_parser.add_argument(
        '--timeout',
        type=int,
        help='Scan timeout in seconds',
        default=1800
    )
    
    # =========================================================================
    # Extract command
    # =========================================================================
    extract_parser = subparsers.add_parser('extract', help='Extract firmware filesystem')
    extract_parser.add_argument('firmware', help='Path to firmware file')
    extract_parser.add_argument(
        '-o', '--output',
        help='Output directory',
        default='./extracted'
    )
    extract_parser.add_argument(
        '--analyze-only',
        action='store_true',
        help='Only analyze, do not extract'
    )
    
    # =========================================================================
    # Emulate command
    # =========================================================================
    emulate_parser = subparsers.add_parser('emulate', help='Emulate firmware in QEMU')
    emulate_parser.add_argument('firmware', help='Path to firmware or extracted rootfs')
    emulate_parser.add_argument(
        '--arch',
        choices=['mipsel', 'mips', 'arm', 'aarch64', 'x86', 'x86_64'],
        help='Target architecture (auto-detected if not specified)'
    )
    emulate_parser.add_argument(
        '--http-port',
        type=int,
        default=8080,
        help='Host port for HTTP forwarding (default: 8080)'
    )
    emulate_parser.add_argument(
        '--ssh-port',
        type=int,
        default=2222,
        help='Host port for SSH forwarding (default: 2222)'
    )
    emulate_parser.add_argument(
        '--telnet-port',
        type=int,
        default=2323,
        help='Host port for Telnet forwarding (default: 2323)'
    )
    emulate_parser.add_argument(
        '--memory',
        type=int,
        default=256,
        help='RAM in MB (default: 256)'
    )
    emulate_parser.add_argument(
        '--debug',
        action='store_true',
        help='Enable GDB debugging (port 1234)'
    )
    
    # =========================================================================
    # SPI Read command
    # =========================================================================
    spi_parser = subparsers.add_parser('spi-read', help='Read firmware from SPI flash')
    spi_parser.add_argument(
        '-o', '--output',
        help='Output file path',
        required=True
    )
    spi_parser.add_argument(
        '--programmer',
        help='Programmer type (ch341a_spi, buspirate_spi, etc.)',
        default='ch341a_spi'
    )
    spi_parser.add_argument(
        '--verify',
        action='store_true',
        help='Verify after reading'
    )
    
    # =========================================================================
    # Report command
    # =========================================================================
    report_parser = subparsers.add_parser('report', help='Generate report from saved session')
    report_parser.add_argument('session_id', help='Session ID or session file path')
    report_parser.add_argument(
        '-o', '--output',
        help='Output directory',
        default='./reports'
    )
    report_parser.add_argument(
        '--format',
        help='Report format (html,json,sarif)',
        default='html'
    )
    
    # =========================================================================
    # Check dependencies command
    # =========================================================================
    deps_parser = subparsers.add_parser('check-deps', help='Check installed dependencies')
    
    # =========================================================================
    # Download kernels command
    # =========================================================================
    kernels_parser = subparsers.add_parser('download-kernels', help='Download emulation kernels')
    kernels_parser.add_argument(
        '--arch',
        help='Architecture to download (mipsel,mips,arm), default: all',
        default=None
    )
    kernels_parser.add_argument(
        '-o', '--output',
        help='Output directory',
        default='./kernels'
    )
    
    return parser


def cmd_scan(args, config: Config):
    """Execute scan command."""
    logger = get_logger('cli')
    
    # Validate firmware path
    firmware_path = Path(args.firmware)
    if not firmware_path.exists():
        print(f"{Colors.FAIL}Error: Firmware file not found: {args.firmware}{Colors.END}")
        sys.exit(1)
    
    # Parse scanners
    scanners = None
    if args.scanners:
        scanners = [s.strip() for s in args.scanners.split(',')]
    
    # Update config
    if args.format:
        config.reporter.output_formats = [f.strip() for f in args.format.split(',')]
    config.reporter.output_dir = args.output
    
    print(f"\n{Colors.CYAN}[*] Starting firmware security scan...{Colors.END}")
    print(f"    Target: {firmware_path}")
    print(f"    Output: {args.output}")
    
    try:
        scanner = EmberScanner(config)
        
        # Check dependencies
        deps = scanner.check_dependencies()
        missing = [k for k, v in deps.items() if not v]
        if missing:
            print(f"\n{Colors.WARNING}Warning: Missing tools: {', '.join(missing)}{Colors.END}")
            print("Some scans may be limited. Run 'emberscan check-deps' for details.\n")
        
        # Run scan
        session = scanner.scan_firmware(
            firmware_path=str(firmware_path),
            session_name=args.name,
            scanners=scanners,
            skip_emulation=args.static_only,
            generate_report=not args.no_report,
        )
        
        # Print summary
        summary = session.get_summary()
        
        print(f"\n{Colors.GREEN}{'='*60}{Colors.END}")
        print(f"{Colors.BOLD}Scan Complete: {session.name}{Colors.END}")
        print(f"{'='*60}")
        
        print(f"\n{Colors.CYAN}Findings Summary:{Colors.END}")
        print(f"  {Colors.FAIL}CRITICAL: {summary['by_severity']['critical']}{Colors.END}")
        print(f"  {Colors.WARNING}HIGH:     {summary['by_severity']['high']}{Colors.END}")
        print(f"  {Colors.WARNING}MEDIUM:   {summary['by_severity']['medium']}{Colors.END}")
        print(f"  {Colors.BLUE}LOW:      {summary['by_severity']['low']}{Colors.END}")
        print(f"  INFO:    {summary['by_severity']['info']}")
        print(f"\n  Total:   {summary['total_vulnerabilities']}")
        
        if summary['duration']:
            print(f"\n  Duration: {summary['duration']:.1f} seconds")
        
        if not args.no_report:
            print(f"\n{Colors.GREEN}Reports saved to: {args.output}/{session.id}/{Colors.END}")
        
        # Exit code based on findings
        if summary['by_severity']['critical'] > 0:
            sys.exit(2)
        elif summary['by_severity']['high'] > 0:
            sys.exit(1)
        
    except KeyboardInterrupt:
        print(f"\n{Colors.WARNING}Scan interrupted by user{Colors.END}")
        sys.exit(130)
    except Exception as e:
        print(f"\n{Colors.FAIL}Scan failed: {e}{Colors.END}")
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
    
    if analysis['entropy'].get('likely_encrypted'):
        print(f"  {Colors.WARNING}Warning: High entropy suggests encryption{Colors.END}")
    
    print(f"\n  Components found: {len(analysis['components'])}")
    for comp in analysis['components'][:10]:
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
    from emberscan.core.models import FirmwareInfo, Architecture
    
    firmware_path = Path(args.firmware)
    
    if not firmware_path.exists():
        print(f"{Colors.FAIL}Error: Path not found: {args.firmware}{Colors.END}")
        sys.exit(1)
    
    # Update config
    config.qemu.memory = args.memory
    
    # Create firmware info
    firmware = FirmwareInfo(file_path=str(firmware_path))
    
    if args.arch:
        firmware.architecture = Architecture.from_string(args.arch)
    else:
        # Auto-detect from extracted files
        extractor = FirmwareExtractor(config)
        analysis = extractor.analyze(str(firmware_path))
        firmware.architecture = analysis['architecture']
    
    # Check if it's extracted rootfs or raw firmware
    if firmware_path.is_dir():
        firmware.rootfs_path = str(firmware_path)
        firmware.extracted = True
    else:
        # Extract first
        print(f"{Colors.CYAN}[*] Extracting firmware...{Colors.END}")
        extractor = FirmwareExtractor(config)
        rootfs = extractor.extract(str(firmware_path), './emulation_temp')
        firmware.rootfs_path = str(rootfs)
        firmware.extracted = True
    
    print(f"\n{Colors.CYAN}[*] Starting QEMU emulation...{Colors.END}")
    print(f"    Architecture: {firmware.architecture.value}")
    print(f"    HTTP port:    {args.http_port}")
    print(f"    SSH port:     {args.ssh_port}")
    
    try:
        manager = QEMUManager(config)
        
        state = manager.start(
            firmware,
            http_port=args.http_port,
            ssh_port=args.ssh_port,
            telnet_port=args.telnet_port,
            enable_debug=args.debug
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
            print(f"\n{Colors.WARNING}Boot timeout - firmware may not be fully functional{Colors.END}")
        
        manager.stop(state)
        print(f"\n{Colors.CYAN}Emulation stopped{Colors.END}")
        
    except Exception as e:
        print(f"\n{Colors.FAIL}Emulation failed: {e}{Colors.END}")
        sys.exit(1)


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
    
    # Show banner unless quiet
    if not args.quiet and args.command:
        print(BANNER)
    
    # Setup logging
    log_level = 'DEBUG' if args.debug else 'INFO'
    setup_logging(level=log_level)
    
    # Load configuration
    config = Config.load(args.config)
    
    if args.debug:
        config.log_level = 'DEBUG'
    
    # Route to command handler
    if args.command == 'scan':
        cmd_scan(args, config)
    elif args.command == 'extract':
        cmd_extract(args, config)
    elif args.command == 'emulate':
        cmd_emulate(args, config)
    elif args.command == 'spi-read':
        cmd_spi_read(args, config)
    elif args.command == 'check-deps':
        cmd_check_deps(args, config)
    elif args.command == 'download-kernels':
        cmd_download_kernels(args, config)
    else:
        parser.print_help()
        sys.exit(0)


if __name__ == '__main__':
    main()
