#!/usr/bin/env python3
"""
EmberScan Example: Basic Firmware Scan

This example demonstrates how to use EmberScan to scan
a firmware image for security vulnerabilities.

Usage:
    python examples/basic_scan.py /path/to/firmware.bin
"""

import sys
import json
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from emberscan import EmberScanner, Config
from emberscan.core.models import Severity


def main():
    # Check arguments
    if len(sys.argv) < 2:
        print("Usage: python basic_scan.py <firmware_path>")
        print("\nExample:")
        print("  python basic_scan.py firmware.bin")
        sys.exit(1)
    
    firmware_path = sys.argv[1]
    
    # Verify file exists
    if not Path(firmware_path).exists():
        print(f"Error: File not found: {firmware_path}")
        sys.exit(1)
    
    print("=" * 60)
    print("EmberScan - Basic Firmware Scan Example")
    print("=" * 60)
    
    # Load configuration
    config = Config()
    config.log_level = "INFO"
    config.workspace_dir = "./scan_workspace"
    
    # Create scanner instance
    print(f"\n[*] Initializing scanner...")
    scanner = EmberScanner(config)
    
    # Check dependencies
    print("\n[*] Checking dependencies...")
    deps = scanner.check_dependencies()
    missing = [k for k, v in deps.items() if not v]
    if missing:
        print(f"    Warning: Missing tools: {', '.join(missing)}")
    
    # Run the scan
    print(f"\n[*] Starting scan of: {firmware_path}")
    print("    This may take several minutes...\n")
    
    try:
        session = scanner.scan_firmware(
            firmware_path=firmware_path,
            session_name="Example Scan",
            # Run all scanners
            scanners=['web', 'network', 'binary', 'credentials', 'cve', 'crypto'],
            # Enable emulation for dynamic analysis
            skip_emulation=False,
            # Generate reports
            generate_report=True,
        )
        
        # Print results
        print("\n" + "=" * 60)
        print("SCAN RESULTS")
        print("=" * 60)
        
        summary = session.get_summary()
        
        print(f"\nSession: {session.name}")
        print(f"Status:  {session.status.name}")
        
        if session.firmware:
            print(f"\nFirmware Info:")
            print(f"  Name:         {session.firmware.name}")
            print(f"  Vendor:       {session.firmware.vendor}")
            print(f"  Architecture: {session.firmware.architecture.value}")
            print(f"  MD5:          {session.firmware.md5}")
        
        print(f"\nVulnerability Summary:")
        print(f"  CRITICAL: {summary['by_severity']['critical']}")
        print(f"  HIGH:     {summary['by_severity']['high']}")
        print(f"  MEDIUM:   {summary['by_severity']['medium']}")
        print(f"  LOW:      {summary['by_severity']['low']}")
        print(f"  INFO:     {summary['by_severity']['info']}")
        print(f"  ─────────────────────")
        print(f"  TOTAL:    {summary['total_vulnerabilities']}")
        
        # List vulnerabilities
        if session.all_vulnerabilities:
            print("\nVulnerabilities Found:")
            print("-" * 60)
            
            # Group by severity
            for severity in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]:
                vulns = [v for v in session.all_vulnerabilities if v.severity == severity]
                if vulns:
                    print(f"\n[{severity.value.upper()}]")
                    for vuln in vulns:
                        print(f"  • {vuln.title}")
                        if vuln.file_path:
                            print(f"    File: {vuln.file_path}")
                        if vuln.cve_ids:
                            print(f"    CVEs: {', '.join(vuln.cve_ids)}")
        
        # Report location
        print(f"\n[*] Reports saved to: {config.reporter.output_dir}/{session.id}/")
        
        # Save JSON summary
        summary_file = Path(f"./scan_summary_{session.id}.json")
        with open(summary_file, 'w') as f:
            json.dump(session.to_dict(), f, indent=2, default=str)
        print(f"[*] Full results saved to: {summary_file}")
        
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"\n[!] Scan failed: {e}")
        raise


if __name__ == "__main__":
    main()
