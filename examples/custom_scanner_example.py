#!/usr/bin/env python3
"""
EmberScan Example: Custom Scanner Plugin

This example shows how to create a custom scanner plugin
that can be integrated with EmberScan.

Usage:
    1. Copy this file to plugins/my_custom_scanner.py
    2. Enable in config: enabled_plugins: ['my_custom_scanner']
    3. Run scan as normal
"""

import re
from pathlib import Path
from typing import List

from emberscan.scanners.base import BaseScanner, ScannerRegistry
from emberscan.core.config import Config
from emberscan.core.models import (
    FirmwareInfo, ScanResult, Vulnerability,
    Severity, VulnerabilityType, ScanStatus
)


# Register the scanner with EmberScan
@ScannerRegistry.register('iot_scanner')
class IoTScanner(BaseScanner):
    """
    Custom IoT-specific vulnerability scanner.
    
    Checks for:
    - Hardcoded cloud API endpoints
    - Insecure MQTT configurations
    - Telemetry/tracking code
    - Debug interfaces
    """
    
    @property
    def name(self) -> str:
        return "iot_scanner"
    
    @property
    def scan_type(self) -> str:
        return "iot"
    
    # IoT-specific patterns to check
    IOT_PATTERNS = {
        'cloud_endpoints': [
            (r'https?://[a-z0-9.-]+\.amazonaws\.com', 'AWS Endpoint'),
            (r'https?://[a-z0-9.-]+\.azure\.com', 'Azure Endpoint'),
            (r'https?://[a-z0-9.-]+\.googleapis\.com', 'Google Cloud Endpoint'),
            (r'mqtt://[a-z0-9.-]+', 'MQTT Broker'),
            (r'mqtts://[a-z0-9.-]+', 'MQTT SSL Broker'),
        ],
        'debug_interfaces': [
            (r'telnetd\s+-l\s+/bin/sh', 'Debug Telnet Shell'),
            (r'gdbserver', 'GDB Server'),
            (r'strace', 'Strace Debug'),
            (r'/dev/console', 'Console Access'),
        ],
        'tracking': [
            (r'analytics\.', 'Analytics Tracking'),
            (r'telemetry', 'Telemetry'),
            (r'beacon', 'Beacon/Tracking'),
            (r'phone[_-]?home', 'Phone Home'),
        ],
    }
    
    def __init__(self, config: Config):
        super().__init__(config)
    
    def scan(
        self,
        target: str,
        firmware: FirmwareInfo,
        **kwargs
    ) -> ScanResult:
        """Execute IoT-specific security scan."""
        result = self._create_result()
        self._start_scan(result)
        
        try:
            rootfs = Path(target)
            
            # Check for cloud/API endpoints
            cloud_vulns = self._check_cloud_endpoints(rootfs)
            result.vulnerabilities.extend(cloud_vulns)
            
            # Check for debug interfaces
            debug_vulns = self._check_debug_interfaces(rootfs)
            result.vulnerabilities.extend(debug_vulns)
            
            # Check for MQTT configurations
            mqtt_vulns = self._check_mqtt_config(rootfs)
            result.vulnerabilities.extend(mqtt_vulns)
            
            # Check for telemetry/tracking
            tracking_vulns = self._check_tracking(rootfs)
            result.vulnerabilities.extend(tracking_vulns)
            
            self._complete_scan(result)
            
        except Exception as e:
            self._fail_scan(result, str(e))
        
        return result
    
    def _check_cloud_endpoints(self, rootfs: Path) -> List[Vulnerability]:
        """Find hardcoded cloud API endpoints."""
        vulnerabilities = []
        found_endpoints = set()
        
        for item in rootfs.rglob('*'):
            if not item.is_file() or item.stat().st_size > 1024 * 1024:
                continue
            
            try:
                content = item.read_text(errors='ignore')
                
                for pattern, endpoint_type in self.IOT_PATTERNS['cloud_endpoints']:
                    matches = re.findall(pattern, content, re.IGNORECASE)
                    
                    for match in matches:
                        if match not in found_endpoints:
                            found_endpoints.add(match)
                            
                            vuln = self._create_vulnerability(
                                title=f"Hardcoded {endpoint_type}",
                                description=f"Found hardcoded cloud endpoint: {match}",
                                severity=Severity.MEDIUM,
                                vuln_type=VulnerabilityType.INFORMATION_DISCLOSURE,
                                file_path=str(item.relative_to(rootfs)),
                                evidence=match,
                                remediation="Use configuration files or environment variables for endpoints",
                            )
                            vulnerabilities.append(vuln)
                            
            except Exception:
                continue
        
        return vulnerabilities
    
    def _check_debug_interfaces(self, rootfs: Path) -> List[Vulnerability]:
        """Check for enabled debug interfaces."""
        vulnerabilities = []
        
        # Check init scripts
        init_paths = [
            'etc/init.d', 'etc/rc.d', 'etc/rcS.d',
            'etc/inittab', 'etc/rc.local'
        ]
        
        for init_path in init_paths:
            full_path = rootfs / init_path
            
            if full_path.is_file():
                files = [full_path]
            elif full_path.is_dir():
                files = list(full_path.glob('*'))
            else:
                continue
            
            for item in files:
                if not item.is_file():
                    continue
                
                try:
                    content = item.read_text(errors='ignore')
                    
                    for pattern, debug_type in self.IOT_PATTERNS['debug_interfaces']:
                        if re.search(pattern, content, re.IGNORECASE):
                            vuln = self._create_vulnerability(
                                title=f"Debug Interface: {debug_type}",
                                description=f"Debug interface enabled in {item.name}",
                                severity=Severity.HIGH,
                                vuln_type=VulnerabilityType.BACKDOOR,
                                file_path=str(item.relative_to(rootfs)),
                                remediation="Disable debug interfaces in production firmware",
                            )
                            vulnerabilities.append(vuln)
                            
                except Exception:
                    continue
        
        return vulnerabilities
    
    def _check_mqtt_config(self, rootfs: Path) -> List[Vulnerability]:
        """Check MQTT configuration for security issues."""
        vulnerabilities = []
        
        mqtt_configs = list(rootfs.rglob('*mqtt*'))
        mqtt_configs.extend(rootfs.rglob('*mosquitto*'))
        
        for config_file in mqtt_configs:
            if not config_file.is_file():
                continue
            
            try:
                content = config_file.read_text(errors='ignore')
                
                # Check for anonymous access
                if 'allow_anonymous true' in content.lower():
                    vuln = self._create_vulnerability(
                        title="MQTT Anonymous Access Enabled",
                        description="MQTT broker allows anonymous connections",
                        severity=Severity.HIGH,
                        vuln_type=VulnerabilityType.AUTHENTICATION_BYPASS,
                        file_path=str(config_file.relative_to(rootfs)),
                        remediation="Disable anonymous access and require authentication",
                    )
                    vulnerabilities.append(vuln)
                
                # Check for unencrypted connections
                if 'listener 1883' in content and 'listener 8883' not in content:
                    vuln = self._create_vulnerability(
                        title="MQTT Unencrypted Connection",
                        description="MQTT broker only uses unencrypted port 1883",
                        severity=Severity.MEDIUM,
                        vuln_type=VulnerabilityType.INSECURE_PROTOCOL,
                        file_path=str(config_file.relative_to(rootfs)),
                        remediation="Enable TLS on port 8883 for encrypted connections",
                    )
                    vulnerabilities.append(vuln)
                    
            except Exception:
                continue
        
        return vulnerabilities
    
    def _check_tracking(self, rootfs: Path) -> List[Vulnerability]:
        """Check for telemetry and tracking code."""
        vulnerabilities = []
        found_tracking = set()
        
        # Only scan specific file types
        scan_extensions = {'.js', '.lua', '.sh', '.py', '.c', '.h', '.conf'}
        
        for item in rootfs.rglob('*'):
            if not item.is_file():
                continue
            
            if item.suffix.lower() not in scan_extensions:
                continue
            
            try:
                content = item.read_text(errors='ignore').lower()
                
                for pattern, tracking_type in self.IOT_PATTERNS['tracking']:
                    if re.search(pattern, content, re.IGNORECASE):
                        key = f"{tracking_type}:{item.name}"
                        
                        if key not in found_tracking:
                            found_tracking.add(key)
                            
                            vuln = self._create_vulnerability(
                                title=f"Potential {tracking_type}",
                                description=f"Found potential tracking/telemetry code in {item.name}",
                                severity=Severity.LOW,
                                vuln_type=VulnerabilityType.INFORMATION_DISCLOSURE,
                                file_path=str(item.relative_to(rootfs)),
                                remediation="Review and document data collection practices",
                            )
                            vulnerabilities.append(vuln)
                            
            except Exception:
                continue
        
        return vulnerabilities


# Plugin registration function (called by EmberScan)
def register(plugin_manager):
    """Register this plugin with EmberScan."""
    print(f"[Plugin] IoT Scanner registered")


# Allow running standalone for testing
if __name__ == "__main__":
    import sys
    from emberscan.core.models import FirmwareInfo, Architecture
    
    if len(sys.argv) < 2:
        print("Usage: python custom_scanner_example.py <rootfs_path>")
        sys.exit(1)
    
    rootfs_path = sys.argv[1]
    
    # Create config and scanner
    config = Config()
    scanner = IoTScanner(config)
    
    # Create firmware info
    firmware = FirmwareInfo(
        name="test",
        architecture=Architecture.MIPS_LE
    )
    
    # Run scan
    result = scanner.scan(rootfs_path, firmware)
    
    print(f"\nScan Status: {result.status.name}")
    print(f"Vulnerabilities Found: {len(result.vulnerabilities)}")
    
    for vuln in result.vulnerabilities:
        print(f"\n[{vuln.severity.value.upper()}] {vuln.title}")
        print(f"  {vuln.description}")
        if vuln.file_path:
            print(f"  File: {vuln.file_path}")
