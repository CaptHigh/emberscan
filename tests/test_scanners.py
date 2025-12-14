"""
Tests for EmberScan vulnerability scanners.
"""

import pytest
from pathlib import Path

from emberscan.scanners.base import BaseScanner, ScannerRegistry
from emberscan.scanners.binary_scanner import BinaryScanner
from emberscan.scanners.credential_scanner import CredentialScanner
from emberscan.core.models import ScanStatus, Severity


class TestScannerRegistry:
    """Test scanner registry functionality."""
    
    def test_register_scanner(self, config):
        """Test scanner registration."""
        @ScannerRegistry.register('test_scanner')
        class TestScanner(BaseScanner):
            @property
            def name(self):
                return "test_scanner"
            
            def scan(self, target, firmware, **kwargs):
                return self._create_result()
        
        assert 'test_scanner' in ScannerRegistry.list_scanners()
        
        scanner = ScannerRegistry.create_scanner('test_scanner', config)
        assert scanner is not None
        assert scanner.name == "test_scanner"


class TestBinaryScanner:
    """Test binary analysis scanner."""
    
    def test_find_binaries(self, config, sample_squashfs):
        """Test binary file discovery."""
        scanner = BinaryScanner(config)
        binaries = scanner._find_binaries(sample_squashfs)
        
        # Should find our mock busybox
        assert len(binaries) >= 1
        assert any('busybox' in str(b) for b in binaries)
    
    def test_is_elf(self, config, sample_squashfs):
        """Test ELF detection."""
        scanner = BinaryScanner(config)
        
        busybox = sample_squashfs / "bin" / "busybox"
        assert scanner._is_elf(busybox) == True
        
        passwd = sample_squashfs / "etc" / "passwd"
        assert scanner._is_elf(passwd) == False
    
    def test_check_suid_binaries(self, config, sample_squashfs):
        """Test SUID binary detection."""
        scanner = BinaryScanner(config)
        
        # Set SUID bit on busybox
        busybox = sample_squashfs / "bin" / "busybox"
        busybox.chmod(0o4755)
        
        vulns = scanner._check_suid_binaries(sample_squashfs)
        
        # Should detect SUID binary
        assert len(vulns) >= 1
        assert any('SUID' in v.title for v in vulns)
    
    def test_full_scan(self, config, sample_squashfs, sample_firmware_info):
        """Test full binary scan."""
        scanner = BinaryScanner(config)
        result = scanner.scan(str(sample_squashfs), sample_firmware_info)
        
        assert result.status == ScanStatus.COMPLETED
        assert result.scanner_name == "binary_scanner"


class TestCredentialScanner:
    """Test credential discovery scanner."""
    
    def test_analyze_passwd_empty_password(self, config, sample_squashfs, sample_firmware_info):
        """Test detection of empty passwords."""
        scanner = CredentialScanner(config)
        vulns = scanner._analyze_auth_files(sample_squashfs)
        
        # Should detect empty root password
        assert len(vulns) >= 1
        assert any('Empty Password' in v.title for v in vulns)
        assert any(v.severity == Severity.CRITICAL for v in vulns)
    
    def test_find_private_keys(self, config, temp_dir, sample_firmware_info):
        """Test private key detection."""
        # Create a mock private key
        key_file = temp_dir / "server.key"
        key_file.write_text("""-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGy...
-----END RSA PRIVATE KEY-----""")
        
        scanner = CredentialScanner(config)
        vulns = scanner._find_private_keys(temp_dir)
        
        assert len(vulns) >= 1
        assert any('Private Key' in v.title for v in vulns)
    
    def test_is_false_positive(self, config):
        """Test false positive detection."""
        scanner = CredentialScanner(config)
        
        # Should be false positives
        assert scanner._is_false_positive("") == True
        assert scanner._is_false_positive("ab") == True
        assert scanner._is_false_positive("your_password") == True
        assert scanner._is_false_positive("${PASSWORD}") == True
        assert scanner._is_false_positive("placeholder") == True
        
        # Should not be false positives
        assert scanner._is_false_positive("actualP@ssw0rd!") == False
        assert scanner._is_false_positive("admin123") == False
    
    def test_search_credentials(self, config, mock_vulnerable_webapp, sample_firmware_info):
        """Test credential pattern matching."""
        # Create a parent directory structure
        rootfs = mock_vulnerable_webapp.parent
        www_dir = rootfs / "www"
        www_dir.mkdir(exist_ok=True)
        
        # Move files
        for f in mock_vulnerable_webapp.iterdir():
            f.rename(www_dir / f.name)
        
        scanner = CredentialScanner(config)
        vulns = scanner._search_credentials(rootfs)
        
        # Should find hardcoded credentials
        assert len(vulns) >= 1
    
    def test_full_scan(self, config, sample_squashfs, sample_firmware_info):
        """Test full credential scan."""
        scanner = CredentialScanner(config)
        result = scanner.scan(str(sample_squashfs), sample_firmware_info)
        
        assert result.status == ScanStatus.COMPLETED
        assert result.scanner_name == "credential_scanner"


class TestWebScanner:
    """Test web vulnerability scanner."""
    
    @pytest.mark.requires_network
    def test_default_credentials(self, config):
        """Test default credential checking logic."""
        from emberscan.scanners.web_scanner import DEFAULT_CREDENTIALS
        
        # Verify we have common defaults
        assert ('admin', 'admin') in DEFAULT_CREDENTIALS
        assert ('root', 'root') in DEFAULT_CREDENTIALS
        assert ('admin', '') in DEFAULT_CREDENTIALS


class TestCVEScanner:
    """Test CVE correlation scanner."""
    
    def test_known_vulnerable_software(self, config):
        """Test known vulnerable software database."""
        from emberscan.scanners.cve_scanner import KNOWN_VULNERABLE_SOFTWARE
        
        assert 'busybox' in KNOWN_VULNERABLE_SOFTWARE
        assert 'dropbear' in KNOWN_VULNERABLE_SOFTWARE
        assert 'openssl' in KNOWN_VULNERABLE_SOFTWARE
    
    def test_find_cves_for_component(self, config):
        """Test CVE matching for components."""
        from emberscan.scanners.cve_scanner import CVEScanner
        
        scanner = CVEScanner(config)
        
        # Test busybox CVE matching
        component = {'name': 'busybox', 'version': '1.27.0'}
        cves = scanner._find_cves_for_component(component)
        
        assert len(cves) >= 1
        assert any('CVE' in c['cve_id'] for c in cves)
    
    def test_cvss_to_severity(self, config):
        """Test CVSS score to severity conversion."""
        from emberscan.scanners.cve_scanner import CVEScanner
        
        scanner = CVEScanner(config)
        
        assert scanner._cvss_to_severity(9.5) == Severity.CRITICAL
        assert scanner._cvss_to_severity(7.5) == Severity.HIGH
        assert scanner._cvss_to_severity(5.0) == Severity.MEDIUM
        assert scanner._cvss_to_severity(2.0) == Severity.LOW
        assert scanner._cvss_to_severity(0.0) == Severity.INFO
