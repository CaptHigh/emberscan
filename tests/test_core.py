"""
Tests for EmberScan core functionality.
"""

import pytest
from pathlib import Path

from emberscan.core.config import Config, QEMUConfig, ScannerConfig
from emberscan.core.models import (
    FirmwareInfo, Vulnerability, ScanResult, ScanSession,
    Architecture, Severity, VulnerabilityType, ScanStatus
)
from emberscan.core.exceptions import EmberScanError, ExtractionError


class TestConfig:
    """Test configuration management."""
    
    def test_default_config(self):
        """Test default configuration values."""
        config = Config()
        
        assert config.project_name == "EmberScan"
        assert config.log_level == "INFO"
        assert config.qemu.memory == 256
        assert config.qemu.timeout == 300
        assert "web" in config.scanner.enabled_scanners
    
    def test_config_validation(self, temp_dir):
        """Test configuration validation."""
        config = Config(workspace_dir=str(temp_dir))
        errors = config.validate()
        
        # Should have kernel directory error
        assert any("kernel" in e.lower() for e in errors)
    
    def test_config_from_dict(self):
        """Test creating config from dictionary."""
        data = {
            'workspace_dir': '/tmp/test',
            'log_level': 'DEBUG',
            'qemu': {
                'memory': 512,
                'timeout': 600,
            }
        }
        
        config = Config._from_dict(data)
        
        assert config.workspace_dir == '/tmp/test'
        assert config.log_level == 'DEBUG'
        assert config.qemu.memory == 512


class TestModels:
    """Test data models."""
    
    def test_firmware_info(self, temp_dir):
        """Test FirmwareInfo model."""
        # Create a test file
        test_file = temp_dir / "test.bin"
        test_file.write_bytes(b"test content")
        
        firmware = FirmwareInfo(
            name="test",
            file_path=str(test_file),
            architecture=Architecture.MIPS_LE,
        )
        firmware.calculate_hashes()
        
        assert firmware.file_size > 0
        assert len(firmware.md5) == 32
        assert len(firmware.sha256) == 64
    
    def test_architecture_from_string(self):
        """Test architecture parsing."""
        assert Architecture.from_string("mipsel") == Architecture.MIPS_LE
        assert Architecture.from_string("mipsle") == Architecture.MIPS_LE
        assert Architecture.from_string("arm") == Architecture.ARM
        assert Architecture.from_string("aarch64") == Architecture.ARM64
        assert Architecture.from_string("unknown") == Architecture.UNKNOWN
    
    def test_vulnerability_creation(self):
        """Test Vulnerability model."""
        vuln = Vulnerability(
            title="Test Vulnerability",
            description="This is a test",
            severity=Severity.HIGH,
            vuln_type=VulnerabilityType.COMMAND_INJECTION,
            file_path="/etc/passwd",
        )
        
        assert vuln.title == "Test Vulnerability"
        assert vuln.severity == Severity.HIGH
        assert len(vuln.id) == 8
        
        # Test serialization
        vuln_dict = vuln.to_dict()
        assert vuln_dict['severity'] == 'high'
        assert vuln_dict['vuln_type'] == 'command_injection'
    
    def test_severity_ordering(self):
        """Test severity comparison."""
        assert Severity.INFO < Severity.LOW
        assert Severity.LOW < Severity.MEDIUM
        assert Severity.MEDIUM < Severity.HIGH
        assert Severity.HIGH < Severity.CRITICAL
    
    def test_scan_result(self):
        """Test ScanResult model."""
        result = ScanResult(
            scanner_name="test_scanner",
            scan_type="test",
            status=ScanStatus.COMPLETED,
        )
        
        result.vulnerabilities.append(
            Vulnerability(title="Test", severity=Severity.HIGH)
        )
        result.vulnerabilities.append(
            Vulnerability(title="Test2", severity=Severity.LOW)
        )
        
        counts = result.vulnerability_count
        assert counts['high'] == 1
        assert counts['low'] == 1
    
    def test_scan_session(self, sample_firmware_info):
        """Test ScanSession model."""
        session = ScanSession(
            name="Test Session",
            firmware=sample_firmware_info,
        )
        
        # Add scan results
        result = ScanResult(scanner_name="test")
        result.vulnerabilities.append(
            Vulnerability(title="Critical", severity=Severity.CRITICAL)
        )
        result.vulnerabilities.append(
            Vulnerability(title="High", severity=Severity.HIGH)
        )
        session.scan_results.append(result)
        
        assert session.critical_count == 1
        assert session.high_count == 1
        assert len(session.all_vulnerabilities) == 2
        
        summary = session.get_summary()
        assert summary['total_vulnerabilities'] == 2
        assert summary['by_severity']['critical'] == 1


class TestExceptions:
    """Test custom exceptions."""
    
    def test_emberscan_error(self):
        """Test base exception."""
        error = EmberScanError("Test error", details={'key': 'value'})
        
        assert "Test error" in str(error)
        assert "key=value" in str(error)
    
    def test_extraction_error(self):
        """Test extraction error."""
        error = ExtractionError("Extraction failed")
        
        assert isinstance(error, EmberScanError)
        assert "Extraction failed" in str(error)
