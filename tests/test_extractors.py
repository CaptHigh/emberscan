"""
Tests for firmware extraction functionality.
"""

import pytest
from pathlib import Path

from emberscan.extractors.firmware_extractor import FirmwareExtractor, SPIExtractor
from emberscan.core.models import Architecture, FilesystemType, Endianness


class TestFirmwareExtractor:
    """Test firmware extraction and analysis."""
    
    def test_signature_detection(self, config, sample_firmware_binary):
        """Test firmware signature detection."""
        extractor = FirmwareExtractor(config)
        analysis = extractor.analyze(str(sample_firmware_binary))
        
        # Should detect TP-Link header and SquashFS
        assert len(analysis['components']) >= 2
        
        component_types = [c['type'] for c in analysis['components']]
        assert 'tplink_header' in component_types
        assert 'squashfs_le' in component_types
    
    def test_filesystem_type_detection(self, config, sample_firmware_binary):
        """Test filesystem type detection."""
        extractor = FirmwareExtractor(config)
        analysis = extractor.analyze(str(sample_firmware_binary))
        
        assert analysis['filesystem_type'] == FilesystemType.SQUASHFS
    
    def test_entropy_analysis(self, config, sample_firmware_binary):
        """Test entropy analysis."""
        extractor = FirmwareExtractor(config)
        analysis = extractor.analyze(str(sample_firmware_binary))
        
        assert 'entropy' in analysis
        assert 'average' in analysis['entropy']
        assert 0 <= analysis['entropy']['average'] <= 8
    
    def test_metadata_extraction(self, config, temp_dir):
        """Test vendor/version metadata extraction."""
        # Create firmware with vendor strings
        firmware_file = temp_dir / "tplink_firmware.bin"
        content = b"TP-LINK Technologies" + b"\x00" * 100
        content += b"Version: 1.2.3" + b"\x00" * 100
        content += b"Archer C7" + b"\x00" * 100
        firmware_file.write_bytes(content)
        
        extractor = FirmwareExtractor(config)
        metadata = extractor.extract_metadata(str(firmware_file))
        
        assert metadata['vendor'] == 'TP-Link'
        assert '1.2.3' in metadata['version']
    
    def test_elf_header_parsing(self, config):
        """Test ELF header parsing for architecture detection."""
        extractor = FirmwareExtractor(config)
        
        # MIPS Little Endian ELF header
        mipsel_header = (
            b'\x7fELF'  # Magic
            b'\x01'     # 32-bit
            b'\x01'     # Little endian
            b'\x01'     # ELF version
            b'\x00' * 9  # Padding
            b'\x02\x00'  # Type: EXEC
            b'\x08\x00'  # Machine: MIPS
            b'\x00' * 32  # Rest
        )
        
        result = extractor._parse_elf_header(mipsel_header)
        
        assert result is not None
        assert result['architecture'] == Architecture.MIPS_LE
        assert result['endianness'] == Endianness.LITTLE
    
    def test_analyze_entropy_encrypted(self, config, temp_dir):
        """Test high entropy detection (potential encryption)."""
        import os
        
        # Create file with random data (high entropy)
        random_file = temp_dir / "encrypted.bin"
        random_file.write_bytes(os.urandom(10000))
        
        extractor = FirmwareExtractor(config)
        
        with open(random_file, 'rb') as f:
            data = f.read()
        
        entropy = extractor._analyze_entropy(data)
        
        assert entropy['average'] > 7.5
        assert entropy['likely_encrypted'] == True


class TestSPIExtractor:
    """Test SPI flash extraction (mock tests)."""
    
    def test_supported_programmers(self, config):
        """Test supported programmer list."""
        spi = SPIExtractor(config)
        
        assert 'ch341a_spi' in SPIExtractor.SUPPORTED_PROGRAMMERS
        assert 'buspirate_spi' in SPIExtractor.SUPPORTED_PROGRAMMERS
    
    def test_programmer_selection(self, config):
        """Test programmer selection."""
        spi = SPIExtractor(config, programmer='buspirate_spi')
        
        assert spi.programmer == 'buspirate_spi'
