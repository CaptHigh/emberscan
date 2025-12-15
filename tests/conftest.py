"""
Pytest configuration and fixtures for EmberScan tests.
"""

import os
import sys
import pytest
import tempfile
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from emberscan.core.config import Config
from emberscan.core.models import FirmwareInfo, Architecture


@pytest.fixture(scope="session")
def project_root():
    """Return project root directory."""
    return Path(__file__).parent.parent


@pytest.fixture
def config():
    """Create test configuration."""
    return Config(
        workspace_dir=tempfile.mkdtemp(),
        log_level="DEBUG",
    )


@pytest.fixture
def temp_dir():
    """Create temporary directory for tests."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def sample_firmware_info():
    """Create sample FirmwareInfo for testing."""
    return FirmwareInfo(
        name="test_firmware",
        version="1.0.0",
        vendor="TestVendor",
        device_type="router",
        architecture=Architecture.MIPS_LE,
    )


@pytest.fixture
def sample_squashfs(temp_dir):
    """Create a minimal SquashFS image for testing."""
    rootfs_dir = temp_dir / "rootfs"
    rootfs_dir.mkdir()

    # Create minimal filesystem structure
    (rootfs_dir / "bin").mkdir()
    (rootfs_dir / "etc").mkdir()
    (rootfs_dir / "lib").mkdir()

    # Create test files
    (rootfs_dir / "etc" / "passwd").write_text(
        "root:x:0:0:root:/root:/bin/sh\n" "nobody:x:99:99:Nobody:/:/sbin/nologin\n"
    )

    (rootfs_dir / "etc" / "shadow").write_text(
        "root::0:0:99999:7:::\n"  # Empty password for testing
    )

    # Create a mock binary (just a text file for testing)
    (rootfs_dir / "bin" / "busybox").write_bytes(
        b"\x7fELF\x01\x01\x01\x00"
        + b"\x00" * 8  # ELF header start
        + b"\x02\x00\x08\x00"  # Type: EXEC, Machine: MIPS
        + b"\x00" * 36  # Rest of header
    )

    return rootfs_dir


@pytest.fixture
def sample_firmware_binary(temp_dir):
    """Create a sample firmware binary with known signatures."""
    firmware_file = temp_dir / "firmware.bin"

    # Create firmware with TP-Link header and SquashFS signature
    content = bytearray(1024 * 10)  # 10KB file

    # TP-Link header at start
    content[0:2] = b"\x55\xaa"

    # SquashFS signature at offset 0x1000
    content[0x1000:0x1004] = b"hsqs"

    firmware_file.write_bytes(bytes(content))
    return firmware_file


@pytest.fixture
def mock_vulnerable_webapp(temp_dir):
    """Create mock web application files with vulnerabilities."""
    www_dir = temp_dir / "www"
    www_dir.mkdir()

    # PHP file with command injection
    (www_dir / "admin.php").write_text(
        """<?php
    $cmd = $_GET['cmd'];
    system($cmd);  // Command injection!
    $password = "admin123";  // Hardcoded password
    ?>"""
    )

    # Config file with credentials
    (www_dir / "config.php").write_text(
        """<?php
    $db_password = "secret123";
    $api_key = "AKIA1234567890ABCDEF";
    ?>"""
    )

    return www_dir


# Markers for test categories
def pytest_configure(config):
    """Configure custom pytest markers."""
    config.addinivalue_line(
        "markers", "slow: marks tests as slow (deselect with '-m \"not slow\"')"
    )
    config.addinivalue_line("markers", "integration: marks tests as integration tests")
    config.addinivalue_line("markers", "requires_qemu: marks tests requiring QEMU")
    config.addinivalue_line("markers", "requires_network: marks tests requiring network access")
