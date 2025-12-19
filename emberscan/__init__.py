"""
EmberScan - Automated Embedded Hardware Firmware Security Scanner

A comprehensive security testing framework for embedded devices including
routers, switches, IP cameras, SBCs, and other IoT/embedded hardware.

Features:
- SPI flash firmware extraction
- Multi-architecture QEMU emulation (MIPS, ARM, x86, PowerPC)
- Automated vulnerability scanning
- CVE correlation and reporting
- Extensible plugin architecture

Author: EmberScan Team
License: MIT
"""

__version__ = "1.0.0"
__author__ = "EmberScan Team"
__license__ = "MIT"

from emberscan.core.config import Config
from emberscan.core.logger import get_logger
from emberscan.core.scanner import EmberScanner

__all__ = [
    "Config",
    "EmberScanner",
    "get_logger",
    "__version__",
]
