"""
Emulation modules for firmware analysis.

Provides QEMU-based emulation for various architectures including
MIPS, ARM, and x86. Includes specialized support for router firmware
like DVRF (Damn Vulnerable Router Firmware).
"""

from .dvrf_emulator import DVRFEmulator, detect_dvrf_firmware, get_dvrf_pwnable_binaries
from .qemu_manager import QEMUManager

__all__ = [
    "QEMUManager",
    "DVRFEmulator",
    "detect_dvrf_firmware",
    "get_dvrf_pwnable_binaries",
]
