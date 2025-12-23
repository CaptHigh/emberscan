"""
Emulation modules for firmware analysis.

Provides QEMU-based emulation for various architectures including
MIPS, ARM, and x86. Includes specialized support for router firmware
with NVRAM emulation and hardware script patching.
"""

from .qemu_manager import QEMUManager
from .router_emulator import RouterEmulator, detect_router_firmware

__all__ = [
    "QEMUManager",
    "RouterEmulator",
    "detect_router_firmware",
]
