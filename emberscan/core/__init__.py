"""
Core modules for EmberScan.
"""

from .config import Config
from .logger import get_logger, setup_logging
from .scanner import EmberScanner
from .models import (
    FirmwareInfo,
    Vulnerability,
    ScanResult,
    ScanSession,
    EmulationState,
    Architecture,
    Severity,
    VulnerabilityType,
    ScanStatus,
)
from .exceptions import (
    EmberScanError,
    ExtractionError,
    EmulationError,
    ScannerError,
)

__all__ = [
    'Config',
    'get_logger',
    'setup_logging',
    'EmberScanner',
    'FirmwareInfo',
    'Vulnerability',
    'ScanResult',
    'ScanSession',
    'EmulationState',
    'Architecture',
    'Severity',
    'VulnerabilityType',
    'ScanStatus',
    'EmberScanError',
    'ExtractionError',
    'EmulationError',
    'ScannerError',
]
