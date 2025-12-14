"""
Custom exceptions for EmberScan.

Defines a hierarchy of exceptions for different error conditions
encountered during firmware analysis and scanning.
"""


class EmberScanError(Exception):
    """Base exception for all EmberScan errors."""
    
    def __init__(self, message: str, details: dict = None):
        super().__init__(message)
        self.message = message
        self.details = details or {}
    
    def __str__(self):
        if self.details:
            details_str = ", ".join(f"{k}={v}" for k, v in self.details.items())
            return f"{self.message} ({details_str})"
        return self.message


# ============================================================================
# Extraction Errors
# ============================================================================

class ExtractionError(EmberScanError):
    """Base class for firmware extraction errors."""
    pass


class SPIExtractionError(ExtractionError):
    """Error during SPI flash extraction."""
    pass


class UnsupportedFirmwareError(ExtractionError):
    """Firmware format is not supported."""
    pass


class EncryptedFirmwareError(ExtractionError):
    """Firmware is encrypted and cannot be processed."""
    pass


class CorruptedFirmwareError(ExtractionError):
    """Firmware image is corrupted or incomplete."""
    pass


class FilesystemExtractionError(ExtractionError):
    """Failed to extract filesystem from firmware."""
    pass


# ============================================================================
# Emulation Errors
# ============================================================================

class EmulationError(EmberScanError):
    """Base class for emulation errors."""
    pass


class QEMUNotFoundError(EmulationError):
    """QEMU binary not found for the target architecture."""
    pass


class KernelNotFoundError(EmulationError):
    """Pre-built kernel not found for emulation."""
    pass


class EmulationTimeoutError(EmulationError):
    """Emulation timed out waiting for firmware to boot."""
    pass


class EmulationBootFailure(EmulationError):
    """Firmware failed to boot in emulated environment."""
    pass


class NetworkConfigurationError(EmulationError):
    """Failed to configure network for emulation."""
    pass


class UnsupportedArchitectureError(EmulationError):
    """Target architecture is not supported for emulation."""
    pass


# ============================================================================
# Scanner Errors
# ============================================================================

class ScannerError(EmberScanError):
    """Base class for scanner errors."""
    pass


class ScanTimeoutError(ScannerError):
    """Scan operation timed out."""
    pass


class TargetUnreachableError(ScannerError):
    """Scan target is not reachable."""
    pass


class ScannerNotFoundError(ScannerError):
    """External scanner tool not found."""
    pass


class ScannerConfigError(ScannerError):
    """Invalid scanner configuration."""
    pass


class CVEDatabaseError(ScannerError):
    """Error accessing CVE database."""
    pass


# ============================================================================
# Reporter Errors
# ============================================================================

class ReporterError(EmberScanError):
    """Base class for reporter errors."""
    pass


class ReportGenerationError(ReporterError):
    """Failed to generate report."""
    pass


class TemplateNotFoundError(ReporterError):
    """Report template not found."""
    pass


# ============================================================================
# Configuration Errors
# ============================================================================

class ConfigurationError(EmberScanError):
    """Base class for configuration errors."""
    pass


class InvalidConfigError(ConfigurationError):
    """Configuration file is invalid."""
    pass


class MissingDependencyError(ConfigurationError):
    """Required dependency is missing."""
    pass


# ============================================================================
# Plugin Errors
# ============================================================================

class PluginError(EmberScanError):
    """Base class for plugin errors."""
    pass


class PluginLoadError(PluginError):
    """Failed to load plugin."""
    pass


class PluginExecutionError(PluginError):
    """Plugin execution failed."""
    pass


# ============================================================================
# Helper Functions
# ============================================================================

def format_exception_chain(exc: Exception) -> str:
    """Format exception chain for logging."""
    chain = []
    current = exc
    while current:
        if isinstance(current, EmberScanError):
            chain.append(f"{type(current).__name__}: {current}")
        else:
            chain.append(f"{type(current).__name__}: {str(current)}")
        current = current.__cause__
    return " -> ".join(chain)
