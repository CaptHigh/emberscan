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


class SPIExtractionError(ExtractionError):
    """Error during SPI flash extraction."""


class UnsupportedFirmwareError(ExtractionError):
    """Firmware format is not supported."""


class EncryptedFirmwareError(ExtractionError):
    """Firmware is encrypted and cannot be processed."""


class CorruptedFirmwareError(ExtractionError):
    """Firmware image is corrupted or incomplete."""


class FilesystemExtractionError(ExtractionError):
    """Failed to extract filesystem from firmware."""


# ============================================================================
# Emulation Errors
# ============================================================================


class EmulationError(EmberScanError):
    """Base class for emulation errors."""


class QEMUNotFoundError(EmulationError):
    """QEMU binary not found for the target architecture."""


class KernelNotFoundError(EmulationError):
    """Pre-built kernel not found for emulation."""


class EmulationTimeoutError(EmulationError):
    """Emulation timed out waiting for firmware to boot."""


class EmulationBootFailure(EmulationError):
    """Firmware failed to boot in emulated environment."""


class NetworkConfigurationError(EmulationError):
    """Failed to configure network for emulation."""


class UnsupportedArchitectureError(EmulationError):
    """Target architecture is not supported for emulation."""


# ============================================================================
# Scanner Errors
# ============================================================================


class ScannerError(EmberScanError):
    """Base class for scanner errors."""


class ScanTimeoutError(ScannerError):
    """Scan operation timed out."""


class TargetUnreachableError(ScannerError):
    """Scan target is not reachable."""


class ScannerNotFoundError(ScannerError):
    """External scanner tool not found."""


class ScannerConfigError(ScannerError):
    """Invalid scanner configuration."""


class CVEDatabaseError(ScannerError):
    """Error accessing CVE database."""


# ============================================================================
# Reporter Errors
# ============================================================================


class ReporterError(EmberScanError):
    """Base class for reporter errors."""


class ReportGenerationError(ReporterError):
    """Failed to generate report."""


class TemplateNotFoundError(ReporterError):
    """Report template not found."""


# ============================================================================
# Configuration Errors
# ============================================================================


class ConfigurationError(EmberScanError):
    """Base class for configuration errors."""


class InvalidConfigError(ConfigurationError):
    """Configuration file is invalid."""


class MissingDependencyError(ConfigurationError):
    """Required dependency is missing."""


# ============================================================================
# Plugin Errors
# ============================================================================


class PluginError(EmberScanError):
    """Base class for plugin errors."""


class PluginLoadError(PluginError):
    """Failed to load plugin."""


class PluginExecutionError(PluginError):
    """Plugin execution failed."""


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
