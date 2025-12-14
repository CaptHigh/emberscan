"""
Base scanner classes and scanner registry.

All vulnerability scanners inherit from BaseScanner and implement
the scan() method.
"""

import abc
from datetime import datetime
from typing import List, Optional, Dict, Any

from ..core.config import Config
from ..core.logger import get_logger
from ..core.models import (
    FirmwareInfo, ScanResult, ScanStatus, Vulnerability, Severity
)

logger = get_logger(__name__)


class BaseScanner(abc.ABC):
    """
    Abstract base class for all vulnerability scanners.
    
    Subclasses must implement:
    - scan(): Main scanning method
    - name: Scanner name property
    """
    
    def __init__(self, config: Config):
        self.config = config
        self._scan_count = 0
    
    @property
    @abc.abstractmethod
    def name(self) -> str:
        """Scanner name identifier."""
        pass
    
    @property
    def scan_type(self) -> str:
        """Type of scan (web, network, binary, etc.)."""
        return "generic"
    
    @abc.abstractmethod
    def scan(self, target: Any, firmware: FirmwareInfo, **kwargs) -> ScanResult:
        """
        Execute scan against target.
        
        Args:
            target: Target to scan (URL, IP, path, etc.)
            firmware: FirmwareInfo context
            **kwargs: Scanner-specific options
        
        Returns:
            ScanResult with findings
        """
        pass
    
    def _create_result(self) -> ScanResult:
        """Create a new ScanResult for this scanner."""
        return ScanResult(
            scanner_name=self.name,
            scan_type=self.scan_type,
            status=ScanStatus.PENDING,
        )
    
    def _create_vulnerability(
        self,
        title: str,
        description: str,
        severity: Severity = Severity.INFO,
        **kwargs
    ) -> Vulnerability:
        """Create a Vulnerability instance with scanner context."""
        return Vulnerability(
            title=title,
            description=description,
            severity=severity,
            scanner_name=self.name,
            **kwargs
        )
    
    def _start_scan(self, result: ScanResult):
        """Mark scan as started."""
        result.status = ScanStatus.RUNNING
        result.started_at = datetime.now()
        logger.info(f"[{self.name}] Scan started")
    
    def _complete_scan(self, result: ScanResult):
        """Mark scan as completed."""
        result.status = ScanStatus.COMPLETED
        result.completed_at = datetime.now()
        duration = result.duration or 0
        logger.info(
            f"[{self.name}] Scan completed in {duration:.1f}s - "
            f"{len(result.vulnerabilities)} findings"
        )
    
    def _fail_scan(self, result: ScanResult, error: str):
        """Mark scan as failed."""
        result.status = ScanStatus.FAILED
        result.completed_at = datetime.now()
        result.error_message = error
        logger.error(f"[{self.name}] Scan failed: {error}")


class ScannerRegistry:
    """Registry for managing available scanners."""
    
    _scanners: Dict[str, type] = {}
    
    @classmethod
    def register(cls, name: str):
        """Decorator to register a scanner class."""
        def decorator(scanner_class):
            cls._scanners[name] = scanner_class
            return scanner_class
        return decorator
    
    @classmethod
    def get(cls, name: str) -> Optional[type]:
        """Get scanner class by name."""
        return cls._scanners.get(name)
    
    @classmethod
    def list_scanners(cls) -> List[str]:
        """List all registered scanner names."""
        return list(cls._scanners.keys())
    
    @classmethod
    def create_scanner(cls, name: str, config: Config) -> Optional[BaseScanner]:
        """Create scanner instance by name."""
        scanner_class = cls.get(name)
        if scanner_class:
            return scanner_class(config)
        return None
