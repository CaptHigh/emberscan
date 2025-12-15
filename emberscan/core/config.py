"""
Configuration management for EmberScan.

Handles loading, validation, and access to configuration settings
from YAML files and environment variables.
"""

import os
import tempfile
import yaml
import logging
from pathlib import Path
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any

logger = logging.getLogger(__name__)


@dataclass
class QEMUConfig:
    """QEMU emulation configuration."""

    timeout: int = 300
    memory: int = 256
    enable_network: bool = True
    network_mode: str = "user"  # user, tap, bridge
    kernel_dir: str = "./kernels"
    snapshot: bool = True
    debug_port: int = 1234
    http_forward_port: int = 8080
    ssh_forward_port: int = 2222
    telnet_forward_port: int = 2323


@dataclass
class ScannerConfig:
    """Scanner configuration."""

    enabled_scanners: List[str] = field(
        default_factory=lambda: ["web", "network", "binary", "cve", "credentials", "crypto"]
    )
    parallel_scans: int = 4
    timeout_per_scan: int = 600
    max_depth: int = 5
    follow_redirects: bool = True
    user_agent: str = "EmberScan/1.0"


@dataclass
class ExtractorConfig:
    """Firmware extractor configuration."""

    auto_detect: bool = True
    max_extraction_depth: int = 5
    supported_formats: List[str] = field(
        default_factory=lambda: ["squashfs", "cramfs", "jffs2", "ubifs", "romfs", "ext2", "ext4"]
    )
    temp_dir: str = field(default_factory=lambda: os.path.join(tempfile.gettempdir(), "emberscan"))


@dataclass
class ReporterConfig:
    """Report generation configuration."""

    output_formats: List[str] = field(default_factory=lambda: ["html", "json", "pdf"])
    output_dir: str = "./reports"
    include_evidence: bool = True
    severity_threshold: str = "low"  # low, medium, high, critical


@dataclass
class Config:
    """Main configuration container."""

    # General settings
    project_name: str = "EmberScan"
    workspace_dir: str = "./workspace"
    log_level: str = "INFO"
    log_file: Optional[str] = None

    # Sub-configurations
    qemu: QEMUConfig = field(default_factory=QEMUConfig)
    scanner: ScannerConfig = field(default_factory=ScannerConfig)
    extractor: ExtractorConfig = field(default_factory=ExtractorConfig)
    reporter: ReporterConfig = field(default_factory=ReporterConfig)

    # Plugin settings
    plugins_dir: str = "./plugins"
    enabled_plugins: List[str] = field(default_factory=list)

    # CVE database
    cve_database: str = "./data/cve_database.json"
    nvd_api_key: Optional[str] = None

    @classmethod
    def load(cls, config_path: Optional[str] = None) -> "Config":
        """Load configuration from YAML file and environment variables."""
        config_data = {}

        # Default config paths
        default_paths = [
            Path("./emberscan.yaml"),
            Path("./config/emberscan.yaml"),
            Path.home() / ".emberscan" / "config.yaml",
            Path("/etc/emberscan/config.yaml"),
        ]

        # Find config file
        if config_path:
            config_file = Path(config_path)
        else:
            config_file = None
            for path in default_paths:
                if path.exists():
                    config_file = path
                    break

        # Load from file
        if config_file and config_file.exists():
            logger.info(f"Loading configuration from {config_file}")
            with open(config_file, "r") as f:
                config_data = yaml.safe_load(f) or {}

        # Override with environment variables
        config_data = cls._apply_env_overrides(config_data)

        # Build configuration object
        return cls._from_dict(config_data)

    @classmethod
    def _apply_env_overrides(cls, config_data: Dict) -> Dict:
        """Apply environment variable overrides."""
        env_mappings = {
            "EMBERSCAN_WORKSPACE": ("workspace_dir",),
            "EMBERSCAN_LOG_LEVEL": ("log_level",),
            "EMBERSCAN_QEMU_TIMEOUT": ("qemu", "timeout"),
            "EMBERSCAN_QEMU_MEMORY": ("qemu", "memory"),
            "EMBERSCAN_NVD_API_KEY": ("nvd_api_key",),
            "EMBERSCAN_PLUGINS_DIR": ("plugins_dir",),
        }

        for env_var, path in env_mappings.items():
            value = os.environ.get(env_var)
            if value is not None:
                cls._set_nested(config_data, path, value)

        return config_data

    @staticmethod
    def _set_nested(data: Dict, path: tuple, value: Any):
        """Set a nested dictionary value."""
        for key in path[:-1]:
            data = data.setdefault(key, {})

        # Type conversion
        if isinstance(value, str):
            if value.isdigit():
                value = int(value)
            elif value.lower() in ("true", "false"):
                value = value.lower() == "true"

        data[path[-1]] = value

    @classmethod
    def _from_dict(cls, data: Dict) -> "Config":
        """Create Config instance from dictionary."""
        qemu_data = data.pop("qemu", {})
        scanner_data = data.pop("scanner", {})
        extractor_data = data.pop("extractor", {})
        reporter_data = data.pop("reporter", {})

        return cls(
            qemu=QEMUConfig(**qemu_data) if qemu_data else QEMUConfig(),
            scanner=ScannerConfig(**scanner_data) if scanner_data else ScannerConfig(),
            extractor=ExtractorConfig(**extractor_data) if extractor_data else ExtractorConfig(),
            reporter=ReporterConfig(**reporter_data) if reporter_data else ReporterConfig(),
            **{k: v for k, v in data.items() if k in cls.__dataclass_fields__},
        )

    def save(self, path: str):
        """Save configuration to YAML file."""
        import dataclasses

        def to_dict(obj):
            if dataclasses.is_dataclass(obj):
                return {k: to_dict(v) for k, v in dataclasses.asdict(obj).items()}
            return obj

        with open(path, "w") as f:
            yaml.dump(to_dict(self), f, default_flow_style=False)

        logger.info(f"Configuration saved to {path}")

    def validate(self) -> List[str]:
        """Validate configuration and return list of errors."""
        errors = []

        # Check workspace directory
        workspace = Path(self.workspace_dir)
        if not workspace.exists():
            try:
                workspace.mkdir(parents=True, exist_ok=True)
            except PermissionError:
                errors.append(f"Cannot create workspace directory: {self.workspace_dir}")

        # Check kernel directory
        kernel_dir = Path(self.qemu.kernel_dir)
        if not kernel_dir.exists():
            errors.append(f"Kernel directory not found: {self.qemu.kernel_dir}")

        # Validate log level
        valid_levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
        if self.log_level.upper() not in valid_levels:
            errors.append(f"Invalid log level: {self.log_level}")

        # Validate scanner settings
        if self.scanner.parallel_scans < 1:
            errors.append("parallel_scans must be >= 1")

        return errors
