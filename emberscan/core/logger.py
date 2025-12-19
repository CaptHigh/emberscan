"""
Logging configuration for EmberScan.

Provides structured logging with colored console output
and optional file logging with rotation.
"""

import logging
import os
import sys
from datetime import datetime
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Optional


# ANSI color codes
class Colors:
    RESET = "\033[0m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    BOLD = "\033[1m"
    DIM = "\033[2m"


class ColoredFormatter(logging.Formatter):
    """Custom formatter with colors for console output."""

    LEVEL_COLORS = {
        logging.DEBUG: Colors.DIM + Colors.CYAN,
        logging.INFO: Colors.GREEN,
        logging.WARNING: Colors.YELLOW,
        logging.ERROR: Colors.RED,
        logging.CRITICAL: Colors.BOLD + Colors.RED,
    }

    def __init__(self, fmt: str = None, datefmt: str = None, use_colors: bool = True):
        super().__init__(fmt, datefmt)
        self.use_colors = use_colors and sys.stdout.isatty()

    def format(self, record: logging.LogRecord) -> str:
        if self.use_colors:
            color = self.LEVEL_COLORS.get(record.levelno, Colors.WHITE)
            record.levelname = f"{color}{record.levelname}{Colors.RESET}"
            record.name = f"{Colors.CYAN}{record.name}{Colors.RESET}"

            # Colorize specific keywords in message
            if hasattr(record, "msg") and isinstance(record.msg, str):
                msg = record.msg
                keywords = {
                    "PASS": Colors.GREEN,
                    "FAIL": Colors.RED,
                    "VULN": Colors.RED + Colors.BOLD,
                    "CRITICAL": Colors.RED + Colors.BOLD,
                    "HIGH": Colors.RED,
                    "MEDIUM": Colors.YELLOW,
                    "LOW": Colors.BLUE,
                    "INFO": Colors.CYAN,
                }
                for keyword, kcolor in keywords.items():
                    if keyword in msg:
                        msg = msg.replace(keyword, f"{kcolor}{keyword}{Colors.RESET}")
                record.msg = msg

        return super().format(record)


class ScanLogAdapter(logging.LoggerAdapter):
    """Logger adapter that adds scan context to log messages."""

    def process(self, msg, kwargs):
        scan_id = self.extra.get("scan_id", "N/A")
        target = self.extra.get("target", "unknown")
        return f"[{scan_id}] [{target}] {msg}", kwargs


def setup_logging(
    level: str = "INFO",
    log_file: Optional[str] = None,
    log_dir: str = "./logs",
    max_bytes: int = 10 * 1024 * 1024,  # 10MB
    backup_count: int = 5,
    use_colors: bool = True,
) -> logging.Logger:
    """
    Configure logging for EmberScan.

    Args:
        level: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: Optional log file path
        log_dir: Directory for log files
        max_bytes: Max size per log file before rotation
        backup_count: Number of backup files to keep
        use_colors: Enable colored console output

    Returns:
        Configured root logger
    """
    # Create logger
    logger = logging.getLogger("emberscan")
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))

    # Remove existing handlers
    logger.handlers.clear()

    # Console handler with colors
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.DEBUG)
    console_format = "%(asctime)s │ %(levelname)-8s │ %(name)s │ %(message)s"
    console_handler.setFormatter(ColoredFormatter(console_format, use_colors=use_colors))
    logger.addHandler(console_handler)

    # File handler (if specified)
    if log_file:
        log_path = Path(log_file)
    else:
        # Auto-generate log file
        Path(log_dir).mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        log_path = Path(log_dir) / f"emberscan_{timestamp}.log"

    file_handler = RotatingFileHandler(log_path, maxBytes=max_bytes, backupCount=backup_count)
    file_handler.setLevel(logging.DEBUG)
    file_format = "%(asctime)s | %(levelname)-8s | %(name)s | %(funcName)s:%(lineno)d | %(message)s"
    file_handler.setFormatter(logging.Formatter(file_format))
    logger.addHandler(file_handler)

    logger.info(f"Logging initialized - Level: {level}, File: {log_path}")

    return logger


def get_logger(name: str = None) -> logging.Logger:
    """Get a logger instance for a module."""
    if name:
        return logging.getLogger(f"emberscan.{name}")
    return logging.getLogger("emberscan")


def get_scan_logger(scan_id: str, target: str) -> ScanLogAdapter:
    """Get a logger adapter for a specific scan."""
    logger = get_logger("scan")
    return ScanLogAdapter(logger, {"scan_id": scan_id, "target": target})


# Progress indicator for long-running operations
class ProgressLogger:
    """Context manager for logging progress of long operations."""

    def __init__(self, logger: logging.Logger, operation: str, total: int = None):
        self.logger = logger
        self.operation = operation
        self.total = total
        self.current = 0
        self.start_time = None

    def __enter__(self):
        self.start_time = datetime.now()
        self.logger.info(f"Starting: {self.operation}")
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        elapsed = datetime.now() - self.start_time
        if exc_type:
            self.logger.error(f"Failed: {self.operation} after {elapsed}")
        else:
            self.logger.info(f"Completed: {self.operation} in {elapsed}")
        return False

    def update(self, current: int = None, message: str = None):
        """Update progress."""
        if current is not None:
            self.current = current
        else:
            self.current += 1

        if self.total:
            pct = (self.current / self.total) * 100
            progress_msg = f"{self.operation}: {self.current}/{self.total} ({pct:.1f}%)"
        else:
            progress_msg = f"{self.operation}: {self.current} items processed"

        if message:
            progress_msg += f" - {message}"

        self.logger.debug(progress_msg)
