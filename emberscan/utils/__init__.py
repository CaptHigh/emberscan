"""
Utility functions for EmberScan.
"""

import hashlib
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple


def check_dependencies() -> Dict[str, bool]:
    """Check if required external tools are installed."""
    tools = {
        "binwalk": "Firmware extraction",
        "unsquashfs": "SquashFS extraction",
        "sasquatch": "Non-standard SquashFS",
        "jefferson": "JFFS2 extraction",
        "qemu-system-mipsel": "MIPS emulation",
        "qemu-system-mips": "MIPS BE emulation",
        "qemu-system-arm": "ARM emulation",
        "qemu-system-aarch64": "ARM64 emulation",
        "nmap": "Network scanning",
        "nikto": "Web scanning",
        "flashrom": "SPI flash reading",
        "strings": "Binary analysis",
        "readelf": "ELF analysis",
        "gdb-multiarch": "Debugging",
    }

    results = {}
    for tool, description in tools.items():
        results[tool] = {
            "installed": shutil.which(tool) is not None,
            "description": description,
        }

    return results


def print_dependency_status():
    """Print dependency status in a formatted way."""
    deps = check_dependencies()

    print("\n=== EmberScan Dependency Check ===\n")

    for tool, info in deps.items():
        status = "✓" if info["installed"] else "✗"
        color = "\033[92m" if info["installed"] else "\033[91m"
        reset = "\033[0m"
        print(f"  {color}{status}{reset} {tool:20} - {info['description']}")

    installed = sum(1 for t in deps.values() if t["installed"])
    total = len(deps)
    print(f"\n  {installed}/{total} tools installed\n")


def calculate_file_hashes(filepath: str) -> Dict[str, str]:
    """Calculate multiple hashes for a file."""
    hashes = {
        "md5": hashlib.md5(usedforsecurity=False),
        "sha1": hashlib.sha1(usedforsecurity=False),
        "sha256": hashlib.sha256(),
    }

    with open(filepath, "rb") as f:
        while chunk := f.read(8192):
            for h in hashes.values():
                h.update(chunk)

    return {name: h.hexdigest() for name, h in hashes.items()}


def get_file_entropy(filepath: str, block_size: int = 1024) -> float:
    """Calculate Shannon entropy of a file."""
    import math

    with open(filepath, "rb") as f:
        data = f.read()

    if not data:
        return 0.0

    freq = {}
    for byte in data:
        freq[byte] = freq.get(byte, 0) + 1

    entropy = 0.0
    for count in freq.values():
        p = count / len(data)
        if p > 0:
            entropy -= p * math.log2(p)

    return entropy


def format_size(size_bytes: int) -> str:
    """Format byte size to human readable string."""
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if size_bytes < 1024:
            return f"{size_bytes:.2f} {unit}"
        size_bytes /= 1024
    return f"{size_bytes:.2f} PB"


def run_command(cmd: List[str], timeout: int = 60, capture: bool = True) -> Tuple[int, str, str]:
    """Run external command with timeout."""
    try:
        result = subprocess.run(cmd, capture_output=capture, text=True, timeout=timeout)
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "Command timed out"
    except FileNotFoundError:
        return -1, "", f"Command not found: {cmd[0]}"
    except Exception as e:
        return -1, "", str(e)


def find_files_by_pattern(root_dir: str, patterns: List[str], max_depth: int = 10) -> List[Path]:
    """Find files matching patterns in directory."""
    results = []
    root = Path(root_dir)

    for pattern in patterns:
        results.extend(root.rglob(pattern))

    return results


def is_elf_binary(filepath: str) -> bool:
    """Check if file is an ELF binary."""
    try:
        with open(filepath, "rb") as f:
            magic = f.read(4)
            return magic == b"\x7fELF"
    except:
        return False


def get_elf_architecture(filepath: str) -> Optional[str]:
    """Get architecture from ELF binary."""
    try:
        with open(filepath, "rb") as f:
            magic = f.read(4)
            if magic != b"\x7fELF":
                return None

            f.seek(18)
            machine = int.from_bytes(f.read(2), "little")

            arch_map = {
                0x03: "x86",
                0x08: "mips",
                0x14: "ppc",
                0x28: "arm",
                0x3E: "x86_64",
                0xB7: "aarch64",
            }

            return arch_map.get(machine, "unknown")
    except:
        return None


def safe_extract_path(base_dir: str, file_path: str) -> Optional[str]:
    """Safely join paths to prevent directory traversal attacks."""
    base = Path(base_dir).resolve()
    target = (base / file_path).resolve()

    if base in target.parents or base == target:
        return str(target)
    return None


def create_workspace(base_dir: str) -> Dict[str, Path]:
    """Create standard workspace directory structure."""
    base = Path(base_dir)

    dirs = {
        "firmware": base / "firmware",
        "extracted": base / "extracted",
        "emulation": base / "emulation",
        "reports": base / "reports",
        "logs": base / "logs",
        "temp": base / "temp",
        "kernels": base / "kernels",
    }

    for dir_path in dirs.values():
        dir_path.mkdir(parents=True, exist_ok=True)

    return dirs


class ProgressBar:
    """Simple progress bar for CLI."""

    def __init__(self, total: int, prefix: str = "", width: int = 50):
        self.total = total
        self.prefix = prefix
        self.width = width
        self.current = 0

    def update(self, current: int = None):
        if current is not None:
            self.current = current
        else:
            self.current += 1

        progress = self.current / self.total if self.total > 0 else 0
        filled = int(self.width * progress)
        bar = "█" * filled + "░" * (self.width - filled)
        percent = progress * 100

        sys.stdout.write(f"\r{self.prefix} |{bar}| {percent:.1f}%")
        sys.stdout.flush()

        if self.current >= self.total:
            print()

    def finish(self):
        self.update(self.total)
