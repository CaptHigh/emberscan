"""
Utility functions for EmberScan.
"""

import hashlib
import importlib.util
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# Python packages for the dynamic emulation subsystem.
# import-name -> (pip requirement, description)
PYTHON_DEPS: Dict[str, Tuple[str, str]] = {
    "unicorn": ("unicorn>=2.0.0", "CPU emulator (dynamic analysis)"),
    "capstone": ("capstone>=5.0.0", "Disassembler"),
    "keystone": ("keystone-engine>=0.9.2", "Assembler (verification harness)"),
    "qiling": ("qiling>=1.4.6", "Linux user-space emulation framework"),
}


def check_python_deps() -> Dict[str, Dict]:
    """Check importability of the emulation Python packages."""
    results = {}
    for import_name, (req, desc) in PYTHON_DEPS.items():
        try:
            installed = importlib.util.find_spec(import_name) is not None
        except Exception:
            installed = False
        results[import_name] = {"installed": installed, "pip": req, "description": desc}
    return results


def pip_install(packages: List[str], upgrade_pip: bool = False) -> int:
    """Install packages into the current interpreter via pip. Returns exit code."""
    if upgrade_pip:
        subprocess.call([sys.executable, "-m", "pip", "install", "--upgrade", "pip"])
    cmd = [sys.executable, "-m", "pip", "install", "--upgrade"] + packages
    print(f"Running: {' '.join(cmd)}")
    return subprocess.call(cmd)


def install_python_deps(upgrade_pip: bool = True) -> int:
    """Install the emulation Python packages (unicorn/capstone/keystone/qiling)."""
    reqs = [req for (req, _) in PYTHON_DEPS.values()]
    return pip_install(reqs, upgrade_pip=upgrade_pip)


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


# Core Python libraries that ship with the base install.
# import-name -> description
CORE_PYTHON_DEPS: Dict[str, str] = {
    "rich": "Console UI / tables",
    "requests": "HTTP client (web scanner)",
    "bs4": "HTML parsing (web scanner)",
    "yaml": "Config parsing",
    "jinja2": "HTML report templating",
    "Crypto": "Crypto analysis (pycryptodome)",
}


def check_core_python_deps() -> Dict[str, Dict]:
    """Check importability of the core (non-emulation) Python packages."""
    results = {}
    for import_name, desc in CORE_PYTHON_DEPS.items():
        try:
            installed = importlib.util.find_spec(import_name) is not None
        except Exception:
            installed = False
        results[import_name] = {"installed": installed, "description": desc}
    return results


def print_dependency_status():
    """Print dependency status using the shared rich UI (plain fallback)."""
    try:
        from ..core.ui import ui
    except Exception:
        ui = None

    deps = check_dependencies()
    core = check_core_python_deps()
    py = check_python_deps()

    def _table(title, items, name_key=lambda k: k):
        rows = []
        for key, info in items.items():
            mark = "[green]✓[/green]" if info["installed"] else "[red]✗[/red]"
            rows.append((mark, name_key(key), info["description"]))
        if ui is not None and ui.rich:
            from rich import box
            from rich.table import Table

            t = Table(
                title=title,
                title_justify="left",
                box=box.SIMPLE,
                show_edge=False,
                header_style="bold",
            )
            t.add_column("", no_wrap=True)
            t.add_column("Component", no_wrap=True)
            t.add_column("Purpose", style="dim")
            for mark, name, desc in rows:
                t.add_row(mark, name, desc)
            ui._console.print(t)
        else:
            print(f"\n{title}")
            for mark, name, desc in rows:
                flag = "OK " if "green" in mark else "-- "
                print(f"  [{flag}] {name:22} - {desc}")

    if ui is not None:
        ui.rule("Dependency Check")
    else:
        print("\n=== EmberScan Dependency Check ===")

    _table("Core Python libraries", core)
    _table("Python emulation libraries (analyze / dynamic)", py)
    _table("External tools", deps)

    ext_ok = sum(1 for t in deps.values() if t["installed"])
    py_ok = sum(1 for t in py.values() if t["installed"])
    core_ok = sum(1 for t in core.values() if t["installed"])

    def _line(msg):
        (ui.info if ui is not None else print)(msg)

    _line("")
    _line(
        f"Core libs: {core_ok}/{len(core)}   "
        f"Emulation libs: {py_ok}/{len(py)}   "
        f"External tools: {ext_ok}/{len(deps)}"
    )

    if py_ok < len(py):
        if ui is not None:
            ui.warn(
                "Emulation libraries missing — install with: "
                "emberscan install-deps  (or)  python scripts/install.py"
            )
        else:
            print("\n  Install emulation libs:  emberscan install-deps")
    if core_ok < len(core):
        if ui is not None:
            ui.warn("Core libraries missing — reinstall with: pip install -e .")
        else:
            print("\n  Reinstall core libs:  pip install -e .")
    print()


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
    except Exception:
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
    except Exception:
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
