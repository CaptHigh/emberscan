"""
QEMU Emulation Manager.

Manages QEMU virtual machines for firmware emulation across
multiple architectures (MIPS, ARM, x86, PowerPC).
"""

import os
import time
import signal
import socket
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass

from ..core.config import Config
from ..core.logger import get_logger
from ..core.models import FirmwareInfo, EmulationState, Architecture, Endianness
from ..core.exceptions import (
    EmulationError,
    QEMUNotFoundError,
    KernelNotFoundError,
    EmulationTimeoutError,
    EmulationBootFailure,
    NetworkConfigurationError,
    UnsupportedArchitectureError,
)

logger = get_logger(__name__)


@dataclass
class QEMUProfile:
    """QEMU configuration profile for a specific architecture."""

    binary: str
    machine: str
    cpu: str
    kernel_name: str
    console: str
    nic_model: str = "e1000"
    extra_args: List[str] = None


class QEMUManager:
    """
    Manage QEMU emulation instances for firmware analysis.

    Features:
    - Multi-architecture support (MIPS, ARM, x86, PowerPC)
    - Automatic kernel selection
    - Network configuration (user mode / TAP)
    - Boot detection and health checking
    - Snapshot support for quick reset
    """

    # Architecture profiles
    PROFILES = {
        Architecture.MIPS_LE: QEMUProfile(
            binary="qemu-system-mipsel",
            machine="malta",
            cpu="MIPS32R2-generic",
            kernel_name="vmlinux.mipsel",
            console="ttyS0",
        ),
        Architecture.MIPS_BE: QEMUProfile(
            binary="qemu-system-mips",
            machine="malta",
            cpu="MIPS32R2-generic",
            kernel_name="vmlinux.mipseb",
            console="ttyS0",
        ),
        Architecture.ARM: QEMUProfile(
            binary="qemu-system-arm",
            machine="virt",
            cpu="cortex-a15",
            kernel_name="zImage.armel",
            console="ttyAMA0",
            nic_model="virtio-net-device",
        ),
        Architecture.ARM64: QEMUProfile(
            binary="qemu-system-aarch64",
            machine="virt",
            cpu="cortex-a53",
            kernel_name="Image.aarch64",
            console="ttyAMA0",
            nic_model="virtio-net-device",
        ),
        Architecture.X86: QEMUProfile(
            binary="qemu-system-i386",
            machine="pc",
            cpu="qemu32",
            kernel_name="bzImage.x86",
            console="ttyS0",
        ),
        Architecture.X86_64: QEMUProfile(
            binary="qemu-system-x86_64",
            machine="pc",
            cpu="qemu64",
            kernel_name="bzImage.x86_64",
            console="ttyS0",
        ),
    }

    def __init__(self, config: Config):
        self.config = config
        self.kernel_dir = Path(config.qemu.kernel_dir)
        self.work_dir = Path(config.workspace_dir) / "emulation"
        self.work_dir.mkdir(parents=True, exist_ok=True)

        # Active emulation instances
        self._instances: Dict[str, subprocess.Popen] = {}

    def start(
        self,
        firmware: FirmwareInfo,
        http_port: int = 8080,
        ssh_port: int = 2222,
        telnet_port: int = 2323,
        debug_port: int = 1234,
        enable_debug: bool = False,
    ) -> EmulationState:
        """
        Start QEMU emulation for firmware.

        Args:
            firmware: FirmwareInfo with extraction path
            http_port: Host port for HTTP forwarding
            ssh_port: Host port for SSH forwarding
            telnet_port: Host port for Telnet forwarding
            debug_port: GDB debug port
            enable_debug: Enable GDB server

        Returns:
            EmulationState with connection info
        """
        logger.info(f"Starting emulation for {firmware.name}")

        # Validate firmware
        if not firmware.rootfs_path or not Path(firmware.rootfs_path).exists():
            raise EmulationError("Firmware rootfs not found")

        # Get architecture profile
        profile = self.PROFILES.get(firmware.architecture)
        if not profile:
            raise UnsupportedArchitectureError(
                f"Architecture not supported: {firmware.architecture.value}"
            )

        # Check QEMU binary
        if not shutil.which(profile.binary):
            raise QEMUNotFoundError(f"QEMU binary not found: {profile.binary}")

        # Find kernel
        kernel_path = self._find_kernel(profile.kernel_name)
        if not kernel_path:
            raise KernelNotFoundError(f"Kernel not found: {profile.kernel_name}")

        # Create emulation state
        state = EmulationState(
            firmware_id=firmware.id,
            http_port=http_port,
            ssh_port=ssh_port,
            telnet_port=telnet_port,
            debug_port=debug_port,
        )

        # Prepare rootfs image
        rootfs_image = self._prepare_rootfs(firmware, state.id)

        # Build QEMU command
        qemu_cmd = self._build_qemu_command(
            profile=profile,
            kernel_path=kernel_path,
            rootfs_image=rootfs_image,
            state=state,
            enable_debug=enable_debug,
        )

        state.qemu_command = " ".join(qemu_cmd)
        logger.debug(f"QEMU command: {state.qemu_command}")

        # Start QEMU process
        try:
            process = subprocess.Popen(
                qemu_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.PIPE,
            )

            state.pid = process.pid
            state.running = True
            state.started_at = __import__("datetime").datetime.now()

            self._instances[state.id] = process

            logger.info(f"QEMU started with PID {state.pid}")

        except Exception as e:
            raise EmulationError(f"Failed to start QEMU: {e}")

        return state

    def stop(self, state: EmulationState):
        """Stop QEMU emulation instance."""
        logger.info(f"Stopping emulation: {state.id}")

        process = self._instances.get(state.id)
        if process:
            try:
                # Try graceful shutdown first
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    # Force kill
                    process.kill()
                    process.wait()
            except:
                pass

            del self._instances[state.id]

        state.running = False

        # Cleanup temporary files
        instance_dir = self.work_dir / state.id
        if instance_dir.exists():
            shutil.rmtree(instance_dir, ignore_errors=True)

    def wait_for_boot(
        self, state: EmulationState, timeout: int = 300, check_interval: int = 5
    ) -> bool:
        """
        Wait for firmware to boot and services to become available.

        Returns True if boot successful, False otherwise.
        """
        logger.info(f"Waiting for boot (timeout: {timeout}s)")

        start_time = time.time()

        while time.time() - start_time < timeout:
            # Check if QEMU is still running
            process = self._instances.get(state.id)
            if not process or process.poll() is not None:
                logger.error("QEMU process terminated unexpectedly")
                return False

            # Check HTTP port
            if self._check_port(state.ip_address, state.http_port):
                state.boot_successful = True
                state.boot_time = time.time() - start_time
                state.services_detected.append("http")
                logger.info(f"HTTP service detected after {state.boot_time:.1f}s")

                # Check other services
                if self._check_port(state.ip_address, state.ssh_port):
                    state.services_detected.append("ssh")
                if self._check_port(state.ip_address, state.telnet_port):
                    state.services_detected.append("telnet")

                return True

            time.sleep(check_interval)

        logger.warning(f"Boot timeout after {timeout}s")
        return False

    def get_console_output(self, state: EmulationState, lines: int = 100) -> str:
        """Get recent console output from QEMU."""
        process = self._instances.get(state.id)
        if not process:
            return ""

        try:
            # Read from stdout (non-blocking would be better)
            output = process.stdout.read(4096)
            if output:
                return output.decode("utf-8", errors="ignore")
        except:
            pass

        return ""

    def send_command(self, state: EmulationState, command: str) -> str:
        """Send command to QEMU console."""
        process = self._instances.get(state.id)
        if not process:
            raise EmulationError("Emulation not running")

        try:
            process.stdin.write(f"{command}\n".encode())
            process.stdin.flush()

            # Wait for response
            time.sleep(0.5)
            output = process.stdout.read(4096)
            return output.decode("utf-8", errors="ignore")
        except Exception as e:
            raise EmulationError(f"Failed to send command: {e}")

    def create_snapshot(self, state: EmulationState, name: str = "clean"):
        """Create QEMU snapshot for quick reset."""
        # This requires QEMU monitor access
        pass

    def restore_snapshot(self, state: EmulationState, name: str = "clean"):
        """Restore QEMU snapshot."""
        pass

    def _find_kernel(self, kernel_name: str) -> Optional[Path]:
        """Find kernel file in kernel directory."""
        kernel_path = self.kernel_dir / kernel_name
        if kernel_path.exists():
            return kernel_path

        # Check alternative locations
        alt_paths = [
            Path(f"./kernels/{kernel_name}"),
            Path(f"/usr/share/emberscan/kernels/{kernel_name}"),
            Path.home() / f".emberscan/kernels/{kernel_name}",
        ]

        for path in alt_paths:
            if path.exists():
                return path

        return None

    def _prepare_rootfs(self, firmware: FirmwareInfo, instance_id: str) -> Path:
        """Prepare rootfs image for QEMU."""
        instance_dir = self.work_dir / instance_id
        instance_dir.mkdir(exist_ok=True)

        rootfs_path = Path(firmware.rootfs_path)
        image_path = instance_dir / "rootfs.ext4"

        # Create ext4 image
        image_size = self._calculate_image_size(rootfs_path)

        logger.info(f"Creating rootfs image ({image_size}MB)")

        # Create empty image
        subprocess.run(
            ["dd", "if=/dev/zero", f"of={image_path}", "bs=1M", f"count={image_size}"],
            capture_output=True,
            check=True,
        )

        # Create filesystem
        subprocess.run(["mkfs.ext4", "-F", str(image_path)], capture_output=True, check=True)

        # Mount and copy files
        mount_point = instance_dir / "mnt"
        mount_point.mkdir(exist_ok=True)

        try:
            subprocess.run(
                ["sudo", "mount", "-o", "loop", str(image_path), str(mount_point)],
                check=True,
                capture_output=True,
            )

            subprocess.run(
                ["sudo", "cp", "-a", f"{rootfs_path}/.", str(mount_point)],
                check=True,
                capture_output=True,
            )

            # Apply emulation patches
            self._patch_rootfs_for_emulation(mount_point)

        finally:
            subprocess.run(["sudo", "umount", str(mount_point)], capture_output=True)

        return image_path

    def _calculate_image_size(self, rootfs_path: Path) -> int:
        """Calculate required image size in MB."""
        total_size = sum(f.stat().st_size for f in rootfs_path.rglob("*") if f.is_file())
        # Add 50% overhead for filesystem metadata
        size_mb = (total_size // (1024 * 1024)) + 1
        size_mb = int(size_mb * 1.5)
        # Minimum 64MB, maximum 512MB
        return max(64, min(512, size_mb))

    def _patch_rootfs_for_emulation(self, rootfs: Path):
        """Apply patches to rootfs for better emulation compatibility."""
        # Add serial console to inittab
        inittab = rootfs / "etc" / "inittab"
        if inittab.exists():
            with open(inittab, "a") as f:
                f.write("\n# EmberScan emulation\n")
                f.write("::respawn:/sbin/getty -L ttyS0 115200 vt100\n")

        # Disable hardware-specific scripts
        init_d = rootfs / "etc" / "init.d"
        if init_d.exists():
            hw_scripts = ["gpio", "led", "button", "switch", "watchdog"]
            for script in init_d.iterdir():
                if any(hw in script.name.lower() for hw in hw_scripts):
                    script.rename(script.with_suffix(".disabled"))

        # Create emulation marker
        marker = rootfs / "etc" / "emberscan_emulated"
        marker.write_text("EmberScan QEMU Emulation\n")

    def _build_qemu_command(
        self,
        profile: QEMUProfile,
        kernel_path: Path,
        rootfs_image: Path,
        state: EmulationState,
        enable_debug: bool,
    ) -> List[str]:
        """Build QEMU command line."""
        cmd = [
            profile.binary,
            "-M",
            profile.machine,
            "-m",
            str(self.config.qemu.memory),
            "-kernel",
            str(kernel_path),
            "-drive",
            f"file={rootfs_image},format=raw,if=virtio",
            "-append",
            f"root=/dev/vda console={profile.console} rw",
            "-nographic",
        ]

        # Add CPU if specified
        if profile.cpu:
            cmd.extend(["-cpu", profile.cpu])

        # Network configuration
        if self.config.qemu.network_mode == "user":
            # User mode networking with port forwarding
            hostfwds = [
                f"tcp::{state.http_port}-:80",
                f"tcp::{state.ssh_port}-:22",
                f"tcp::{state.telnet_port}-:23",
            ]
            netdev = f'user,id=net0,{",".join(f"hostfwd={h}" for h in hostfwds)}'
            cmd.extend(["-netdev", netdev, "-device", f"{profile.nic_model},netdev=net0"])

        # Debug server
        if enable_debug:
            cmd.extend(["-s", "-S"])  # GDB server on 1234, wait for connection

        # Snapshot mode (if supported)
        if self.config.qemu.snapshot:
            cmd.append("-snapshot")

        return cmd

    def _check_port(self, host: str, port: int, timeout: float = 2.0) -> bool:
        """Check if a port is open."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            return result == 0
        except:
            return False

    def list_available_kernels(self) -> List[Dict]:
        """List available emulation kernels."""
        kernels = []

        if self.kernel_dir.exists():
            for kernel_file in self.kernel_dir.iterdir():
                if kernel_file.is_file():
                    # Determine architecture from filename
                    name = kernel_file.name.lower()
                    arch = "unknown"

                    if "mipsel" in name or "mipsle" in name:
                        arch = "mipsel"
                    elif "mips" in name:
                        arch = "mips"
                    elif "arm64" in name or "aarch64" in name:
                        arch = "aarch64"
                    elif "arm" in name:
                        arch = "arm"
                    elif "x86_64" in name or "amd64" in name:
                        arch = "x86_64"
                    elif "x86" in name or "i386" in name:
                        arch = "x86"

                    kernels.append(
                        {
                            "name": kernel_file.name,
                            "path": str(kernel_file),
                            "architecture": arch,
                            "size": kernel_file.stat().st_size,
                        }
                    )

        return kernels

    def download_kernels(self, architectures: List[str] = None) -> Dict[str, bool]:
        """
        Download pre-built kernels from firmadyne project releases.

        Args:
            architectures: List of architectures to download (mipsel, mips, arm)

        Returns:
            Dictionary mapping architecture to download success status
        """
        import urllib.request

        # Use the correct release URLs from firmadyne project
        kernel_urls = {
            "mipsel": (
                "https://github.com/firmadyne/kernel-v2.6/releases/download/v1.1/vmlinux.mipsel",
                "vmlinux.mipsel",
            ),
            "mips": (
                "https://github.com/firmadyne/kernel-v2.6/releases/download/v1.1/vmlinux.mipseb",
                "vmlinux.mipseb",
            ),
            "arm": (
                "https://github.com/firmadyne/kernel-v4.1/releases/download/v1.1/zImage.armel",
                "zImage.armel",
            ),
        }

        if not architectures:
            architectures = list(kernel_urls.keys())

        self.kernel_dir.mkdir(parents=True, exist_ok=True)

        results = {}
        for arch in architectures:
            if arch not in kernel_urls:
                logger.warning(f"Unknown architecture: {arch}")
                results[arch] = False
                continue

            url, filename = kernel_urls[arch]
            target = self.kernel_dir / filename

            if target.exists():
                logger.info(f"Kernel already exists: {target}")
                results[arch] = True
                continue

            logger.info(f"Downloading kernel for {arch}...")
            try:
                # Validate URL scheme to prevent file:// or other unsafe schemes
                from urllib.parse import urlparse

                parsed = urlparse(url)
                if parsed.scheme not in ("http", "https"):
                    logger.error(f"Invalid URL scheme: {parsed.scheme}")
                    results[arch] = False
                    continue
                urllib.request.urlretrieve(url, target)  # nosec B310

                # Verify file was downloaded and has content
                if target.exists() and target.stat().st_size > 0:
                    logger.info(f"Downloaded: {target} ({target.stat().st_size} bytes)")
                    results[arch] = True
                else:
                    logger.error(f"Download resulted in empty file for {arch}")
                    results[arch] = False
                    if target.exists():
                        target.unlink()
            except Exception as e:
                logger.error(f"Failed to download {arch} kernel: {e}")
                results[arch] = False

        return results
