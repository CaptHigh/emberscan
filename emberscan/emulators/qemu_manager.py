"""
QEMU Emulation Manager.

Manages QEMU virtual machines for firmware emulation across
multiple architectures (MIPS, ARM, x86, PowerPC).
"""

import os
import shutil
import signal
import socket
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from ..core.config import Config
from ..core.exceptions import (
    EmulationBootFailure,
    EmulationError,
    EmulationTimeoutError,
    KernelNotFoundError,
    NetworkConfigurationError,
    QEMUNotFoundError,
    UnsupportedArchitectureError,
)
from ..core.logger import get_logger
from ..core.models import Architecture, EmulationState, Endianness, FirmwareInfo

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
    disk_if: str = "ide"  # Disk interface: ide, virtio, scsi
    root_dev: str = "/dev/hda"  # Root device name in guest
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
            cpu="24Kc",
            kernel_name="vmlinux.mipsel",
            console="ttyS0",
            disk_if="ide",
            root_dev="/dev/sda",
        ),
        Architecture.MIPS_BE: QEMUProfile(
            binary="qemu-system-mips",
            machine="malta",
            cpu="24Kc",
            kernel_name="vmlinux.mipseb",
            console="ttyS0",
            disk_if="ide",
            root_dev="/dev/sda",
        ),
        Architecture.ARM: QEMUProfile(
            binary="qemu-system-arm",
            machine="virt",
            cpu="cortex-a15",
            kernel_name="zImage.armel",
            console="ttyAMA0",
            nic_model="virtio-net-device",
            disk_if="virtio",
            root_dev="/dev/vda",
        ),
        Architecture.ARM64: QEMUProfile(
            binary="qemu-system-aarch64",
            machine="virt",
            cpu="cortex-a53",
            kernel_name="Image.aarch64",
            console="ttyAMA0",
            nic_model="virtio-net-device",
            disk_if="virtio",
            root_dev="/dev/vda",
        ),
        Architecture.X86: QEMUProfile(
            binary="qemu-system-i386",
            machine="pc",
            cpu="qemu32",
            kernel_name="bzImage.x86",
            console="ttyS0",
            disk_if="ide",
            root_dev="/dev/hda",
        ),
        Architecture.X86_64: QEMUProfile(
            binary="qemu-system-x86_64",
            machine="pc",
            cpu="qemu64",
            kernel_name="bzImage.x86_64",
            console="ttyS0",
            disk_if="ide",
            root_dev="/dev/hda",
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
        display_mode: str = "none",
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
            display_mode: Display mode (none, gtk, sdl, curses, console)

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
            display_mode=display_mode,
        )

        state.qemu_command = " ".join(qemu_cmd)
        logger.debug(f"QEMU command: {state.qemu_command}")

        # Start QEMU process
        # For interactive modes (console, gtk, sdl), don't capture stdio
        try:
            if display_mode in ("console", "gtk", "sdl"):
                # Interactive modes - need access to stdio for serial console
                process = subprocess.Popen(
                    qemu_cmd,
                    stdin=None,
                    stdout=None,
                    stderr=None,
                )
            else:
                # Headless modes - can capture output for debugging
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
        last_check_time = start_time
        boot_detected = False
        service_found = False

        while time.time() - start_time < timeout:
            # Check if QEMU is still running
            process = self._instances.get(state.id)
            if not process or process.poll() is not None:
                elapsed = time.time() - start_time

                # If process ended very early (< 10s), it's likely a boot error
                # If it ran longer, user might have closed the window or services already started
                if elapsed < 10:
                    # Try to capture error output (only works if stderr was captured)
                    error_msg = None
                    exit_code = None

                    if process:
                        exit_code = process.returncode

                        # Only try to read stderr if it was captured (non-interactive mode)
                        if process.stderr:
                            try:
                                _, stderr = process.communicate(timeout=1)
                                if stderr:
                                    error_msg = stderr.decode("utf-8", errors="ignore").strip()
                                    # Get last few lines of error
                                    error_lines = error_msg.split("\n")[-10:]
                                    error_msg = "\n".join(error_lines)
                            except Exception:
                                pass

                        # Exit code 0 means normal shutdown - might be user closing window
                        if exit_code == 0:
                            logger.warning(f"QEMU exited normally after {elapsed:.1f}s")
                            logger.warning("This might mean:")
                            logger.warning("  - User closed the display window")
                            logger.warning("  - Firmware completed boot and shutdown")
                            # Don't treat as error, just return with current state
                            return boot_detected
                        else:
                            logger.error(f"QEMU process crashed early (exit code: {exit_code}) after {elapsed:.1f}s")
                            if error_msg:
                                logger.error(f"QEMU error output:\n{error_msg}")
                                # Check for common boot errors
                                if "Kernel panic" in error_msg:
                                    logger.error("→ Kernel panic detected - wrong architecture or incompatible firmware")
                                elif "VFS: Cannot open root device" in error_msg:
                                    logger.error("→ Root device error - disk configuration issue")
                                elif "unable to find CPU model" in error_msg:
                                    logger.error("→ Invalid CPU model for this architecture")
                            else:
                                logger.error("Unable to capture error output (interactive mode)")
                                logger.error("Try running with --display none to capture detailed errors")
                    else:
                        logger.error("QEMU process terminated unexpectedly")
                    return False
                else:
                    # Process ended after running for a while
                    logger.info(f"QEMU process ended after {elapsed:.1f}s")
                    if boot_detected:
                        logger.info("Services were detected - boot was successful")
                        return True
                    else:
                        logger.warning("No services detected before QEMU ended")
                        return False

            current_time = time.time()
            elapsed = current_time - start_time

            # Check for actual service responses (not just open ports)
            # Only check every check_interval seconds to avoid spam
            if current_time - last_check_time >= check_interval:
                last_check_time = current_time

                # Try HTTP first (most common web interface)
                if self._check_http_service(state.ip_address, state.http_port):
                    if not service_found:
                        state.boot_successful = True
                        state.boot_time = elapsed
                        state.services_detected.append("http")
                        logger.info(f"✓ HTTP service responding after {state.boot_time:.1f}s")
                        service_found = True
                        boot_detected = True

                # Check SSH
                if self._check_ssh_service(state.ip_address, state.ssh_port):
                    if "ssh" not in state.services_detected:
                        state.services_detected.append("ssh")
                        logger.info(f"✓ SSH service responding after {elapsed:.1f}s")
                        if not boot_detected:
                            state.boot_successful = True
                            state.boot_time = elapsed
                            boot_detected = True
                            service_found = True

                # Check Telnet
                if self._check_telnet_service(state.ip_address, state.telnet_port):
                    if "telnet" not in state.services_detected:
                        state.services_detected.append("telnet")
                        logger.info(f"✓ Telnet service responding after {elapsed:.1f}s")
                        if not boot_detected:
                            state.boot_successful = True
                            state.boot_time = elapsed
                            boot_detected = True
                            service_found = True

                # If we found any responding service, consider boot successful
                if boot_detected:
                    return True

                # Log progress every 30 seconds
                if int(elapsed) % 30 == 0 and elapsed > 0:
                    logger.info(f"Still waiting for services... ({int(elapsed)}s elapsed)")

            time.sleep(1)  # Check more frequently but only run service checks every check_interval

        # Timeout reached
        logger.warning(f"Boot timeout after {timeout}s")

        # Check if QEMU is still running
        process = self._instances.get(state.id)
        if process and process.poll() is None:
            logger.warning("QEMU is still running but no services responded")
            logger.warning("This usually means:")
            logger.warning("  - Wrong architecture specified (firmware can't execute)")
            logger.warning("  - Network not configured in firmware")
            logger.warning("  - Services failed to start (check with --display console)")
            logger.warning("  - Firmware waiting for user interaction")

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

        # Create filesystem - use ext2 with minimal features for old kernel compatibility
        # Disable 64bit, metadata_csum, and other modern features
        subprocess.run(
            [
                "mkfs.ext2",
                "-F",
                "-O", "^64bit,^metadata_csum,^dir_index",
                "-I", "128",  # Small inode size for compatibility
                str(image_path)
            ],
            capture_output=True,
            check=True,
        )

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
        # Create /dev if it doesn't exist
        dev_dir = rootfs / "dev"
        subprocess.run(
            ["sudo", "mkdir", "-p", str(dev_dir)],
            capture_output=True,
        )

        # Create fake /dev/nvram as a regular file (firmware will fail to ioctl but won't crash)
        nvram_dev = dev_dir / "nvram"
        if not nvram_dev.exists():
            subprocess.run(
                ["sudo", "mknod", str(nvram_dev), "c", "10", "144"],
                capture_output=True,
            )

        # Create other common device nodes
        for dev_name, dev_type, major, minor in [
            ("console", "c", "5", "1"),
            ("null", "c", "1", "3"),
            ("zero", "c", "1", "5"),
            ("random", "c", "1", "8"),
            ("urandom", "c", "1", "9"),
        ]:
            dev_path = dev_dir / dev_name
            if not dev_path.exists():
                subprocess.run(
                    ["sudo", "mknod", str(dev_path), dev_type, major, minor],
                    capture_output=True,
                )

        # Add serial console to inittab for interactive access
        inittab = rootfs / "etc" / "inittab"
        # Check if inittab exists
        result = subprocess.run(
            ["sudo", "test", "-f", str(inittab)],
            capture_output=True,
        )

        if result.returncode == 0:  # File exists
            # Check if ttyS0 entry already exists to avoid duplicates
            result = subprocess.run(
                ["sudo", "grep", "-q", "ttyS0", str(inittab)],
                capture_output=True,
            )
            has_ttys0 = (result.returncode == 0)

            if not has_ttys0:
                # BusyBox init format: <id>::<action>:<process>
                # Append getty line to inittab
                subprocess.run(
                    ["sudo", "sh", "-c",
                     f"echo '' >> '{inittab}' && "
                     f"echo '# EmberScan emulation - serial console' >> '{inittab}' && "
                     f"echo 'ttyS0::respawn:/sbin/getty -L ttyS0 115200 vt100' >> '{inittab}' && "
                     f"echo '# Fallback if /sbin/getty doesn\\'t exist' >> '{inittab}' && "
                     f"echo 'ttyS1::respawn:/bin/sh' >> '{inittab}'"],
                    capture_output=True,
                )

        # Disable hardware-specific scripts
        init_d = rootfs / "etc" / "init.d"
        if init_d.exists():
            hw_scripts = ["gpio", "led", "button", "switch", "watchdog"]
            for script in init_d.iterdir():
                if any(hw in script.name.lower() for hw in hw_scripts):
                    try:
                        script.rename(script.with_suffix(".disabled"))
                    except (PermissionError, FileNotFoundError):
                        pass

        # Configure network for emulation
        # Create a simple network startup script for firmwares that don't auto-configure
        init_d = rootfs / "etc" / "init.d"

        # Ensure init.d directory exists
        subprocess.run(
            ["sudo", "mkdir", "-p", str(init_d)],
            capture_output=True,
        )

        network_script = init_d / "S40network_emulation"
        network_content = """#!/bin/sh
# EmberScan network configuration for emulation
# This ensures eth0 is up with a basic configuration

case "$1" in
    start)
        echo "Configuring network for emulation..."
        # Bring up loopback
        ifconfig lo 127.0.0.1 up 2>/dev/null
        # Configure eth0 with DHCP or static IP
        ifconfig eth0 up 2>/dev/null
        # Try DHCP first (QEMU user networking provides DHCP)
        udhcpc -i eth0 -n -q 2>/dev/null || {
            # Fallback to static IP if DHCP fails
            ifconfig eth0 192.168.1.1 netmask 255.255.255.0 up 2>/dev/null
        }
        ;;
    stop)
        ifconfig eth0 down 2>/dev/null
        ;;
    *)
        echo "Usage: $0 {start|stop}"
        exit 1
        ;;
esac
"""
        # Always use sudo to write to mounted filesystem
        subprocess.run(
            ["sudo", "sh", "-c", f"cat > '{network_script}' << 'EOFNET'\n{network_content}EOFNET"],
            capture_output=True,
            check=True,
        )
        subprocess.run(
            ["sudo", "chmod", "755", str(network_script)],
            capture_output=True,
            check=True,
        )

        # Create emulation marker
        marker = rootfs / "etc" / "emberscan_emulated"
        subprocess.run(
            ["sudo", "sh", "-c", f"echo 'EmberScan QEMU Emulation' > '{marker}'"],
            capture_output=True,
        )

    def _build_qemu_command(
        self,
        profile: QEMUProfile,
        kernel_path: Path,
        rootfs_image: Path,
        state: EmulationState,
        enable_debug: bool,
        display_mode: str = "none",
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
            f"file={rootfs_image},format=raw,if={profile.disk_if}",
            "-append",
            f"root={profile.root_dev} console={profile.console} rw",
        ]

        # Display mode configuration
        if display_mode == "none":
            # Headless mode - no display, serial to null
            cmd.extend(["-nographic", "-serial", "null"])
        elif display_mode == "gtk":
            # GTK GUI window with serial console multiplexed to stdio
            # This allows both GTK window AND interactive terminal access
            # User can interact via terminal while seeing GUI output
            cmd.extend(["-display", "gtk", "-serial", "mon:stdio"])
        elif display_mode == "sdl":
            # SDL GUI window with serial console multiplexed to stdio
            cmd.extend(["-display", "sdl", "-serial", "mon:stdio"])
        elif display_mode == "curses":
            # Text-mode display in terminal - uses ncurses UI
            cmd.extend(["-display", "curses", "-serial", "stdio"])
        elif display_mode == "console":
            # Serial console to terminal - shows boot messages and allows interaction
            cmd.extend(["-serial", "mon:stdio", "-nographic"])

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
            cmd.extend(["-s"])  # GDB server on 1234 (port can be connected anytime)

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

    def _check_http_service(self, host: str, port: int, timeout: float = 5.0) -> bool:
        """Check if HTTP service is actually responding (not just port open)."""
        import urllib.request
        import urllib.error

        try:
            # Try to get HTTP response
            url = f"http://{host}:{port}/"
            req = urllib.request.Request(url, method='GET')
            with urllib.request.urlopen(req, timeout=timeout) as response:
                # Any HTTP response (even 404) means the server is working
                return response.status < 600
        except urllib.error.HTTPError as e:
            # HTTP errors (404, 500, etc.) still mean the server is responding
            return e.code < 600
        except (urllib.error.URLError, TimeoutError, ConnectionRefusedError, OSError):
            # Connection failed - server not responding
            return False
        except Exception:
            return False

    def _check_ssh_service(self, host: str, port: int, timeout: float = 5.0) -> bool:
        """Check if SSH service is actually responding with SSH banner."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((host, port))
            # SSH server sends banner immediately
            banner = sock.recv(256).decode('utf-8', errors='ignore')
            sock.close()
            # Check for SSH banner
            return banner.startswith('SSH-')
        except:
            return False

    def _check_telnet_service(self, host: str, port: int, timeout: float = 5.0) -> bool:
        """Check if Telnet service is actually responding."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((host, port))
            # Telnet server typically sends IAC (0xff) commands or login prompt
            data = sock.recv(256)
            sock.close()
            # If we got any data, telnet is responding
            return len(data) > 0
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
