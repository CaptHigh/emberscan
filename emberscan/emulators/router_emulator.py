"""
Router Firmware Emulation Support.

This module provides emulation support for embedded router firmware
that requires NVRAM emulation and hardware script patching.

Supports various router firmware including:
- Linksys (E-series, WRT-series)
- TP-Link
- D-Link
- Netgear
- ASUS
- And other embedded Linux-based routers
"""

import os
import shutil
from pathlib import Path
from typing import Dict, List, Optional

from ..core.config import Config
from ..core.exceptions import EmulationError
from ..core.logger import get_logger
from ..core.models import Architecture, FirmwareInfo

logger = get_logger(__name__)


class RouterEmulator:
    """
    Emulator for embedded router firmware.

    Handles common requirements for router firmware emulation:
    - NVRAM emulation (for nvram_get/nvram_set calls)
    - Hardware script disabling (GPIO, LED, watchdog, etc.)
    - Init script patching for serial console access
    - Required directory structure creation
    """

    # NVRAM defaults commonly needed by router firmware
    DEFAULT_NVRAM_VALUES = {
        # Network settings
        "lan_ipaddr": "192.168.1.1",
        "lan_netmask": "255.255.255.0",
        "lan_gateway": "192.168.1.1",
        "lan_proto": "static",
        "wan_ipaddr": "0.0.0.0",
        "wan_proto": "dhcp",
        # Wireless settings (disabled for emulation)
        "wl0_ssid": "EmberScan-Emulated",
        "wl0_mode": "disabled",
        "wl_radio": "0",
        # System settings
        "router_name": "EmberScan-Router",
        "time_zone": "PST8PDT",
        "ntp_server": "pool.ntp.org",
        # Web interface settings
        "http_enable": "1",
        "http_lanport": "80",
        "http_username": "admin",
        "http_passwd": "admin",
        # Telnet/SSH settings
        "telnet_enable": "1",
        "ssh_enable": "1",
        # Emulation marker
        "emberscan_emulated": "1",
    }

    # Hardware-specific scripts that should be disabled in emulation
    HW_SCRIPTS_TO_DISABLE = [
        "gpio",
        "led",
        "button",
        "buttons",
        "switch",
        "watchdog",
        "wdog",
        "fan",
        "thermal",
        "wifi",
        "wireless",
        "wlan",
        "phy",
        "radio",
        "brcm",  # Broadcom-specific
        "bcm",
        "ath",  # Atheros-specific
        "mtd-write",
        "mtd_write",
        "nvram_daemon",
    ]

    # Scripts to ensure remain enabled
    REQUIRED_SCRIPTS = [
        "rcS",
        "rc.local",
        "network",
        "httpd",
        "lighttpd",
        "uhttpd",
        "mini_httpd",
        "telnetd",
        "sshd",
        "dropbear",
        "syslog",
        "cron",
    ]

    def __init__(self, config: Config):
        self.config = config
        self.work_dir = Path(config.workspace_dir) / "router_emulation"
        self.work_dir.mkdir(parents=True, exist_ok=True)

    def prepare_firmware(
        self,
        firmware: FirmwareInfo,
        instance_id: str,
        nvram_overrides: Optional[Dict[str, str]] = None,
    ) -> Path:
        """
        Prepare router firmware for emulation.

        This method:
        1. Creates NVRAM configuration file
        2. Patches init scripts for emulation compatibility
        3. Disables hardware-specific scripts
        4. Creates emulation marker files

        Args:
            firmware: FirmwareInfo with extracted rootfs
            instance_id: Unique emulation instance ID
            nvram_overrides: Optional NVRAM value overrides

        Returns:
            Path to prepared rootfs directory
        """
        if not firmware.rootfs_path:
            raise EmulationError("Firmware rootfs not extracted")

        rootfs = Path(firmware.rootfs_path)
        if not rootfs.exists():
            raise EmulationError(f"Rootfs not found: {rootfs}")

        logger.info(f"Preparing router firmware for emulation: {firmware.name}")

        # Create working copy if needed
        work_rootfs = self.work_dir / instance_id / "rootfs"
        if work_rootfs != rootfs:
            logger.debug(f"Creating working copy at {work_rootfs}")
            if work_rootfs.exists():
                shutil.rmtree(work_rootfs)
            shutil.copytree(rootfs, work_rootfs, symlinks=True)
            rootfs = work_rootfs

        # Apply patches
        self._create_nvram_config(rootfs, nvram_overrides)
        self._patch_init_scripts(rootfs)
        self._disable_hardware_scripts(rootfs)
        self._ensure_required_directories(rootfs)
        self._create_emulation_markers(rootfs, firmware)
        self._patch_library_paths(rootfs, firmware.architecture)

        return rootfs

    def _create_nvram_config(
        self, rootfs: Path, overrides: Optional[Dict[str, str]] = None
    ) -> None:
        """Create NVRAM configuration for nvram emulation."""
        nvram_values = self.DEFAULT_NVRAM_VALUES.copy()
        if overrides:
            nvram_values.update(overrides)

        # Create nvram.ini for libnvram-faker
        nvram_ini = rootfs / "etc" / "nvram.ini"
        logger.debug(f"Creating NVRAM config at {nvram_ini}")

        lines = ["# NVRAM configuration for EmberScan emulation\n"]
        for key, value in sorted(nvram_values.items()):
            lines.append(f"{key}={value}\n")

        nvram_ini.parent.mkdir(parents=True, exist_ok=True)
        nvram_ini.write_text("".join(lines))

        # Also create nvram directory for firmware that reads files directly
        nvram_dir = rootfs / "var" / "nvram"
        nvram_dir.mkdir(parents=True, exist_ok=True)

        # Create individual nvram files
        for key, value in nvram_values.items():
            (nvram_dir / key).write_text(value)

        # Create /tmp/nvram symlink (some firmware expects this)
        tmp_nvram = rootfs / "tmp" / "nvram"
        tmp_nvram.parent.mkdir(parents=True, exist_ok=True)
        if not tmp_nvram.exists():
            try:
                tmp_nvram.symlink_to("/var/nvram")
            except OSError:
                pass  # Symlink may already exist or fail in some environments

    def _patch_init_scripts(self, rootfs: Path) -> None:
        """Patch init scripts for emulation compatibility."""
        # Patch inittab for serial console
        inittab = rootfs / "etc" / "inittab"
        if inittab.exists():
            content = inittab.read_text()

            # Add serial console if not present
            if "ttyS0" not in content:
                content += "\n# EmberScan emulation - serial console\n"
                content += "ttyS0::respawn:/sbin/getty -L ttyS0 115200 vt100\n"

            # Disable hardware console entries that won't work in emulation
            lines = []
            for line in content.split("\n"):
                if any(
                    hw in line.lower()
                    for hw in ["ttyatm", "ttyusb", "ttymxc", "ttys1", "ttys2"]
                ):
                    lines.append(f"# DISABLED for emulation: {line}")
                else:
                    lines.append(line)

            inittab.write_text("\n".join(lines))
            logger.debug("Patched inittab for serial console")

        # Patch rcS to skip hardware init
        rcs_paths = [
            rootfs / "etc" / "init.d" / "rcS",
            rootfs / "etc" / "rc.d" / "rcS",
            rootfs / "etc" / "rcS",
        ]

        for rcs in rcs_paths:
            if rcs.exists():
                self._patch_rcs_script(rcs)

    def _patch_rcs_script(self, rcs_path: Path) -> None:
        """Patch rcS script to be emulation-friendly."""
        content = rcs_path.read_text()

        # Add emulation detection at the start
        emulation_check = """
# EmberScan Emulation Detection
if [ -f /etc/emberscan_emulated ]; then
    echo "[EmberScan] Running in emulation mode"
    export EMBERSCAN_EMULATED=1
fi
"""
        if "EMBERSCAN_EMULATED" not in content:
            # Insert after shebang
            lines = content.split("\n")
            if lines[0].startswith("#!"):
                lines.insert(1, emulation_check)
            else:
                lines.insert(0, emulation_check)
            content = "\n".join(lines)
            rcs_path.write_text(content)
            logger.debug(f"Patched {rcs_path} with emulation detection")

    def _disable_hardware_scripts(self, rootfs: Path) -> None:
        """Disable hardware-specific init scripts."""
        init_dirs = [
            rootfs / "etc" / "init.d",
            rootfs / "etc" / "rc.d",
            rootfs / "etc" / "rc.d" / "init.d",
        ]

        disabled_count = 0
        for init_dir in init_dirs:
            if not init_dir.exists():
                continue

            for script in init_dir.iterdir():
                if not script.is_file():
                    continue

                script_lower = script.name.lower()

                # Check if this is a hardware script to disable
                should_disable = any(
                    hw in script_lower for hw in self.HW_SCRIPTS_TO_DISABLE
                )

                # Don't disable required scripts
                is_required = any(req in script_lower for req in self.REQUIRED_SCRIPTS)

                if should_disable and not is_required:
                    disabled_path = script.with_suffix(script.suffix + ".disabled")
                    try:
                        script.rename(disabled_path)
                        disabled_count += 1
                        logger.debug(f"Disabled hardware script: {script.name}")
                    except OSError as e:
                        logger.warning(f"Could not disable {script.name}: {e}")

        logger.info(f"Disabled {disabled_count} hardware-specific scripts")

    def _ensure_required_directories(self, rootfs: Path) -> None:
        """Ensure required directories exist."""
        required_dirs = [
            "dev",
            "proc",
            "sys",
            "tmp",
            "var",
            "var/run",
            "var/log",
            "var/tmp",
            "var/lock",
            "mnt",
            "root",
        ]

        for dir_name in required_dirs:
            dir_path = rootfs / dir_name
            dir_path.mkdir(parents=True, exist_ok=True)

        # Create essential device nodes info (actual nodes created at runtime)
        dev_info = rootfs / "etc" / "devices.txt"
        dev_info.write_text(
            """# Device nodes needed for emulation
# These are created by the init system
console 5:1
null 1:3
zero 1:5
random 1:8
urandom 1:9
ttyS0 4:64
"""
        )

    def _create_emulation_markers(self, rootfs: Path, firmware: FirmwareInfo) -> None:
        """Create marker files for emulation detection."""
        # Main marker file
        marker = rootfs / "etc" / "emberscan_emulated"
        marker.write_text(
            f"""EmberScan QEMU Emulation
Type: Router Firmware
Architecture: {firmware.architecture.value}
"""
        )

        # Create emulation environment script
        env_script = rootfs / "etc" / "profile.d" / "emberscan.sh"
        env_script.parent.mkdir(parents=True, exist_ok=True)
        env_script.write_text(
            """# EmberScan Emulation Environment
export EMBERSCAN_EMULATED=1
export QEMU_EMULATION=1

# Alias for convenience
alias nvram_get='cat /var/nvram/'
alias nvram_list='ls /var/nvram/'

echo "[EmberScan] Emulated environment ready"
"""
        )

    def _patch_library_paths(self, rootfs: Path, architecture: Architecture) -> None:
        """Ensure library paths are correctly set up."""
        # Create ld.so.conf if it doesn't exist
        ld_conf = rootfs / "etc" / "ld.so.conf"

        # Architecture-specific library paths
        arch_lib_paths = {
            Architecture.MIPS_LE: ["/lib", "/usr/lib", "/lib/mipsel-linux-gnu"],
            Architecture.MIPS_BE: ["/lib", "/usr/lib", "/lib/mips-linux-gnu"],
            Architecture.ARM: ["/lib", "/usr/lib", "/lib/arm-linux-gnueabi"],
            Architecture.ARM64: ["/lib", "/usr/lib", "/lib/aarch64-linux-gnu"],
            Architecture.X86: ["/lib", "/usr/lib", "/lib/i386-linux-gnu"],
            Architecture.X86_64: ["/lib", "/usr/lib", "/lib/x86_64-linux-gnu"],
        }

        lib_paths = arch_lib_paths.get(architecture, ["/lib", "/usr/lib"])

        if ld_conf.exists():
            existing = ld_conf.read_text()
            for path in lib_paths:
                if path not in existing:
                    existing += f"\n{path}"
            ld_conf.write_text(existing)
        else:
            ld_conf.write_text("\n".join(lib_paths) + "\n")

    def get_qemu_extra_args(self) -> List[str]:
        """Get extra QEMU arguments for router emulation."""
        return [
            # Enable more debugging output
            "-d",
            "guest_errors",
        ]

    def get_kernel_cmdline_extras(self) -> str:
        """Get extra kernel command line arguments."""
        return "init=/sbin/init panic=10"


def detect_router_firmware(firmware: FirmwareInfo) -> bool:
    """
    Detect if firmware is router/embedded device firmware.

    Checks for common indicators:
    - NVRAM utilities
    - Web server binaries
    - Router-specific directory structures
    - Common router configuration files
    """
    if not firmware.rootfs_path:
        return False

    rootfs = Path(firmware.rootfs_path)

    # Check for NVRAM-related indicators (strong signal for router firmware)
    nvram_indicators = [
        rootfs / "usr" / "sbin" / "nvram",
        rootfs / "bin" / "nvram",
        rootfs / "usr" / "bin" / "nvram",
        rootfs / "sbin" / "nvram",
        rootfs / "etc" / "nvram.conf",
    ]

    for indicator in nvram_indicators:
        if indicator.exists():
            logger.debug(f"Detected router firmware: found {indicator}")
            return True

    # Check for web server binaries (common in routers)
    web_indicators = [
        rootfs / "usr" / "sbin" / "httpd",
        rootfs / "usr" / "sbin" / "uhttpd",
        rootfs / "usr" / "sbin" / "lighttpd",
        rootfs / "usr" / "sbin" / "mini_httpd",
        rootfs / "www" / "cgi-bin",
        rootfs / "www" / "index.html",
        rootfs / "www" / "index.asp",
    ]

    web_found = sum(1 for ind in web_indicators if ind.exists())
    if web_found >= 2:  # Multiple web indicators suggest router
        logger.debug("Detected router firmware: multiple web server indicators found")
        return True

    # Check for router-specific configuration structures
    router_configs = [
        rootfs / "etc" / "config",  # OpenWrt style
        rootfs / "etc" / "wl.conf",  # Broadcom wireless
        rootfs / "etc" / "wireless",
        rootfs / "etc" / "network",
        rootfs / "etc_ro",  # Read-only config partition
    ]

    for config in router_configs:
        if config.exists():
            logger.debug(f"Detected router firmware: found {config}")
            return True

    # Check for vendor-specific indicators
    vendor_indicators = [
        rootfs / "usr" / "sbin" / "wl",  # Broadcom wireless utility
        rootfs / "usr" / "sbin" / "iwpriv",  # Wireless config
        rootfs / "usr" / "sbin" / "brctl",  # Bridge control
        rootfs / "usr" / "sbin" / "iptables",  # Firewall
        rootfs / "usr" / "sbin" / "udhcpd",  # DHCP server
    ]

    vendor_found = sum(1 for ind in vendor_indicators if ind.exists())
    if vendor_found >= 3:  # Multiple router utilities suggest router firmware
        logger.debug("Detected router firmware: multiple router utilities found")
        return True

    return False
