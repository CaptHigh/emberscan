"""
Firmware extraction module.

Handles extraction of firmware from various sources including
SPI flash dumps, manufacturer firmware files, and compressed images.
"""

import os
import re
import shutil
import struct
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from ..core.config import Config
from ..core.exceptions import (
    EncryptedFirmwareError,
    ExtractionError,
    FilesystemExtractionError,
    UnsupportedFirmwareError,
)
from ..core.logger import get_logger
from ..core.models import Architecture, Endianness, FilesystemType, FirmwareInfo

logger = get_logger(__name__)


class FirmwareExtractor:
    """
    Extract and analyze firmware images.

    Supports:
    - SPI flash dumps
    - Manufacturer firmware files
    - Multiple filesystem types (SquashFS, JFFS2, CramFS, etc.)
    - Compressed images (LZMA, GZIP, XZ)
    """

    # Known firmware signatures
    SIGNATURES = {
        b"\x55\xaa": ("tplink_header", "TP-Link Firmware Header"),
        b"\x27\x05\x19\x56": ("uimage", "U-Boot uImage Header"),
        b"hsqs": ("squashfs_le", "SquashFS (Little Endian)"),
        b"sqsh": ("squashfs_be", "SquashFS (Big Endian)"),
        b"\x68\x73\x71\x73": ("squashfs_le", "SquashFS (Little Endian)"),
        b"\x73\x71\x73\x68": ("squashfs_be", "SquashFS (Big Endian)"),
        b"\x5d\x00\x00": ("lzma", "LZMA Compressed"),
        b"\x1f\x8b\x08": ("gzip", "GZIP Compressed"),
        b"\xfd\x37\x7a\x58\x5a\x00": ("xz", "XZ Compressed"),
        b"UBI#": ("ubi", "UBI Image"),
        b"\x31\x18\x10\x06": ("ubifs", "UBIFS Filesystem"),
        b"\x85\x19\x03\x20": ("jffs2_le", "JFFS2 (Little Endian)"),
        b"\x19\x85\x20\x03": ("jffs2_be", "JFFS2 (Big Endian)"),
        b"\x45\x3d\xcd\x28": ("cramfs_le", "CramFS (Little Endian)"),
        b"\x28\xcd\x3d\x45": ("cramfs_be", "CramFS (Big Endian)"),
        b"-rom1fs-": ("romfs", "RomFS"),
        b"\x7fELF": ("elf", "ELF Binary"),
    }

    def __init__(self, config: Config):
        self.config = config
        self.temp_dir = Path(config.extractor.temp_dir)
        self.temp_dir.mkdir(parents=True, exist_ok=True)

    def analyze(self, firmware_path: str) -> Dict[str, Any]:
        """
        Analyze firmware without extraction.

        Returns dict with:
        - architecture
        - endianness
        - filesystem_type
        - components (list of detected components with offsets)
        - entropy_analysis
        """
        logger.info(f"Analyzing firmware: {firmware_path}")

        with open(firmware_path, "rb") as f:
            data = f.read()

        result = {
            "file_size": len(data),
            "components": [],
            "architecture": Architecture.UNKNOWN,
            "endianness": Endianness.UNKNOWN,
            "filesystem_type": FilesystemType.UNKNOWN,
        }

        # Scan for signatures
        for signature, (sig_type, description) in self.SIGNATURES.items():
            offset = 0
            while True:
                pos = data.find(signature, offset)
                if pos == -1:
                    break

                result["components"].append(
                    {
                        "type": sig_type,
                        "description": description,
                        "offset": pos,
                        "offset_hex": hex(pos),
                    }
                )

                # Determine filesystem type
                if "squashfs" in sig_type:
                    result["filesystem_type"] = FilesystemType.SQUASHFS
                    result["endianness"] = (
                        Endianness.LITTLE if "_le" in sig_type else Endianness.BIG
                    )
                elif "jffs2" in sig_type:
                    result["filesystem_type"] = FilesystemType.JFFS2
                    result["endianness"] = (
                        Endianness.LITTLE if "_le" in sig_type else Endianness.BIG
                    )
                elif sig_type == "cramfs_le" or sig_type == "cramfs_be":
                    result["filesystem_type"] = FilesystemType.CRAMFS
                    result["endianness"] = (
                        Endianness.LITTLE if "_le" in sig_type else Endianness.BIG
                    )
                elif sig_type in ("ubifs", "ubi"):
                    result["filesystem_type"] = FilesystemType.UBIFS
                elif sig_type == "romfs":
                    result["filesystem_type"] = FilesystemType.ROMFS

                offset = pos + 1

        # Detect architecture from ELF binaries
        elf_pos = data.find(b"\x7fELF")
        if elf_pos != -1:
            arch_info = self._parse_elf_header(data[elf_pos : elf_pos + 52])
            if arch_info:
                result["architecture"] = arch_info["architecture"]
                result["endianness"] = arch_info["endianness"]

        # Run binwalk for more detailed analysis
        binwalk_results = self._run_binwalk_analysis(firmware_path)
        if binwalk_results:
            result["binwalk"] = binwalk_results

        # Entropy analysis
        result["entropy"] = self._analyze_entropy(data)

        logger.info(
            f"Analysis complete: {result['architecture'].value}, {result['filesystem_type'].value}"
        )

        return result

    def extract(self, firmware_path: str, output_dir: str) -> Path:
        """
        Extract firmware filesystem to output directory.

        Returns path to extracted rootfs.
        """
        logger.info(f"Extracting firmware to: {output_dir}")

        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)

        # Try binwalk extraction first
        rootfs = self._binwalk_extract(firmware_path, output_path)
        if rootfs:
            return rootfs

        # Manual extraction fallback
        analysis = self.analyze(firmware_path)

        # Supported filesystem types for extraction
        supported_fs_types = [
            "squashfs_le",
            "squashfs_be",
            "cramfs_le",
            "cramfs_be",
            "jffs2_le",
            "jffs2_be",
            "ubifs",
            "ubi",
            "romfs",
        ]

        # Find filesystem component
        fs_component = None
        for comp in analysis["components"]:
            if comp["type"] in supported_fs_types:
                fs_component = comp
                break

        if not fs_component:
            # Provide more detailed error message about what was found
            found_types = [comp["type"] for comp in analysis["components"]]
            if found_types:
                logger.warning(f"Components found but not extractable: {found_types}")
                raise FilesystemExtractionError(
                    f"No supported filesystem found. Detected components: {', '.join(found_types)}. "
                    "Supported types: squashfs, cramfs, jffs2, ubifs, romfs"
                )
            else:
                raise FilesystemExtractionError(
                    "No supported filesystem found in firmware. "
                    "The firmware may be encrypted, compressed with an unknown format, "
                    "or use a proprietary filesystem."
                )

        # Extract filesystem
        rootfs = self._manual_extract(
            firmware_path, fs_component, output_path, analysis["filesystem_type"]
        )

        return rootfs

    def extract_metadata(self, firmware_path: str) -> Dict[str, str]:
        """Extract vendor, version, and device information from firmware."""
        metadata = {
            "vendor": "",
            "version": "",
            "device_type": "",
            "name": "",
        }

        # Extract strings and search for patterns
        try:
            result = subprocess.run(
                ["strings", "-n", "8", firmware_path], capture_output=True, text=True, timeout=60
            )
            strings_output = result.stdout
        except:
            return metadata

        # Vendor detection patterns
        vendor_patterns = [
            (r"TP-LINK|TP-Link|tplink", "TP-Link"),
            (r"D-Link|D-LINK|dlink", "D-Link"),
            (r"Netgear|NETGEAR", "Netgear"),
            (r"ASUS|Asus", "ASUS"),
            (r"Linksys|LINKSYS", "Linksys"),
            (r"Cisco|CISCO", "Cisco"),
            (r"Ubiquiti|UBNT", "Ubiquiti"),
            (r"MikroTik|mikrotik", "MikroTik"),
            (r"Huawei|HUAWEI", "Huawei"),
            (r"ZTE|zte", "ZTE"),
            (r"Hikvision|HIKVISION", "Hikvision"),
            (r"Dahua|DAHUA", "Dahua"),
        ]

        for pattern, vendor in vendor_patterns:
            if re.search(pattern, strings_output):
                metadata["vendor"] = vendor
                break

        # Version detection
        version_patterns = [
            r"[Vv]ersion[:\s]+(\d+\.\d+\.\d+)",
            r"[Ff]irmware[:\s]+(\d+\.\d+\.\d+)",
            r"[Vv](\d+\.\d+\.\d+)",
            r"(\d+\.\d+\.\d+\s+[Bb]uild)",
        ]

        for pattern in version_patterns:
            match = re.search(pattern, strings_output)
            if match:
                metadata["version"] = match.group(1)
                break

        # Device type detection
        device_patterns = [
            (r"[Rr]outer|Router", "router"),
            (r"[Ss]witch|Switch", "switch"),
            (r"[Cc]amera|Camera|[Ii]PCam|NVR|DVR", "camera"),
            (r"[Aa]ccess\s*[Pp]oint|AP", "access_point"),
            (r"[Mm]odem|Modem", "modem"),
            (r"[Ff]irewall|Firewall", "firewall"),
            (r"NAS|nas", "nas"),
        ]

        for pattern, device_type in device_patterns:
            if re.search(pattern, strings_output):
                metadata["device_type"] = device_type
                break

        # Extract model name
        model_patterns = [
            r"(Archer\s*[A-Z]+\d+)",
            r"(DIR-\d+)",
            r"(WRT\d+)",
            r"(RT-[A-Z]+\d+)",
            r"Model[:\s]+([A-Za-z0-9-]+)",
        ]

        for pattern in model_patterns:
            match = re.search(pattern, strings_output)
            if match:
                metadata["name"] = match.group(1)
                break

        return metadata

    def _binwalk_extract(self, firmware_path: str, output_dir: Path) -> Optional[Path]:
        """Use binwalk to extract firmware."""
        try:
            # Run binwalk extraction
            subprocess.run(
                ["binwalk", "-e", "-C", str(output_dir), firmware_path],
                capture_output=True,
                timeout=300,
            )

            # Common rootfs directory patterns created by binwalk
            rootfs_patterns = [
                "squashfs-root",
                "cpio-root",
                "jffs2-root",
                "cramfs-root",
                "ubifs-root",
                "romfs-root",
                "rootfs",
            ]

            # Find extracted rootfs by common patterns
            for pattern in rootfs_patterns:
                for item in output_dir.rglob(pattern):
                    if item.is_dir():
                        logger.info(f"Found rootfs: {item}")
                        return item

            # Check for extraction directories (e.g., _firmware.bin.extracted)
            for item in output_dir.iterdir():
                if item.is_dir() and item.name.startswith("_"):
                    # First try to find rootfs patterns inside
                    for pattern in rootfs_patterns:
                        for subitem in item.rglob(pattern):
                            if subitem.is_dir():
                                logger.info(f"Found rootfs: {subitem}")
                                return subitem

                    # Look for directories with typical filesystem structure
                    for subitem in item.rglob("*"):
                        if subitem.is_dir():
                            # Check for common rootfs indicators
                            has_bin = (subitem / "bin").exists()
                            has_etc = (subitem / "etc").exists()
                            has_lib = (subitem / "lib").exists()
                            has_usr = (subitem / "usr").exists()
                            has_sbin = (subitem / "sbin").exists()

                            # If at least 2 of these exist, likely a rootfs
                            indicators = sum([has_bin, has_etc, has_lib, has_usr, has_sbin])
                            if indicators >= 2:
                                logger.info(f"Found rootfs: {subitem}")
                                return subitem

                    # Last resort: return the extraction directory itself if it has content
                    subdirs = list(item.iterdir())
                    if subdirs:
                        # Check if the extraction directory itself looks like rootfs
                        has_bin = (item / "bin").exists()
                        has_etc = (item / "etc").exists()
                        if has_bin or has_etc:
                            logger.info(f"Found rootfs: {item}")
                            return item

            return None

        except subprocess.TimeoutExpired:
            logger.warning("Binwalk extraction timed out")
            return None
        except FileNotFoundError:
            logger.warning("Binwalk not found")
            return None

    def _manual_extract(
        self, firmware_path: str, fs_component: Dict, output_dir: Path, fs_type: FilesystemType
    ) -> Path:
        """Manually extract filesystem using dd and unsquashfs/etc."""

        offset = fs_component["offset"]
        temp_fs = output_dir / f"filesystem.{fs_type.value}"
        rootfs_dir = output_dir / "rootfs"

        # Extract filesystem portion with dd
        logger.info(f"Extracting filesystem from offset {offset}")

        subprocess.run(
            ["dd", f"if={firmware_path}", f"of={temp_fs}", "bs=1", f"skip={offset}"],
            capture_output=True,
            check=True,
        )

        # Extract based on filesystem type
        rootfs_dir.mkdir(exist_ok=True)

        if fs_type == FilesystemType.SQUASHFS:
            try:
                subprocess.run(
                    ["unsquashfs", "-d", str(rootfs_dir), str(temp_fs)],
                    capture_output=True,
                    check=True,
                )
            except subprocess.CalledProcessError:
                # Try sasquatch for non-standard squashfs
                subprocess.run(
                    ["sasquatch", "-d", str(rootfs_dir), str(temp_fs)], capture_output=True
                )

        elif fs_type == FilesystemType.CRAMFS:
            subprocess.run(["cramfsck", "-x", str(rootfs_dir), str(temp_fs)], capture_output=True)

        elif fs_type == FilesystemType.JFFS2:
            # JFFS2 extraction requires special handling
            subprocess.run(["jefferson", str(temp_fs), "-d", str(rootfs_dir)], capture_output=True)

        elif fs_type == FilesystemType.UBIFS:
            # UBIFS extraction using ubireader
            try:
                subprocess.run(
                    ["ubireader_extract_files", "-o", str(rootfs_dir), str(temp_fs)],
                    capture_output=True,
                    check=True,
                )
            except (subprocess.CalledProcessError, FileNotFoundError):
                # Try ubi_reader as alternative
                try:
                    subprocess.run(
                        ["ubi_reader", "-e", str(rootfs_dir), str(temp_fs)],
                        capture_output=True,
                    )
                except FileNotFoundError:
                    logger.warning("ubireader tools not found, trying binwalk fallback")
                    subprocess.run(
                        ["binwalk", "-e", "-C", str(rootfs_dir), str(temp_fs)],
                        capture_output=True,
                    )

        elif fs_type == FilesystemType.ROMFS:
            # RomFS extraction using genromfs or binwalk
            try:
                # Use binwalk for romfs extraction
                subprocess.run(
                    ["binwalk", "-e", "-C", str(rootfs_dir), str(temp_fs)],
                    capture_output=True,
                    check=True,
                )
            except subprocess.CalledProcessError:
                logger.warning("RomFS extraction with binwalk failed")

        else:
            raise FilesystemExtractionError(f"Unsupported filesystem type: {fs_type}")

        # Cleanup temp file
        temp_fs.unlink(missing_ok=True)

        return rootfs_dir

    def _run_binwalk_analysis(self, firmware_path: str) -> Optional[List[Dict]]:
        """Run binwalk signature scan."""
        try:
            result = subprocess.run(
                ["binwalk", firmware_path], capture_output=True, text=True, timeout=120
            )

            components = []
            for line in result.stdout.split("\n"):
                parts = line.split()
                if len(parts) >= 3 and parts[0].isdigit():
                    components.append(
                        {
                            "offset": int(parts[0]),
                            "offset_hex": parts[1],
                            "description": " ".join(parts[2:]),
                        }
                    )

            return components

        except (subprocess.TimeoutExpired, FileNotFoundError):
            return None

    def _parse_elf_header(self, data: bytes) -> Optional[Dict]:
        """Parse ELF header to determine architecture."""
        if len(data) < 52 or data[:4] != b"\x7fELF":
            return None

        # ELF class (32/64 bit)
        elf_class = data[4]

        # Endianness
        endian = Endianness.LITTLE if data[5] == 1 else Endianness.BIG

        # Machine type (offset 18-19)
        if endian == Endianness.LITTLE:
            machine = struct.unpack("<H", data[18:20])[0]
        else:
            machine = struct.unpack(">H", data[18:20])[0]

        # Map machine type to architecture
        arch_map = {
            0x03: Architecture.X86,
            0x08: Architecture.MIPS_BE,  # Default, check endianness
            0x14: Architecture.PPC,
            0x28: Architecture.ARM,
            0x3E: Architecture.X86_64,
            0xB7: Architecture.ARM64,
        }

        arch = arch_map.get(machine, Architecture.UNKNOWN)

        # Adjust MIPS based on endianness
        if arch == Architecture.MIPS_BE and endian == Endianness.LITTLE:
            arch = Architecture.MIPS_LE

        return {
            "architecture": arch,
            "endianness": endian,
            "bits": 64 if elf_class == 2 else 32,
        }

    def _analyze_entropy(self, data: bytes, block_size: int = 1024) -> Dict:
        """Analyze entropy of firmware data."""
        import math

        def calc_entropy(block: bytes) -> float:
            if not block:
                return 0.0
            freq = {}
            for byte in block:
                freq[byte] = freq.get(byte, 0) + 1
            entropy = 0.0
            for count in freq.values():
                p = count / len(block)
                if p > 0:
                    entropy -= p * math.log2(p)
            return entropy

        total_blocks = len(data) // block_size
        if total_blocks == 0:
            return {"average": 0, "encrypted": False}

        entropies = [
            calc_entropy(data[i * block_size : (i + 1) * block_size]) for i in range(total_blocks)
        ]

        avg_entropy = sum(entropies) / len(entropies)

        return {
            "average": round(avg_entropy, 4),
            "max": round(max(entropies), 4),
            "min": round(min(entropies), 4),
            "likely_encrypted": avg_entropy > 7.9,
            "likely_compressed": 7.0 < avg_entropy <= 7.9,
        }


class SPIExtractor:
    """
    Extract firmware from SPI flash chips.

    Supports:
    - CH341A programmer
    - Bus Pirate
    - Flashrom compatible programmers
    """

    SUPPORTED_PROGRAMMERS = [
        "ch341a_spi",
        "buspirate_spi",
        "serprog",
        "linux_spi",
        "ft2232_spi",
    ]

    def __init__(self, config: Config, programmer: str = "ch341a_spi"):
        self.config = config
        self.programmer = programmer

    def detect_chip(self) -> Optional[Dict]:
        """Detect SPI flash chip."""
        try:
            result = subprocess.run(
                ["flashrom", "-p", self.programmer], capture_output=True, text=True, timeout=30
            )

            # Parse output for chip info
            for line in result.stdout.split("\n"):
                if "Found" in line and "flash chip" in line:
                    # Parse: Found Macronix MX25L12835F flash chip
                    parts = line.split('"')
                    if len(parts) >= 2:
                        return {"name": parts[1], "detected": True}

            return None

        except Exception as e:
            logger.error(f"Chip detection failed: {e}")
            return None

    def read_flash(self, output_path: str, verify: bool = True) -> bool:
        """Read entire flash contents to file."""
        logger.info(f"Reading SPI flash to: {output_path}")

        try:
            cmd = ["flashrom", "-p", self.programmer, "-r", output_path]

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)

            if result.returncode != 0:
                logger.error(f"Flash read failed: {result.stderr}")
                return False

            # Verify read
            if verify:
                verify_path = f"{output_path}.verify"
                subprocess.run(
                    ["flashrom", "-p", self.programmer, "-v", output_path],
                    capture_output=True,
                    timeout=600,
                )

            logger.info(f"Flash read complete: {output_path}")
            return True

        except subprocess.TimeoutExpired:
            logger.error("Flash read timed out")
            return False
        except Exception as e:
            logger.error(f"Flash read failed: {e}")
            return False

    def write_flash(self, firmware_path: str, verify: bool = True) -> bool:
        """Write firmware to SPI flash."""
        logger.warning("Flash write operation - ensure you have a backup!")

        try:
            cmd = ["flashrom", "-p", self.programmer, "-w", firmware_path]

            if verify:
                cmd.append("-v")

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=900)

            if result.returncode != 0:
                logger.error(f"Flash write failed: {result.stderr}")
                return False

            logger.info("Flash write complete")
            return True

        except Exception as e:
            logger.error(f"Flash write failed: {e}")
            return False
