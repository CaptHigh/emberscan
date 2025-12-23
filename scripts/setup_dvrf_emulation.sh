#!/bin/bash
# Router Firmware Emulation Setup Script
# This script sets up everything needed to emulate router firmware with EmberScan
#
# Supports various router firmware including DVRF, OpenWrt, DD-WRT, etc.
# Architectures: MIPS (LE/BE), ARM, ARM64

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
KERNELS_DIR="$PROJECT_ROOT/kernels"
FIRMWARE_DIR="$PROJECT_ROOT/firmware"
DVRF_DIR="$FIRMWARE_DIR/DVRF"

echo -e "${CYAN}"
echo "╔════════════════════════════════════════════════════════════════════╗"
echo "║           Router Firmware Emulation Setup for EmberScan            ║"
echo "║     QEMU-based emulation for MIPS/ARM router firmware              ║"
echo "╚════════════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Check for sudo privileges for certain operations
check_sudo() {
    if [ "$EUID" -ne 0 ]; then
        echo -e "${YELLOW}[!] Some operations may require sudo privileges${NC}"
        return 1
    fi
    return 0
}

# =============================================================================
# Step 1: Install QEMU
# =============================================================================
install_qemu() {
    echo -e "\n${CYAN}[1/5] Checking QEMU installation...${NC}"

    if command -v qemu-system-mipsel &> /dev/null; then
        echo -e "${GREEN}    ✓ QEMU MIPS Little Endian already installed${NC}"
        qemu-system-mipsel --version | head -1
    else
        echo -e "${YELLOW}    Installing QEMU emulators...${NC}"
        if check_sudo; then
            apt-get update -qq
            apt-get install -y qemu-system-mips qemu-system-arm qemu-system-x86 qemu-user-static
            echo -e "${GREEN}    ✓ QEMU installed successfully${NC}"
        else
            echo -e "${RED}    ✗ QEMU not installed. Run with sudo or install manually:${NC}"
            echo -e "${YELLOW}      sudo apt-get install qemu-system-mips qemu-system-arm qemu-user-static${NC}"
            return 1
        fi
    fi
}

# =============================================================================
# Step 2: Download Emulation Kernels
# =============================================================================
download_kernels() {
    echo -e "\n${CYAN}[2/5] Setting up emulation kernels...${NC}"

    mkdir -p "$KERNELS_DIR"

    # MIPS Little Endian kernel (required for DVRF)
    MIPSEL_KERNEL="$KERNELS_DIR/vmlinux.mipsel"
    if [ ! -f "$MIPSEL_KERNEL" ] || [ ! -s "$MIPSEL_KERNEL" ]; then
        echo -e "    Downloading MIPS LE kernel from firmadyne..."

        # Try multiple sources for reliability
        KERNEL_URLS=(
            "https://github.com/firmadyne/kernel-v2.6/releases/download/v1.1/vmlinux.mipsel"
            "https://github.com/zcutlip/nvram-faker/releases/download/v0.1/vmlinux.mipsel.2"
        )

        DOWNLOADED=false
        for URL in "${KERNEL_URLS[@]}"; do
            echo -e "    Trying: $URL"
            if curl -sL --fail -o "$MIPSEL_KERNEL" "$URL" 2>/dev/null; then
                if [ -s "$MIPSEL_KERNEL" ]; then
                    echo -e "${GREEN}    ✓ Downloaded vmlinux.mipsel ($(stat -c%s "$MIPSEL_KERNEL") bytes)${NC}"
                    DOWNLOADED=true
                    break
                fi
            fi
        done

        if [ "$DOWNLOADED" = false ]; then
            echo -e "${YELLOW}    ⚠ Could not download kernel automatically${NC}"
            echo -e "${YELLOW}    You may need to build or obtain a MIPS kernel manually${NC}"
        fi
    else
        echo -e "${GREEN}    ✓ MIPS LE kernel already present${NC}"
    fi

    # MIPS Big Endian kernel (optional, for other firmware)
    MIPSEB_KERNEL="$KERNELS_DIR/vmlinux.mipseb"
    if [ ! -f "$MIPSEB_KERNEL" ] || [ ! -s "$MIPSEB_KERNEL" ]; then
        echo -e "    Downloading MIPS BE kernel..."
        if curl -sL --fail -o "$MIPSEB_KERNEL" \
            "https://github.com/firmadyne/kernel-v2.6/releases/download/v1.1/vmlinux.mipseb" 2>/dev/null; then
            if [ -s "$MIPSEB_KERNEL" ]; then
                echo -e "${GREEN}    ✓ Downloaded vmlinux.mipseb${NC}"
            fi
        fi
    else
        echo -e "${GREEN}    ✓ MIPS BE kernel already present${NC}"
    fi
}

# =============================================================================
# Step 3: Download DVRF Firmware
# =============================================================================
download_dvrf() {
    echo -e "\n${CYAN}[3/5] Setting up DVRF firmware...${NC}"

    mkdir -p "$FIRMWARE_DIR"
    mkdir -p "$DVRF_DIR"

    if [ -d "$DVRF_DIR/.git" ]; then
        echo -e "${GREEN}    ✓ DVRF repository already cloned${NC}"
        echo -e "    Updating repository..."
        cd "$DVRF_DIR" && git pull --quiet 2>/dev/null || true
    else
        echo -e "    Cloning DVRF repository..."
        if git clone --quiet https://github.com/praetorian-inc/DVRF.git "$DVRF_DIR" 2>/dev/null; then
            echo -e "${GREEN}    ✓ DVRF cloned successfully${NC}"
        else
            echo -e "${YELLOW}    ⚠ Could not clone DVRF (repository may be archived)${NC}"
            echo -e "    Downloading as archive..."
            curl -sL -o /tmp/dvrf.zip "https://github.com/praetorian-inc/DVRF/archive/refs/heads/master.zip" && \
            unzip -q /tmp/dvrf.zip -d "$FIRMWARE_DIR" && \
            mv "$FIRMWARE_DIR/DVRF-master" "$DVRF_DIR" 2>/dev/null || true
            rm -f /tmp/dvrf.zip
        fi
    fi

    # List firmware files
    if [ -d "$DVRF_DIR/Firmware" ]; then
        echo -e "\n${CYAN}    Available DVRF firmware images:${NC}"
        ls -la "$DVRF_DIR/Firmware/"*.bin 2>/dev/null | while read line; do
            echo -e "    $line"
        done
    fi
}

# =============================================================================
# Step 4: Install Additional Dependencies
# =============================================================================
install_dependencies() {
    echo -e "\n${CYAN}[4/5] Checking additional dependencies...${NC}"

    # Check for binwalk
    if command -v binwalk &> /dev/null; then
        echo -e "${GREEN}    ✓ binwalk installed${NC}"
    else
        echo -e "${YELLOW}    Installing binwalk...${NC}"
        if check_sudo; then
            apt-get install -y binwalk
        else
            echo -e "${YELLOW}    Run: sudo apt-get install binwalk${NC}"
        fi
    fi

    # Check for squashfs-tools
    if command -v unsquashfs &> /dev/null; then
        echo -e "${GREEN}    ✓ squashfs-tools installed${NC}"
    else
        echo -e "${YELLOW}    Installing squashfs-tools...${NC}"
        if check_sudo; then
            apt-get install -y squashfs-tools
        else
            echo -e "${YELLOW}    Run: sudo apt-get install squashfs-tools${NC}"
        fi
    fi

    # Check for GDB multiarch (for debugging)
    if command -v gdb-multiarch &> /dev/null; then
        echo -e "${GREEN}    ✓ gdb-multiarch installed${NC}"
    else
        echo -e "${YELLOW}    Installing gdb-multiarch for debugging...${NC}"
        if check_sudo; then
            apt-get install -y gdb-multiarch
        else
            echo -e "${YELLOW}    Run: sudo apt-get install gdb-multiarch${NC}"
        fi
    fi
}

# =============================================================================
# Step 5: Create DVRF Configuration
# =============================================================================
create_config() {
    echo -e "\n${CYAN}[5/5] Creating DVRF emulation configuration...${NC}"

    DVRF_CONFIG="$PROJECT_ROOT/configs/dvrf_emulation.yaml"
    cat > "$DVRF_CONFIG" << 'EOF'
# DVRF (Damn Vulnerable Router Firmware) Emulation Configuration
# This config is optimized for emulating DVRF on EmberScan
#
# Target: Linksys E1550 Router
# Architecture: MIPS Little Endian (mipsel)
# Project: https://github.com/praetorian-inc/DVRF

project_name: DVRF-Emulation

workspace_dir: ./workspace/dvrf

log_level: DEBUG

# QEMU settings optimized for DVRF
qemu:
  # Increased timeout for slower emulation startup
  timeout: 600

  # Memory - DVRF works with 256MB
  memory: 256

  # Enable networking for web interface testing
  enable_network: true
  network_mode: user

  # Kernel directory (relative to project root)
  kernel_dir: ./kernels

  # Enable snapshot for faster reset during fuzzing
  snapshot: true

  # Debug settings for GDB attachment
  debug_port: 1234

  # Port forwarding
  # DVRF exposes a web interface on port 80
  http_forward_port: 8080
  ssh_forward_port: 2222
  telnet_forward_port: 2323

# Scanner settings for DVRF analysis
scanner:
  enabled_scanners:
    - web           # Web interface vulnerabilities (DVRF has several)
    - binary        # Binary analysis (pwnable binaries)
    - credentials   # Default credential discovery
    - crypto        # Cryptographic issues

  parallel_scans: 2
  timeout_per_scan: 900
  max_depth: 10
  follow_redirects: true
  user_agent: "EmberScan/1.0 DVRF-Analysis"

# Firmware extraction settings
extractor:
  auto_detect: true
  max_extraction_depth: 5
  supported_formats:
    - squashfs
    - cramfs
    - jffs2
  temp_dir: /tmp/emberscan-dvrf

# Report settings
reporter:
  output_formats:
    - html
    - json
  output_dir: ./reports/dvrf
  include_evidence: true
  severity_threshold: low

# DVRF-specific pwnable binaries to analyze
# These are the intentionally vulnerable binaries in DVRF
dvrf_targets:
  pwnable_binaries:
    - stack_bof_01
    - socket_bof
    - uClibc_nfp_update
  web_interfaces:
    - /cgi-bin/
    - /HNAP1/
EOF

    echo -e "${GREEN}    ✓ Created $DVRF_CONFIG${NC}"
}

# =============================================================================
# Print Usage Instructions
# =============================================================================
print_usage() {
    echo -e "\n${GREEN}╔════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║           Router Emulation Setup Complete!                         ║${NC}"
    echo -e "${GREEN}╚════════════════════════════════════════════════════════════════════╝${NC}"

    echo -e "\n${CYAN}Next Steps:${NC}"
    echo -e ""
    echo -e "${YELLOW}1. Emulate any router firmware:${NC}"
    echo -e "   emberscan emulate <firmware.bin> --display console"
    echo -e "   # Router mode is auto-detected, or force with --router-mode"
    echo -e ""
    echo -e "${YELLOW}2. Example with DVRF:${NC}"
    echo -e "   emberscan emulate firmware/DVRF/Firmware/DVRF_v03.bin --display console"
    echo -e ""
    echo -e "${YELLOW}3. For debugging with GDB:${NC}"
    echo -e "   emberscan emulate <firmware.bin> --debug"
    echo -e "   # In another terminal:"
    echo -e "   gdb-multiarch -ex 'target remote localhost:1234'"
    echo -e ""
    echo -e "${YELLOW}4. Access emulated web interface:${NC}"
    echo -e "   http://localhost:8080 (after boot)"
    echo -e ""
    echo -e "${CYAN}Supported Router Firmware:${NC}"
    echo -e "   - DVRF (Damn Vulnerable Router Firmware)"
    echo -e "   - Linksys (E-series, WRT-series)"
    echo -e "   - TP-Link, D-Link, Netgear, ASUS"
    echo -e "   - OpenWrt, DD-WRT based firmware"
    echo -e ""
    echo -e "${CYAN}Resources:${NC}"
    echo -e "   DVRF: https://github.com/praetorian-inc/DVRF"
    echo -e "   EmberScan: https://github.com/emberscan/emberscan"
    echo -e ""
}

# =============================================================================
# Main
# =============================================================================
main() {
    cd "$PROJECT_ROOT"

    install_qemu || true
    download_kernels
    download_dvrf
    install_dependencies
    create_config
    print_usage
}

main "$@"
