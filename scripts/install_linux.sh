#!/bin/bash
# EmberScan Installation Script for Linux (Ubuntu/Debian)
# Run with: sudo ./scripts/install_linux.sh

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

echo -e "${CYAN}"
echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║           EmberScan Installation Script                       ║"
echo "║     Automated Embedded Firmware Security Scanner              ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Please run as root (sudo)${NC}"
    exit 1
fi

# Detect distribution
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$NAME
    VER=$VERSION_ID
else
    echo -e "${RED}Cannot detect OS version${NC}"
    exit 1
fi

echo -e "${CYAN}[*] Detected: $OS $VER${NC}"

# Update package lists
echo -e "\n${CYAN}[*] Updating package lists...${NC}"
apt-get update -qq

# Install Python and pip
echo -e "\n${CYAN}[*] Installing Python...${NC}"
apt-get install -y python3 python3-pip python3-dev python3-venv

# Install firmware extraction tools
echo -e "\n${CYAN}[*] Installing firmware extraction tools...${NC}"
apt-get install -y \
    binwalk \
    squashfs-tools \
    mtd-utils \
    gzip \
    bzip2 \
    xz-utils \
    p7zip-full \
    unzip \
    cpio \
    lzop \
    liblzo2-dev \
    liblzma-dev \
    zlib1g-dev

# Install QEMU for emulation
echo -e "\n${CYAN}[*] Installing QEMU emulators...${NC}"
apt-get install -y \
    qemu-system-mips \
    qemu-system-arm \
    qemu-system-x86 \
    qemu-user-static

# Install network scanning tools
echo -e "\n${CYAN}[*] Installing network scanning tools...${NC}"
apt-get install -y \
    nmap \
    nikto \
    netcat-openbsd \
    tcpdump \
    curl \
    wget

# Install binary analysis tools
echo -e "\n${CYAN}[*] Installing binary analysis tools...${NC}"
apt-get install -y \
    binutils \
    file \
    gdb-multiarch \
    strace \
    ltrace

# Install build tools (for sasquatch)
echo -e "\n${CYAN}[*] Installing build tools...${NC}"
apt-get install -y \
    build-essential \
    git \
    autoconf \
    automake \
    libtool

# Install sasquatch for non-standard SquashFS
echo -e "\n${CYAN}[*] Installing sasquatch...${NC}"
if ! command -v sasquatch &> /dev/null; then
    TEMP_DIR=$(mktemp -d)
    cd $TEMP_DIR
    git clone https://github.com/devttys0/sasquatch.git
    cd sasquatch
    ./build.sh
    cp sasquatch /usr/local/bin/
    cd /
    rm -rf $TEMP_DIR
    echo -e "${GREEN}    sasquatch installed${NC}"
else
    echo -e "${YELLOW}    sasquatch already installed${NC}"
fi

# Install jefferson for JFFS2
echo -e "\n${CYAN}[*] Installing jefferson (JFFS2 extractor)...${NC}"
pip3 install jefferson

# Install ubi_reader for UBIFS
echo -e "\n${CYAN}[*] Installing ubi_reader...${NC}"
pip3 install ubi_reader

# Install flashrom for SPI extraction
echo -e "\n${CYAN}[*] Installing flashrom...${NC}"
apt-get install -y flashrom

# Install optional tools
echo -e "\n${CYAN}[*] Installing optional tools...${NC}"
apt-get install -y \
    radare2 \
    yara \
    ssdeep || true

# Create directories
echo -e "\n${CYAN}[*] Creating directories...${NC}"
mkdir -p /opt/emberscan/kernels
mkdir -p /opt/emberscan/data

# Download emulation kernels
echo -e "\n${CYAN}[*] Downloading emulation kernels...${NC}"
KERNEL_DIR="/opt/emberscan/kernels"

# MIPS Little Endian
if [ ! -f "$KERNEL_DIR/vmlinux.mipsel" ]; then
    echo "    Downloading MIPS LE kernel..."
    curl -sL -o "$KERNEL_DIR/vmlinux.mipsel" \
        "https://github.com/firmadyne/kernel-v4.1/raw/master/images/vmlinux.mipsel" || true
fi

# MIPS Big Endian
if [ ! -f "$KERNEL_DIR/vmlinux.mipseb" ]; then
    echo "    Downloading MIPS BE kernel..."
    curl -sL -o "$KERNEL_DIR/vmlinux.mipseb" \
        "https://github.com/firmadyne/kernel-v4.1/raw/master/images/vmlinux.mipseb" || true
fi

# ARM
if [ ! -f "$KERNEL_DIR/zImage.armel" ]; then
    echo "    Downloading ARM kernel..."
    curl -sL -o "$KERNEL_DIR/zImage.armel" \
        "https://github.com/firmadyne/kernel-v4.1/raw/master/images/zImage.armel" || true
fi

# Install EmberScan Python package
echo -e "\n${CYAN}[*] Installing EmberScan...${NC}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR/.."
pip3 install -e .

# Create symlink
ln -sf /usr/local/bin/emberscan /usr/bin/emberscan 2>/dev/null || true

# Set permissions
chmod -R 755 /opt/emberscan

# Verify installation
echo -e "\n${CYAN}[*] Verifying installation...${NC}"
emberscan check-deps

echo -e "\n${GREEN}╔═══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║           EmberScan Installation Complete!                     ║${NC}"
echo -e "${GREEN}╚═══════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "Usage:"
echo -e "  ${CYAN}emberscan scan firmware.bin${NC}        - Scan firmware"
echo -e "  ${CYAN}emberscan extract firmware.bin${NC}     - Extract filesystem"
echo -e "  ${CYAN}emberscan emulate firmware.bin${NC}     - Emulate in QEMU"
echo -e "  ${CYAN}emberscan --help${NC}                   - Show help"
echo ""
echo -e "Documentation: https://github.com/emberscan/emberscan"
echo ""
