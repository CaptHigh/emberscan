# Installation Guide

This guide covers all installation methods for EmberScan.

## Prerequisites

### System Requirements

- **Operating System**: Linux (Ubuntu 20.04+ recommended), macOS, or Windows with WSL2
- **Python**: 3.9 or higher
- **RAM**: 4GB minimum, 8GB recommended for emulation
- **Disk**: 2GB for installation, additional space for firmware analysis

### Required System Dependencies

#### Ubuntu/Debian

```bash
sudo apt update
sudo apt install -y \
    binwalk \
    squashfs-tools \
    qemu-system-mips \
    qemu-system-arm \
    qemu-system-x86 \
    nmap \
    nikto \
    flashrom \
    python3-pip \
    python3-dev \
    mtd-utils \
    gzip \
    bzip2 \
    p7zip-full \
    unrar \
    cabextract \
    lzma \
    lzop \
    cpio
```

#### Fedora/RHEL

```bash
sudo dnf install -y \
    binwalk \
    squashfs-tools \
    qemu-system-mips \
    qemu-system-arm \
    qemu-system-x86 \
    nmap \
    nikto \
    flashrom \
    python3-pip \
    python3-devel \
    mtd-utils
```

#### macOS (with Homebrew)

```bash
brew install \
    binwalk \
    squashfs \
    qemu \
    nmap \
    python@3.11
```

### Optional Dependencies

#### Sasquatch (for non-standard SquashFS)

Many firmware images use modified SquashFS variants. Install sasquatch for better extraction:

```bash
git clone https://github.com/devttys0/sasquatch.git
cd sasquatch
./build.sh
sudo cp sasquatch /usr/local/bin/
```

#### Jefferson (for JFFS2 extraction)

```bash
pip install jefferson
```

#### ubi_reader (for UBIFS extraction)

```bash
pip install ubi_reader
```

## Installation Methods

### Method 1: From PyPI (Recommended)

```bash
pip install emberscan
```

### Method 2: From Source

```bash
# Clone the repository
git clone https://github.com/CaptHigh/emberscan.git
cd emberscan

# Install in development mode
pip install -e ".[dev]"
```

### Method 3: Using Docker

```bash
# Pull the image
docker pull capthigh/emberscan:latest

# Run with firmware mounted
docker run -v $(pwd)/firmware:/data emberscan scan /data/firmware.bin
```

## Post-Installation Setup

### 1. Verify Installation

```bash
emberscan check-deps
```

This will show the status of all required dependencies:

```
EmberScan Dependency Check
==========================
binwalk:            ✓ Installed
unsquashfs:         ✓ Installed
qemu-system-mipsel: ✓ Installed
qemu-system-arm:    ✓ Installed
nmap:               ✓ Installed
nikto:              ✓ Installed
```

### 2. Download Emulation Kernels

For firmware emulation, download pre-built kernels:

```bash
emberscan download-kernels
```

This downloads kernels for MIPS and ARM architectures from the [firmadyne project](https://github.com/firmadyne/firmadyne).

### 3. Create Configuration (Optional)

Create a custom configuration file:

```bash
cat > emberscan.yaml << EOF
workspace_dir: ./workspace
log_level: INFO

qemu:
  timeout: 300
  memory: 256
  kernel_dir: ./kernels

scanner:
  enabled_scanners:
    - web
    - network
    - binary
    - credentials
    - crypto
  parallel_scans: 4

reporter:
  output_formats:
    - html
    - json
  output_dir: ./reports
EOF
```

## Troubleshooting Installation

### "binwalk: command not found"

Install binwalk:
```bash
pip install binwalk
# or
sudo apt install binwalk
```

### "unsquashfs: command not found"

Install squashfs-tools:
```bash
sudo apt install squashfs-tools
```

### "Permission denied" errors with QEMU

Add your user to the kvm group:
```bash
sudo usermod -aG kvm $USER
```
Then log out and back in.

### Python version issues

Ensure Python 3.9+ is installed:
```bash
python3 --version
```

If needed, install a newer Python version:
```bash
sudo apt install python3.11
```

## Next Steps

- [[Getting Started]] - Run your first scan
- [[CLI Reference]] - Learn all available commands
