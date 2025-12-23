# DVRF Emulation Guide

This guide explains how to set up and run DVRF (Damn Vulnerable Router Firmware) emulation with EmberScan.

## Overview

DVRF is a Linksys E1550 router firmware designed for security research and practice. It contains intentionally vulnerable binaries and web interfaces that can be used to learn about router exploitation.

- **Architecture**: MIPS Little Endian (mipsel)
- **Project**: https://github.com/praetorian-inc/DVRF
- **Target Device**: Linksys E1550

## Quick Start

### 1. Run the Setup Script

```bash
# From the EmberScan project root
sudo ./scripts/setup_dvrf_emulation.sh
```

This script will:
- Install QEMU emulators
- Download pre-built MIPS kernels
- Clone the DVRF repository
- Create DVRF-specific configuration

### 2. Emulate DVRF

```bash
# Extract and emulate the firmware
emberscan emulate firmware/DVRF/Firmware/DVRF_v03.bin --dvrf --display console
```

### 3. Access the Emulated Router

After boot completes:
- **Web Interface**: http://localhost:8080
- **Telnet**: `telnet localhost 2323`
- **SSH**: `ssh -p 2222 root@localhost`

## Manual Setup

If the setup script doesn't work, follow these manual steps:

### Install QEMU

```bash
sudo apt-get update
sudo apt-get install qemu-system-mips qemu-system-arm qemu-user-static
```

### Download Kernels

```bash
# Create kernels directory
mkdir -p kernels

# Download MIPS LE kernel
curl -L -o kernels/vmlinux.mipsel \
  https://github.com/firmadyne/kernel-v2.6/releases/download/v1.1/vmlinux.mipsel

# Verify download
ls -la kernels/
```

### Download DVRF

```bash
mkdir -p firmware
git clone https://github.com/praetorian-inc/DVRF.git firmware/DVRF
```

## Emulation Options

### Basic Emulation

```bash
emberscan emulate firmware/DVRF/Firmware/DVRF_v03.bin
```

### With Interactive Console

```bash
emberscan emulate firmware/DVRF/Firmware/DVRF_v03.bin --display console
```

This shows the serial console output, allowing you to:
- See boot messages
- Login to the emulated system
- Run commands directly

### With GDB Debugging

```bash
# Start emulation with debugging
emberscan emulate firmware/DVRF/Firmware/DVRF_v03.bin --debug

# In another terminal, connect GDB
gdb-multiarch -ex "target remote localhost:1234"
```

### Custom Port Forwarding

```bash
emberscan emulate firmware/DVRF/Firmware/DVRF_v03.bin \
  --http-port 9080 \
  --ssh-port 9022 \
  --telnet-port 9023
```

## DVRF Challenges

DVRF contains several pwnable binaries in `/pwnable/`:

| Binary | Vulnerability Type |
|--------|-------------------|
| `stack_bof_01` | Stack buffer overflow |
| `socket_bof` | Socket-based buffer overflow |
| `uClibc_nfp_update` | Format string vulnerability |

### Accessing Pwnable Binaries

```bash
# Connect via telnet
telnet localhost 2323

# Navigate to pwnable directory
cd /pwnable

# List challenges
ls -la

# Run a challenge
./stack_bof_01
```

## Configuration

Use the DVRF-specific configuration for full scanning:

```bash
emberscan scan firmware/DVRF/Firmware/DVRF_v03.bin \
  --config configs/dvrf_emulation.yaml
```

## Troubleshooting

### Kernel Not Found

```
Error: Kernel not found: vmlinux.mipsel
```

**Solution**: Download kernels:
```bash
emberscan download-kernels --arch mipsel
```

### QEMU Not Installed

```
Error: QEMU binary not found: qemu-system-mipsel
```

**Solution**: Install QEMU:
```bash
sudo apt-get install qemu-system-mips
```

### Boot Timeout

If the firmware doesn't boot within the timeout:

1. Try with console mode to see what's happening:
   ```bash
   emberscan emulate firmware.bin --display console
   ```

2. Increase memory:
   ```bash
   emberscan emulate firmware.bin --memory 512
   ```

3. Enable DVRF mode explicitly:
   ```bash
   emberscan emulate firmware.bin --dvrf
   ```

### NVRAM Errors

Router firmware often requires NVRAM. The `--dvrf` flag enables NVRAM emulation:

```bash
emberscan emulate firmware.bin --dvrf
```

## Architecture Reference

| Architecture | QEMU Binary | Kernel |
|-------------|-------------|---------|
| MIPS LE | qemu-system-mipsel | vmlinux.mipsel |
| MIPS BE | qemu-system-mips | vmlinux.mipseb |
| ARM | qemu-system-arm | zImage.armel |
| ARM64 | qemu-system-aarch64 | Image.aarch64 |

## Resources

- [DVRF GitHub Repository](https://github.com/praetorian-inc/DVRF)
- [Firmadyne Kernels](https://github.com/firmadyne/kernel-v2.6)
- [QEMU Documentation](https://www.qemu.org/docs/master/)
- [EmberScan Documentation](../README.md)
