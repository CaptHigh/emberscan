# Router Firmware Emulation Guide

This guide explains how to set up and run router firmware emulation with EmberScan.

## Overview

EmberScan supports QEMU-based emulation for embedded router firmware. The emulation system automatically:
- Detects router firmware and enables appropriate emulation mode
- Sets up NVRAM emulation for firmware that requires it
- Patches hardware-specific scripts that would fail in emulation
- Configures serial console access

### Supported Firmware Types
- Linksys (E-series, WRT-series)
- TP-Link, D-Link, Netgear, ASUS
- OpenWrt and DD-WRT based firmware
- DVRF (Damn Vulnerable Router Firmware)
- Other embedded Linux router firmware

### Supported Architectures
- MIPS Little Endian (mipsel) - Most common for routers
- MIPS Big Endian (mips)
- ARM 32-bit
- ARM64 (aarch64)

## Quick Start

### 1. Run the Setup Script

```bash
# From the EmberScan project root
sudo ./scripts/setup_dvrf_emulation.sh
```

This script will:
- Install QEMU emulators
- Download pre-built kernels for MIPS/ARM
- Optionally clone DVRF for testing

### 2. Emulate Router Firmware

```bash
# Emulate any router firmware (auto-detects router mode)
emberscan emulate <firmware.bin> --display console

# Explicitly enable router mode (NVRAM emulation)
emberscan emulate <firmware.bin> --router-mode --display console
```

### 3. Access the Emulated Router

After boot completes:
- **Web Interface**: http://localhost:8080
- **Telnet**: `telnet localhost 2323`
- **SSH**: `ssh -p 2222 root@localhost`

## Manual Setup

### Install QEMU

```bash
sudo apt-get update
sudo apt-get install qemu-system-mips qemu-system-arm qemu-user-static
```

### Download Kernels

```bash
# Using EmberScan
emberscan download-kernels

# Or manually
mkdir -p kernels
curl -L -o kernels/vmlinux.mipsel \
  https://github.com/firmadyne/kernel-v2.6/releases/download/v1.1/vmlinux.mipsel
curl -L -o kernels/vmlinux.mipseb \
  https://github.com/firmadyne/kernel-v2.6/releases/download/v1.1/vmlinux.mipseb
```

## Emulation Options

### Basic Emulation

```bash
emberscan emulate firmware.bin
```

Router firmware is auto-detected based on:
- Presence of NVRAM utilities
- Web server binaries
- Router-specific directory structures

### With Interactive Console

```bash
emberscan emulate firmware.bin --display console
```

This shows the serial console output, allowing you to:
- See boot messages
- Login to the emulated system
- Run commands directly

### With GDB Debugging

```bash
# Start emulation with debugging
emberscan emulate firmware.bin --debug

# In another terminal, connect GDB
gdb-multiarch -ex "target remote localhost:1234"
```

### Custom Port Forwarding

```bash
emberscan emulate firmware.bin \
  --http-port 9080 \
  --ssh-port 9022 \
  --telnet-port 9023
```

### Force Router Mode

If auto-detection doesn't work, force router emulation mode:

```bash
emberscan emulate firmware.bin --router-mode
```

## Router Mode Features

When `--router-mode` is enabled (or auto-detected), EmberScan:

1. **NVRAM Emulation**: Creates `/etc/nvram.ini` and `/var/nvram/` with default router settings
2. **Hardware Script Patching**: Disables GPIO, LED, watchdog, and other hardware scripts
3. **Serial Console Setup**: Patches `/etc/inittab` for ttyS0 console access
4. **Init Script Patching**: Adds emulation detection markers

## DVRF Example

DVRF (Damn Vulnerable Router Firmware) is a great firmware for testing:

```bash
# Clone DVRF
git clone https://github.com/praetorian-inc/DVRF.git firmware/DVRF

# Emulate it
emberscan emulate firmware/DVRF/Firmware/DVRF_v03.bin --display console
```

DVRF contains intentionally vulnerable binaries in `/pwnable/`:

| Binary | Vulnerability Type |
|--------|-------------------|
| `stack_bof_01` | Stack buffer overflow |
| `socket_bof` | Socket-based buffer overflow |

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

3. Force router mode:
   ```bash
   emberscan emulate firmware.bin --router-mode
   ```

### NVRAM Errors

Router firmware often requires NVRAM. Use `--router-mode` to enable NVRAM emulation:

```bash
emberscan emulate firmware.bin --router-mode
```

## Architecture Reference

| Architecture | QEMU Binary | Kernel |
|-------------|-------------|---------|
| MIPS LE | qemu-system-mipsel | vmlinux.mipsel |
| MIPS BE | qemu-system-mips | vmlinux.mipseb |
| ARM | qemu-system-arm | zImage.armel |
| ARM64 | qemu-system-aarch64 | Image.aarch64 |

## Resources

- [Firmadyne Kernels](https://github.com/firmadyne/kernel-v2.6)
- [QEMU Documentation](https://www.qemu.org/docs/master/)
- [DVRF GitHub Repository](https://github.com/praetorian-inc/DVRF)
- [EmberScan Documentation](../README.md)
