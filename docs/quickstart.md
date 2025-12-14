# Quick Start Guide

This guide will help you get started with EmberScan in under 5 minutes.

## Installation

### Option 1: pip (Recommended)

```bash
pip install emberscan
```

### Option 2: From Source

```bash
git clone https://github.com/emberscan/emberscan.git
cd emberscan
pip install -e .
```

### Install System Dependencies

**Ubuntu/Debian:**
```bash
sudo apt install binwalk squashfs-tools qemu-system-mips qemu-system-arm nmap
```

**Or use the installation script:**
```bash
sudo ./scripts/install_linux.sh
```

## Verify Installation

```bash
emberscan check-deps
```

## Your First Scan

### 1. Basic Firmware Scan

```bash
emberscan scan firmware.bin
```

This will:
- Extract the firmware filesystem
- Analyze binaries and configurations
- Attempt QEMU emulation
- Run all vulnerability scanners
- Generate HTML and JSON reports

### 2. Static Analysis Only

If you don't need emulation:

```bash
emberscan scan firmware.bin --static-only
```

### 3. Extract Firmware

Just extract without scanning:

```bash
emberscan extract firmware.bin --output ./extracted
```

### 4. Analyze Firmware

Get information about a firmware image:

```bash
emberscan extract firmware.bin --analyze-only
```

Example output:
```
Analysis Results:
  File size:    16,777,216 bytes
  Architecture: mipsel
  Filesystem:   squashfs
  Entropy:      6.42

  Components found: 5
    - 0x20: TP-Link Firmware Header
    - 0x1000: U-Boot uImage Header
    - 0x20000: LZMA Compressed
    - 0x180000: SquashFS (Little Endian)
```

## Reading from SPI Flash

If you have hardware access:

```bash
# Connect CH341A programmer
emberscan spi-read --output firmware_dump.bin

# Then scan the dump
emberscan scan firmware_dump.bin
```

## Interactive Emulation

For manual testing:

```bash
emberscan emulate extracted/squashfs-root --http-port 8080
```

Then access the web interface at `http://localhost:8080`

## Understanding Results

### Severity Levels

| Level | Description | Action |
|-------|-------------|--------|
| **CRITICAL** | Exploitable remotely, immediate risk | Fix immediately |
| **HIGH** | Serious vulnerability | Fix in next release |
| **MEDIUM** | Moderate risk | Plan to fix |
| **LOW** | Minor issue | Consider fixing |
| **INFO** | Informational | Review |

### Report Files

After scanning, find reports in `./emberscan_reports/<session-id>/`:

- `report.html` - Interactive HTML report
- `report.json` - Machine-readable JSON
- `report.sarif` - For CI/CD integration

## Configuration

Create `emberscan.yaml` for custom settings:

```yaml
workspace_dir: ./workspace
log_level: INFO

qemu:
  timeout: 300
  memory: 256

scanner:
  enabled_scanners:
    - web
    - network
    - binary
    - credentials
    - cve

reporter:
  output_formats:
    - html
    - json
```

## Next Steps

- Read the [User Guide](user-guide.md) for detailed usage
- Check [Scanner Reference](scanners.md) for vulnerability details
- See [Plugin Development](plugins.md) to extend EmberScan

## Common Issues

### "Firmware failed to boot"

- Some firmware requires specific hardware
- Try `--static-only` for analysis without emulation

### "Missing dependencies"

Run `emberscan check-deps` and install missing tools

### "Extraction failed"

- Firmware may be encrypted
- Check entropy analysis results
- Try manual extraction with binwalk

## Getting Help

- [GitHub Issues](https://github.com/emberscan/emberscan/issues)
- [Documentation](https://emberscan.readthedocs.io)
