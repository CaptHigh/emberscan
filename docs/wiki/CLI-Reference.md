# CLI Reference

Complete command-line interface documentation for EmberScan.

## Global Options

These options are available for all commands:

| Option | Description |
|--------|-------------|
| `-c, --config FILE` | Path to configuration file |
| `-q, --quiet` | Suppress banner and non-essential output |
| `--debug` | Enable debug logging |
| `-v, --version` | Show version and exit |

## Commands

### scan

Scan firmware for security vulnerabilities.

```bash
emberscan scan <firmware> [options]
```

#### Arguments

| Argument | Description |
|----------|-------------|
| `firmware` | Path to firmware file (required) |

#### Options

| Option | Description | Default |
|--------|-------------|---------|
| `-o, --output DIR` | Output directory for reports | `./emberscan_reports` |
| `-n, --name NAME` | Custom name for scan session | Auto-generated |
| `--scanners LIST` | Comma-separated list of scanners to run | All enabled |
| `--static-only` | Skip emulation, perform static analysis only | False |
| `--no-report` | Skip report generation | False |
| `--format LIST` | Report formats (html,json,sarif) | `html,json` |
| `--timeout SECONDS` | Scan timeout in seconds | 1800 |

#### Examples

```bash
# Basic scan
emberscan scan firmware.bin

# Custom output directory
emberscan scan firmware.bin -o ./custom_reports

# Static analysis only
emberscan scan firmware.bin --static-only

# Specific scanners
emberscan scan firmware.bin --scanners web,credentials,binary

# Named session with JSON output
emberscan scan firmware.bin -n "Router Security Audit" --format json
```

#### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Scan completed, no HIGH/CRITICAL findings |
| 1 | Scan completed with HIGH severity findings |
| 2 | Scan completed with CRITICAL severity findings |
| 130 | Scan interrupted by user (Ctrl+C) |

---

### extract

Extract firmware filesystem.

```bash
emberscan extract <firmware> [options]
```

#### Arguments

| Argument | Description |
|----------|-------------|
| `firmware` | Path to firmware file (required) |

#### Options

| Option | Description | Default |
|--------|-------------|---------|
| `-o, --output DIR` | Output directory for extracted files | `./extracted` |
| `--analyze-only` | Only analyze, do not extract | False |

#### Examples

```bash
# Extract firmware
emberscan extract firmware.bin -o ./extracted

# Analyze without extraction
emberscan extract firmware.bin --analyze-only
```

---

### emulate

Emulate firmware in QEMU.

```bash
emberscan emulate <firmware> [options]
```

#### Arguments

| Argument | Description |
|----------|-------------|
| `firmware` | Path to firmware file or extracted rootfs (required) |

#### Options

| Option | Description | Default |
|--------|-------------|---------|
| `--arch ARCH` | Target architecture (mipsel, mips, arm, aarch64, x86, x86_64) | Auto-detect |
| `--http-port PORT` | Host port for HTTP forwarding | 8080 |
| `--ssh-port PORT` | Host port for SSH forwarding | 2222 |
| `--telnet-port PORT` | Host port for Telnet forwarding | 2323 |
| `--memory MB` | RAM in MB | 256 |
| `--debug` | Enable GDB debugging on port 1234 | False |

#### Examples

```bash
# Basic emulation
emberscan emulate firmware.bin

# Specify architecture
emberscan emulate firmware.bin --arch mipsel

# Custom ports
emberscan emulate firmware.bin --http-port 9090 --ssh-port 2200

# Emulate extracted rootfs
emberscan emulate ./extracted/squashfs-root
```

---

### spi-read

Read firmware from SPI flash chip.

```bash
emberscan spi-read [options]
```

#### Options

| Option | Description | Default |
|--------|-------------|---------|
| `-o, --output FILE` | Output file path (required) | - |
| `--programmer TYPE` | Programmer type (ch341a_spi, buspirate_spi, etc.) | `ch341a_spi` |
| `--verify` | Verify after reading | False |

#### Supported Programmers

- `ch341a_spi` - CH341A USB programmer
- `buspirate_spi` - Bus Pirate
- `serprog` - Serial programmer
- `linux_spi` - Linux SPI interface
- `ft2232_spi` - FTDI FT2232

#### Examples

```bash
# Read with CH341A
emberscan spi-read -o dump.bin --programmer ch341a_spi

# Read with verification
emberscan spi-read -o dump.bin --verify
```

---

### download-kernels

Download pre-built emulation kernels.

```bash
emberscan download-kernels [options]
```

#### Options

| Option | Description | Default |
|--------|-------------|---------|
| `--arch ARCH` | Architecture to download (mipsel, mips, arm) | All |
| `-o, --output DIR` | Output directory | `./kernels` |

#### Examples

```bash
# Download all kernels
emberscan download-kernels

# Download specific architecture
emberscan download-kernels --arch mipsel

# Custom directory
emberscan download-kernels -o /opt/emberscan/kernels
```

#### Kernel Sources

Kernels are downloaded from the [firmadyne project](https://github.com/firmadyne/firmadyne):
- MIPS: `kernel-v2.6` releases
- ARM: `kernel-v4.1` releases

---

### check-deps

Check installed dependencies.

```bash
emberscan check-deps
```

Shows the status of all required tools:

```
EmberScan Dependency Check
==========================
binwalk:            ✓ Installed (/usr/bin/binwalk)
unsquashfs:         ✓ Installed (/usr/bin/unsquashfs)
qemu-system-mipsel: ✓ Installed (/usr/bin/qemu-system-mipsel)
qemu-system-arm:    ✓ Installed (/usr/bin/qemu-system-arm)
nmap:               ✓ Installed (/usr/bin/nmap)
nikto:              ✗ Not found
```

---

### report

Generate report from saved session (future feature).

```bash
emberscan report <session-id> [options]
```

#### Options

| Option | Description | Default |
|--------|-------------|---------|
| `-o, --output DIR` | Output directory | `./reports` |
| `--format FORMAT` | Report format (html, json, sarif) | `html` |

## Configuration File

Create `emberscan.yaml` for persistent configuration:

```yaml
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
  timeout_per_scan: 600

reporter:
  output_formats:
    - html
    - json
  output_dir: ./reports
```

Use with:
```bash
emberscan -c emberscan.yaml scan firmware.bin
```

## Environment Variables

| Variable | Description |
|----------|-------------|
| `EMBERSCAN_WORKSPACE` | Override workspace directory |
| `EMBERSCAN_LOG_LEVEL` | Set log level (DEBUG, INFO, WARNING, ERROR) |
| `EMBERSCAN_QEMU_TIMEOUT` | Override QEMU timeout |
| `EMBERSCAN_QEMU_MEMORY` | Override QEMU memory |
| `EMBERSCAN_NVD_API_KEY` | NVD API key for CVE lookups |
