# Getting Started with EmberScan

This guide will walk you through your first firmware security scan.

## Basic Workflow

```
1. Obtain Firmware → 2. Extract → 3. Scan → 4. Review Report
```

## Step 1: Obtain Firmware

### Option A: Download from Manufacturer

Most manufacturers provide firmware downloads on their support pages:

```bash
# Example: Download TP-Link firmware
wget https://static.tp-link.com/firmware_TL-WR841N_v14.bin
```

### Option B: Extract from Device (SPI Flash)

If you have physical access to the device:

```bash
# Connect CH341A programmer and read flash
emberscan spi-read --programmer ch341a_spi -o device_dump.bin
```

## Step 2: Run Your First Scan

### Quick Scan

```bash
emberscan scan firmware.bin
```

### Scan with Custom Output Directory

```bash
emberscan scan firmware.bin -o ./my_reports
```

### Static Analysis Only (No Emulation)

Faster scan without QEMU emulation:

```bash
emberscan scan firmware.bin --static-only
```

## Step 3: Understanding the Output

### Terminal Output

After a scan completes, you'll see a summary:

```
============================================================
Scan Complete: Scan_20241217_103045
============================================================

Findings Summary:
  CRITICAL: 2
  HIGH:     5
  MEDIUM:   12
  LOW:      8
  INFO:     15

  Total:   42

  Duration: 145.3 seconds

Top Vulnerabilities:

  [CRITICAL] Empty Password: root
    File: etc/shadow
    User 'root' has empty password hash in shadow file

  [CRITICAL] Private Key Found: RSA
    File: etc/ssl/private/server.key
    Private key file found in firmware: etc/ssl/private/server.key

  [HIGH] Weak Password: admin
    File: etc/shadow
    User 'admin' has a weak/common password

  ... and 39 more vulnerabilities (see report for details)

Reports saved to: /home/user/my_reports/abc123-def456/
```

### Report Files

Reports are saved in the output directory:

```
my_reports/
└── abc123-def456/
    ├── emberscan_report_abc123-def456.html   # Interactive HTML report
    └── emberscan_report_abc123-def456.json   # Machine-readable JSON
```

## Step 4: Review the Report

### HTML Report

Open the HTML report in a browser for an interactive view:

```bash
firefox my_reports/abc123-def456/emberscan_report_abc123-def456.html
```

### JSON Report

Use the JSON report for automation or integration:

```bash
cat my_reports/abc123-def456/emberscan_report_abc123-def456.json | jq '.vulnerabilities[] | select(.severity == "critical")'
```

## Common Scan Options

### Select Specific Scanners

```bash
# Only run credential and binary scanners
emberscan scan firmware.bin --scanners credentials,binary
```

### Available Scanners

| Scanner | Description |
|---------|-------------|
| `web` | Web interface vulnerabilities |
| `network` | Network service security |
| `binary` | Binary analysis and backdoors |
| `credentials` | Hardcoded passwords and keys |
| `crypto` | Cryptographic issues |
| `cve` | CVE correlation |

### Change Report Format

```bash
# Generate only JSON report
emberscan scan firmware.bin --format json

# Generate all formats
emberscan scan firmware.bin --format html,json,sarif
```

### Set Scan Timeout

```bash
# 1 hour timeout
emberscan scan firmware.bin --timeout 3600
```

## Extraction Only

To just extract firmware without scanning:

```bash
emberscan extract firmware.bin -o ./extracted
```

This is useful for:
- Manual analysis
- Using other security tools
- Debugging extraction issues

### Analyze Without Extraction

```bash
emberscan extract firmware.bin --analyze-only
```

Output:
```
Analysis Results:
  File size:    16,777,216 bytes
  Architecture: MIPS_LE
  Filesystem:   SQUASHFS
  Entropy:      5.82

  Components found: 8
    - 0x40: U-Boot uImage Header
    - 0x10000: SquashFS (Little Endian)
    - 0x800000: LZMA Compressed
```

## Emulation

### Download Kernels First

```bash
emberscan download-kernels
```

### Start Emulation

```bash
emberscan emulate firmware.bin --http-port 8080
```

Access the emulated device:
- Web: http://localhost:8080
- SSH: `ssh -p 2222 root@localhost`
- Telnet: `telnet localhost 2323`

## Next Steps

- [[CLI Reference]] - Complete command documentation
- [[Scanners]] - Detailed scanner information
- [[Troubleshooting]] - Solve common issues
