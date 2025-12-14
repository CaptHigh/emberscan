# EmberScan Documentation

Welcome to the EmberScan documentation. EmberScan is an automated embedded hardware firmware security scanner.

## Quick Links

- [Quick Start Guide](quickstart.md)
- [Installation Guide](installation.md)
- [User Guide](user-guide.md)
- [API Reference](api-reference.md)
- [Scanner Reference](scanners.md)
- [Plugin Development](plugins.md)
- [FAQ](faq.md)

## Overview

EmberScan automates the security analysis of embedded device firmware by:

1. **Extracting** firmware from SPI flash dumps or manufacturer files
2. **Emulating** the firmware in QEMU for dynamic analysis
3. **Scanning** for vulnerabilities using multiple specialized scanners
4. **Reporting** findings in professional formats

## Supported Devices

- **Routers**: TP-Link, D-Link, Netgear, ASUS, Linksys, Ubiquiti
- **Switches**: Cisco, Netgear, TP-Link
- **IP Cameras**: Hikvision, Dahua, Reolink
- **Access Points**: Ubiquiti, Ruckus, Aruba
- **Single Board Computers**: Raspberry Pi, Orange Pi, BeagleBone

## Architecture Support

| Architecture | QEMU Binary | Status |
|-------------|-------------|--------|
| MIPS Little Endian | qemu-system-mipsel | ✅ Full |
| MIPS Big Endian | qemu-system-mips | ✅ Full |
| ARM 32-bit | qemu-system-arm | ✅ Full |
| ARM 64-bit | qemu-system-aarch64 | ✅ Full |
| x86 | qemu-system-i386 | ✅ Full |
| x86_64 | qemu-system-x86_64 | ✅ Full |
| PowerPC | qemu-system-ppc | ⚠️ Partial |

## Vulnerability Categories

EmberScan detects vulnerabilities in these categories:

### Web Interface
- Command injection
- Authentication bypass
- Default credentials
- Path traversal
- XSS, CSRF, SQLi

### Network Services
- Insecure protocols (Telnet, FTP)
- Weak SSH configurations
- Default SNMP communities
- Open debug ports

### Binary Analysis
- Dangerous function usage
- SUID/SGID binaries
- Missing security hardening
- Backdoor indicators

### Credentials
- Hardcoded passwords
- API keys and tokens
- Private keys
- Weak password hashes

### Cryptography
- Weak algorithms
- Hardcoded keys
- Self-signed certificates

## Getting Started

```bash
# Install EmberScan
pip install emberscan

# Scan firmware
emberscan scan firmware.bin

# View help
emberscan --help
```

## License

EmberScan is released under the MIT License.
