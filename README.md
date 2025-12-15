# EmberScan 🔥
## **THIS PROJECT IS WORK IN PROGRESS**
[![Python Version](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Build Status](https://img.shields.io/github/actions/workflow/status/emberscan/emberscan/ci.yml?branch=main)](https://github.com/CaptHigh/emberscan/actions)

**EmberScan** is an automated embedded hardware firmware security scanner that extracts, emulates, and analyzes firmware from routers, switches, IP cameras, SBCs, and other IoT/embedded devices.

<p align="center">
  <img src="docs/images/emberscan-demo.gif" alt="EmberScan Demo" width="800">
</p>

## 🌟 Features

- **🔬 Firmware Extraction** - Extract firmware from SPI flash dumps and manufacturer files
- **🖥️ QEMU Emulation** - Emulate firmware across MIPS, ARM, x86, PowerPC architectures
- **🔍 Vulnerability Scanning** - Comprehensive security analysis similar to Nessus/Nikto
- **📊 CVE Correlation** - Match findings against known CVE database
- **📝 Professional Reports** - HTML, JSON, and SARIF format reports
- **🔌 Plugin System** - Extensible architecture for custom scanners

## 📋 Table of Contents

- [Installation](#-installation)
- [Quick Start](#-quick-start)
- [Usage](#-usage)
- [Supported Devices](#-supported-devices)
- [Architecture](#-architecture)
- [Configuration](#-configuration)
- [Development](#-development)
- [Contributing](#-contributing)
- [License](#-license)

## 🚀 Installation

### Prerequisites

**System Dependencies (Ubuntu/Debian):**

```bash
# Install required tools
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
    python3-dev

# Optional: Install sasquatch for non-standard SquashFS
git clone https://github.com/devttys0/sasquatch.git
cd sasquatch && ./build.sh && sudo cp sasquatch /usr/local/bin/
```

### Install EmberScan

**From PyPI:**
```bash
pip install emberscan
```

**From Source:**
```bash
git clone https://github.com/CaptHigh/emberscan.git
cd emberscan
pip install -e ".[dev]"
```

**Using Docker:**
```bash
docker pull CaptHigh/emberscan:latest
docker run -v $(pwd)/firmware:/data emberscan scan /data/firmware.bin
```

### Verify Installation

```bash
emberscan check-deps
```

## ⚡ Quick Start

### 1. Scan Firmware

```bash
# Basic scan
emberscan scan firmware.bin

# Full scan with all features
emberscan scan firmware.bin --output ./reports --format html,json

# Static analysis only (no emulation)
emberscan scan firmware.bin --static-only
```

### 2. Extract & Analyze

```bash
# Extract firmware filesystem
emberscan extract firmware.bin --output ./extracted

# Analyze without extraction
emberscan extract firmware.bin --analyze-only
```

### 3. Emulate Firmware

```bash
# Start emulation with web interface
emberscan emulate firmware.bin --http-port 8080

# Then access: http://localhost:8080
```

### 4. Read from SPI Flash

```bash
# Connect CH341A programmer and read flash
emberscan spi-read --programmer ch341a_spi --output dump.bin
```

## 📖 Usage

### Complete Workflow

```bash
# Step 1: Extract firmware from physical device
emberscan spi-read --output device_dump.bin

# Step 2: Analyze and extract filesystem
emberscan extract device_dump.bin --output ./extracted

# Step 3: Run security scan
emberscan scan device_dump.bin --output ./reports

# Step 4: (Optional) Interactive emulation for manual testing
emberscan emulate ./extracted/squashfs-root --http-port 8080
```

### CLI Reference

```
emberscan <command> [options]

Commands:
  scan            Scan firmware for vulnerabilities
  extract         Extract firmware filesystem
  emulate         Emulate firmware in QEMU
  spi-read        Read firmware from SPI flash chip
  check-deps      Check installed dependencies
  download-kernels Download QEMU emulation kernels

Global Options:
  -c, --config    Path to configuration file
  -q, --quiet     Suppress banner output
  --debug         Enable debug logging
  -v, --version   Show version
```

### Python API

```python
from emberscan import EmberScanner, Config

# Initialize scanner
config = Config.load('emberscan.yaml')
scanner = EmberScanner(config)

# Run scan
session = scanner.scan_firmware(
    firmware_path='firmware.bin',
    session_name='Router Security Audit',
    scanners=['web', 'network', 'binary', 'credentials'],
    skip_emulation=False
)

# Access results
print(f"Found {len(session.all_vulnerabilities)} vulnerabilities")

for vuln in session.all_vulnerabilities:
    print(f"[{vuln.severity.value}] {vuln.title}")
    print(f"  {vuln.description}")
    print(f"  File: {vuln.file_path}")
```

## 🎯 Supported Devices

| Device Type | Vendors | Status |
|-------------|---------|--------|
| **Routers** | TP-Link, D-Link, Netgear, ASUS, Linksys, Ubiquiti, MikroTik | ✅ Full Support |
| **Switches** | Cisco, Netgear, TP-Link | ✅ Full Support |
| **IP Cameras** | Hikvision, Dahua, Reolink, Wyze | ✅ Full Support |
| **Access Points** | Ubiquiti, Ruckus, Aruba | ✅ Full Support |
| **NAS Devices** | QNAP, Synology, WD | ⚠️ Partial |
| **SBCs** | Raspberry Pi, Orange Pi, BeagleBone | ✅ Full Support |

### Supported Architectures

- MIPS (Big/Little Endian)
- ARM / ARM64 (AArch64)
- x86 / x86_64
- PowerPC

### Supported Filesystems

- SquashFS (including non-standard variants)
- JFFS2
- CramFS
- UBIFS
- RomFS
- ext2/ext4

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         EmberScan                               │
├─────────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐              │
│  │   CLI       │  │   Python    │  │   REST API  │  Interfaces  │
│  │   Interface │  │   API       │  │   (Future)  │              │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘              │
│         │                │                │                      │
│  ┌──────▼────────────────▼────────────────▼──────┐              │
│  │              Core Orchestrator                 │              │
│  │         (emberscan/core/scanner.py)           │              │
│  └──────┬─────────────┬─────────────┬────────────┘              │
│         │             │             │                           │
│  ┌──────▼──────┐ ┌────▼────┐ ┌──────▼──────┐                   │
│  │  Extractors │ │Emulators│ │  Scanners   │                   │
│  ├─────────────┤ ├─────────┤ ├─────────────┤                   │
│  │ • Firmware  │ │ • QEMU  │ │ • Web       │                   │
│  │ • SPI Flash │ │ • ARM   │ │ • Network   │                   │
│  │ • UART     │ │ • MIPS  │ │ • Binary    │                   │
│  │ • JTAG     │ │ • x86   │ │ • CVE       │                   │
│  └─────────────┘ └─────────┘ │ • Credential│                   │
│                              │ • Crypto    │                   │
│                              └──────┬──────┘                   │
│                                     │                          │
│  ┌──────────────────────────────────▼──────────────────┐       │
│  │                    Reporters                         │       │
│  │    HTML  │  JSON  │  SARIF  │  PDF (Future)        │       │
│  └──────────────────────────────────────────────────────┘       │
└─────────────────────────────────────────────────────────────────┘
```

## ⚙️ Configuration

Create `emberscan.yaml`:

```yaml
# EmberScan Configuration

# Workspace settings
workspace_dir: ./workspace
log_level: INFO

# QEMU Emulation
qemu:
  timeout: 300
  memory: 256
  kernel_dir: ./kernels
  network_mode: user
  http_forward_port: 8080
  ssh_forward_port: 2222

# Scanner settings
scanner:
  enabled_scanners:
    - web
    - network
    - binary
    - cve
    - credentials
    - crypto
  parallel_scans: 4
  timeout_per_scan: 600

# Extraction settings
extractor:
  auto_detect: true
  max_extraction_depth: 5

# Report settings
reporter:
  output_formats:
    - html
    - json
  output_dir: ./reports
  include_evidence: true
  severity_threshold: low

# CVE Database
cve_database: ./data/cve_database.json
nvd_api_key: null  # Optional: Your NVD API key

# Plugins
plugins_dir: ./plugins
enabled_plugins: []
```

## 🔌 Scanners

| Scanner | Description | Checks |
|---------|-------------|--------|
| **web** | Web interface security | Command injection, XSS, SQLi, path traversal, default credentials |
| **network** | Network service security | Open ports, weak protocols, SNMP, SSH config |
| **binary** | Binary analysis | Dangerous functions, SUID/SGID, backdoors, hardening |
| **credentials** | Credential discovery | Hardcoded passwords, API keys, private keys, weak hashes |
| **cve** | CVE correlation | Known vulnerabilities, version matching |
| **crypto** | Cryptographic issues | Weak algorithms, key management |

## 🧪 Development

### Setup Development Environment

```bash
# Clone repository
git clone https://github.com/emberscan/emberscan.git
cd emberscan

# Create virtual environment
python -m venv venv
source venv/bin/activate

# Install in development mode
pip install -e ".[dev]"

# Install pre-commit hooks
pre-commit install
```

### Run Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=emberscan --cov-report=html

# Run specific test file
pytest tests/test_scanner.py -v
```

### Code Quality

```bash
# Format code
black emberscan tests
isort emberscan tests

# Lint
flake8 emberscan tests
mypy emberscan
```

### Building

```bash
# Build package
python -m build

# Build Docker image
docker build -t emberscan:latest .
```

## 🤝 Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Areas for Contribution

- [ ] New device/vendor support
- [ ] Additional vulnerability checks
- [ ] Performance improvements
- [ ] Documentation improvements
- [ ] Bug fixes

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚠️ Disclaimer

EmberScan is designed for **authorized security testing only**. Users are responsible for ensuring they have proper authorization before scanning any devices or firmware. Unauthorized access to computer systems is illegal.

## 🙏 Acknowledgments

- [Firmadyne](https://github.com/firmadyne/firmadyne) - Firmware emulation framework
- [Binwalk](https://github.com/ReFirmLabs/binwalk) - Firmware extraction tool
- [QEMU](https://www.qemu.org/) - Machine emulation
- [Sasquatch](https://github.com/devttys0/sasquatch) - SquashFS extraction

## 📞 Support

- **Documentation**: [emberscan.readthedocs.io](https://emberscan.readthedocs.io)
- **Issues**: [GitHub Issues](https://github.com/CaptHigh/emberscan/issues)
- **Discussions**: [GitHub Discussions](https://github.com/CaptHigh/emberscan/discussions)

---

<p align="center">
  Made with ❤️ for the security community
</p>
