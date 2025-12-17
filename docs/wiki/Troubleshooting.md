# Troubleshooting Guide

Common issues and their solutions when using EmberScan.

## Extraction Issues

### "No supported filesystem found"

**Error:**
```
Extraction Failed: No supported filesystem found. Detected components: lzma, gzip.
Supported types: squashfs, cramfs, jffs2, ubifs, romfs
```

**Causes:**
1. Firmware uses encrypted/compressed outer layer
2. Proprietary filesystem format
3. Custom compression

**Solutions:**

1. **Install additional extraction tools:**
   ```bash
   sudo apt install binwalk squashfs-tools mtd-utils
   pip install jefferson ubi_reader
   ```

2. **Try manual extraction with binwalk:**
   ```bash
   binwalk -e firmware.bin
   cd _firmware.bin.extracted
   ls
   ```

3. **Check for encryption:**
   ```bash
   emberscan extract firmware.bin --analyze-only
   ```
   If entropy > 7.9, firmware may be encrypted.

### "unsquashfs: command not found"

**Solution:**
```bash
# Ubuntu/Debian
sudo apt install squashfs-tools

# Fedora/RHEL
sudo dnf install squashfs-tools

# macOS
brew install squashfs
```

### "sasquatch required for non-standard SquashFS"

Some routers (TP-Link, D-Link) use modified SquashFS variants.

**Solution:**
```bash
git clone https://github.com/devttys0/sasquatch.git
cd sasquatch
./build.sh
sudo cp sasquatch /usr/local/bin/
```

### Permission Denied During Extraction

**Error:**
```
PermissionError: [Errno 13] Permission denied: '/tmp/emberscan/...'
```

**Solution:**
```bash
# Fix temp directory permissions
sudo chmod -R 755 /tmp/emberscan

# Or use a different temp directory in config:
extractor:
  temp_dir: /home/user/emberscan_temp
```

---

## Kernel Download Issues

### "HTTP Error 404: Not Found"

**Error:**
```
Failed to download mipsel kernel: HTTP Error 404: Not Found
```

**Cause:** Old kernel URLs that no longer exist.

**Solution:** Update to latest EmberScan version which uses correct URLs:
```bash
pip install --upgrade emberscan
```

Or manually download from [firmadyne releases](https://github.com/firmadyne/kernel-v2.6/releases):
```bash
mkdir -p kernels
wget -O kernels/vmlinux.mipsel https://github.com/firmadyne/kernel-v2.6/releases/download/v1.1/vmlinux.mipsel
wget -O kernels/vmlinux.mipseb https://github.com/firmadyne/kernel-v2.6/releases/download/v1.1/vmlinux.mipseb
wget -O kernels/zImage.armel https://github.com/firmadyne/kernel-v4.1/releases/download/v1.1/zImage.armel
```

### Network Timeout During Download

**Solution:**
```bash
# Retry with increased timeout
export EMBERSCAN_DOWNLOAD_TIMEOUT=120
emberscan download-kernels
```

---

## Emulation Issues

### "Kernel not found"

**Error:**
```
KernelNotFoundError: Kernel not found: vmlinux.mipsel
```

**Solution:**
```bash
# Download kernels first
emberscan download-kernels

# Verify kernels exist
ls -la kernels/
```

### "QEMU binary not found"

**Error:**
```
QEMUNotFoundError: QEMU binary not found: qemu-system-mipsel
```

**Solution:**
```bash
# Ubuntu/Debian
sudo apt install qemu-system-mips qemu-system-arm qemu-system-x86

# Fedora/RHEL
sudo dnf install qemu-system-mips qemu-system-arm qemu-system-x86
```

### Firmware Boot Timeout

**Error:**
```
Boot timeout after 300s - firmware may not be fully functional
```

**Causes:**
1. Architecture mismatch
2. Missing hardware emulation
3. Firmware requires specific bootloader

**Solutions:**

1. **Specify correct architecture:**
   ```bash
   emberscan emulate firmware.bin --arch mipsel
   ```

2. **Increase timeout:**
   ```yaml
   qemu:
     timeout: 600
   ```

3. **Try static analysis only:**
   ```bash
   emberscan scan firmware.bin --static-only
   ```

### Cannot Access Web Interface

**Issue:** Emulation starts but http://localhost:8080 doesn't respond.

**Solutions:**

1. **Check if services are running:**
   ```bash
   # After emulation starts, wait for boot
   curl http://localhost:8080
   ```

2. **Try different port:**
   ```bash
   emberscan emulate firmware.bin --http-port 9090
   ```

3. **Check QEMU process:**
   ```bash
   ps aux | grep qemu
   ```

---

## Scanning Issues

### Too Many False Positives in Credential Scanner

**Issue:** Scanner reports help text as hardcoded passwords.

**Solution:** Update to latest version which includes improved false positive filtering:
```bash
pip install --upgrade emberscan
```

The latest version filters out:
- System binaries (passwd, login, etc.)
- UI strings and prompts
- Error messages
- ELF binaries

### Scan Takes Too Long

**Solutions:**

1. **Use static analysis only:**
   ```bash
   emberscan scan firmware.bin --static-only
   ```

2. **Reduce scanners:**
   ```bash
   emberscan scan firmware.bin --scanners credentials,binary
   ```

3. **Reduce timeout:**
   ```bash
   emberscan scan firmware.bin --timeout 600
   ```

### "Scanner Error: Unknown scanner"

**Error:**
```
ScannerError: Unknown scanner: unknown_scanner
```

**Solution:** Use valid scanner names:
- `web`
- `network`
- `binary`
- `credentials`
- `crypto`
- `cve`

---

## Report Issues

### Reports Saved to Wrong Directory

**Issue:** CLI shows different path than where reports are saved.

**Solution:** Update to latest version:
```bash
pip install --upgrade emberscan
```

The `-o` flag now correctly saves reports to the specified directory.

### Cannot Open HTML Report

**Issue:** Browser shows blank page or errors.

**Solutions:**

1. **Check file exists:**
   ```bash
   ls -la ./emberscan_reports/*/
   ```

2. **Try different browser:**
   ```bash
   google-chrome report.html
   # or
   firefox report.html
   ```

---

## Installation Issues

### Python Version Errors

**Error:**
```
ERROR: Package 'emberscan' requires a different Python: 3.7.0 not in '>=3.9'
```

**Solution:**
```bash
# Install Python 3.11
sudo apt install python3.11 python3.11-venv

# Create virtual environment
python3.11 -m venv venv
source venv/bin/activate
pip install emberscan
```

### Missing Dependencies

**Error:**
```
ModuleNotFoundError: No module named 'defusedxml'
```

**Solution:**
```bash
pip install defusedxml packaging
```

### Binwalk Import Error

**Error:**
```
ImportError: cannot import name 'magic' from 'binwalk'
```

**Solution:**
```bash
# Install from apt instead of pip
sudo apt install binwalk
pip uninstall binwalk
```

---

## Getting More Help

### Enable Debug Logging

```bash
emberscan --debug scan firmware.bin
```

### Check Dependencies

```bash
emberscan check-deps
```

### Report Issues

If you encounter a bug:

1. Collect debug logs:
   ```bash
   emberscan --debug scan firmware.bin 2>&1 | tee debug.log
   ```

2. Open an issue: [GitHub Issues](https://github.com/CaptHigh/emberscan/issues)

Include:
- EmberScan version (`emberscan --version`)
- Python version (`python --version`)
- Operating system
- Debug log
- Firmware type (if known)
