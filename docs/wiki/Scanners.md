# Security Scanners

EmberScan includes multiple specialized scanners for comprehensive firmware security analysis.

## Available Scanners

| Scanner | Type | Description |
|---------|------|-------------|
| `credentials` | Static | Hardcoded credentials, API keys, private keys |
| `binary` | Static | Binary security analysis, backdoors |
| `crypto` | Static | Cryptographic implementation issues |
| `web` | Dynamic | Web interface vulnerabilities |
| `network` | Dynamic | Network service security |
| `cve` | Static | CVE database correlation |

## Credential Scanner

Scans for hardcoded credentials and secrets in firmware.

### What It Detects

- **Password Files**: Analysis of `/etc/passwd` and `/etc/shadow`
  - Empty passwords
  - Weak/common passwords (attempts to crack against wordlist)
  - Password hashes in passwd file (should be in shadow)

- **Hardcoded Credentials**:
  - Passwords in configuration files
  - API keys and tokens
  - AWS access keys and secrets
  - Database connection strings

- **Private Keys**:
  - RSA, DSA, EC private keys
  - OpenSSH private keys
  - PGP private keys
  - Unencrypted vs encrypted keys

### File Types Scanned

| Category | Extensions/Patterns |
|----------|-------------------|
| Config files | `.conf`, `.cfg`, `.ini`, `.xml`, `.json`, `.yaml`, `.yml` |
| Scripts | `.sh`, `.lua`, `.pl`, `.py`, `.php` |
| Web files | `.html`, `.js`, `.cgi` |
| Key files | `.pem`, `.key`, `.p12`, `.pfx` |

### False Positive Reduction

The scanner intelligently filters out:
- Help text and UI strings (e.g., "password: Retype...")
- Error messages and prompts
- System binaries (passwd, login, su, etc.)
- ELF binaries in system directories
- Common placeholder values

### Example Findings

```
[CRITICAL] Empty Password: root
  File: etc/shadow
  Description: User 'root' has empty password hash

[CRITICAL] Private Key Found: RSA
  File: etc/ssl/private/server.key
  Key type: RSA, Encrypted: False

[HIGH] Hardcoded Password
  File: etc/config/system
  Pattern match: password = admin123
```

---

## Binary Scanner

Analyzes compiled binaries for security issues.

### What It Detects

- **Dangerous Functions**:
  - `strcpy`, `strcat` (buffer overflow risks)
  - `sprintf`, `gets` (format string vulnerabilities)
  - `system`, `popen` (command injection)

- **Security Features**:
  - Stack canaries
  - ASLR (PIE)
  - NX bit (non-executable stack)
  - RELRO

- **Backdoors/Suspicious Code**:
  - Hidden shell commands
  - Hardcoded IP addresses
  - Suspicious strings

- **SUID/SGID Binaries**:
  - Privileged binaries
  - Potential privilege escalation

### Example Findings

```
[HIGH] Dangerous Function: strcpy
  File: usr/bin/httpd
  Description: Buffer overflow risk from strcpy usage

[MEDIUM] Missing Stack Canary
  File: usr/sbin/telnetd
  Description: Binary compiled without stack protection

[HIGH] SUID Binary
  File: usr/bin/busybox
  Description: SUID bit set on busybox
```

---

## Crypto Scanner

Identifies cryptographic implementation issues.

### What It Detects

- **Weak Algorithms**:
  - MD5, SHA1 for password hashing
  - DES, 3DES encryption
  - RC4 cipher

- **Key Management**:
  - Hardcoded encryption keys
  - Weak key derivation
  - Insecure random number generation

- **Certificate Issues**:
  - Self-signed certificates
  - Expired certificates
  - Weak signature algorithms

### Example Findings

```
[HIGH] Weak Hash Algorithm: MD5
  File: usr/lib/libcrypto.so
  Description: MD5 used for password hashing

[MEDIUM] Self-Signed Certificate
  File: etc/ssl/certs/server.crt
  Description: Certificate is self-signed
```

---

## Web Scanner

Tests web interfaces for vulnerabilities (requires emulation).

### What It Detects

- **Injection Vulnerabilities**:
  - Command injection
  - SQL injection
  - XSS (Cross-Site Scripting)

- **Authentication Issues**:
  - Default credentials
  - Missing authentication
  - Session management flaws

- **Configuration**:
  - Directory listing
  - Debug mode enabled
  - Information disclosure

### Prerequisites

- Firmware must be emulated successfully
- Web interface must be accessible

### Example Findings

```
[CRITICAL] Command Injection
  URL: /cgi-bin/firmware_upgrade.cgi
  Parameter: filename
  Description: OS command injection in filename parameter

[HIGH] Default Credentials
  URL: /login.html
  Description: Default admin/admin credentials accepted
```

---

## Network Scanner

Analyzes network services and configurations.

### What It Detects

- **Open Ports**:
  - Unnecessary services
  - Debugging interfaces

- **Protocol Issues**:
  - Telnet (unencrypted)
  - FTP (unencrypted)
  - SNMPv1/v2 (weak authentication)

- **Service Configuration**:
  - Weak SSH configuration
  - Anonymous FTP
  - SNMP default communities

### Prerequisites

- Firmware must be emulated successfully
- Network services must be running

### Example Findings

```
[MEDIUM] Telnet Service Enabled
  Port: 23
  Description: Telnet transmits data unencrypted

[HIGH] SNMP Default Community
  Port: 161
  Community: public
  Description: Default SNMP community string in use
```

---

## CVE Scanner

Correlates findings with known vulnerabilities.

### Data Sources

- NVD (National Vulnerability Database)
- Embedded device CVE feeds
- Vendor security advisories

### What It Detects

- **Known Vulnerabilities**:
  - CVEs affecting detected software
  - Version-specific vulnerabilities

- **Component Matching**:
  - BusyBox versions
  - OpenSSL versions
  - Web server software

### Configuration

For better CVE matching, provide an NVD API key:

```yaml
nvd_api_key: your-api-key-here
```

### Example Findings

```
[CRITICAL] CVE-2021-42013
  Component: Apache HTTP Server
  Version: 2.4.49
  Description: Path traversal and RCE vulnerability

[HIGH] CVE-2020-8597
  Component: pppd
  Version: 2.4.5
  Description: Buffer overflow in EAP parsing
```

---

## Using Specific Scanners

### Run All Scanners (Default)

```bash
emberscan scan firmware.bin
```

### Run Specific Scanners

```bash
# Static analysis only
emberscan scan firmware.bin --scanners credentials,binary,crypto --static-only

# Web and network (requires emulation)
emberscan scan firmware.bin --scanners web,network
```

### Disable Specific Scanners

Via configuration file:

```yaml
scanner:
  enabled_scanners:
    - binary
    - credentials
    # - web      # Disabled
    # - network  # Disabled
```

## Custom Scanners

EmberScan supports custom scanner plugins. See [[API Reference]] for details on creating custom scanners.
