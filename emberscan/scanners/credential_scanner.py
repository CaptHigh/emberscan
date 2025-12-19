"""
Credential Scanner.

Scans firmware for hardcoded credentials, API keys, and secrets:
- /etc/passwd and /etc/shadow analysis
- Hardcoded passwords in scripts and configs
- API keys and tokens
- Private keys and certificates
- Database credentials
"""

import base64
import hashlib
import os
import re
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set

from ..core.config import Config
from ..core.logger import get_logger
from ..core.models import FirmwareInfo, ScanResult, Severity, Vulnerability, VulnerabilityType
from .base import BaseScanner, ScannerRegistry

logger = get_logger(__name__)


# Patterns for credential detection
CREDENTIAL_PATTERNS = [
    # Passwords
    (r'password\s*[=:]\s*["\']?([^"\'\s]{4,})["\']?', "password", Severity.HIGH),
    (r'passwd\s*[=:]\s*["\']?([^"\'\s]{4,})["\']?', "password", Severity.HIGH),
    (r'pwd\s*[=:]\s*["\']?([^"\'\s]{4,})["\']?', "password", Severity.MEDIUM),
    (r'pass\s*[=:]\s*["\']?([^"\'\s]{4,})["\']?', "password", Severity.MEDIUM),
    # API Keys
    (r'api[_-]?key\s*[=:]\s*["\']?([a-zA-Z0-9_\-]{16,})["\']?', "api_key", Severity.HIGH),
    (r'apikey\s*[=:]\s*["\']?([a-zA-Z0-9_\-]{16,})["\']?', "api_key", Severity.HIGH),
    (r'secret[_-]?key\s*[=:]\s*["\']?([a-zA-Z0-9_\-]{16,})["\']?', "secret_key", Severity.CRITICAL),
    # Tokens
    (r'token\s*[=:]\s*["\']?([a-zA-Z0-9_\-]{16,})["\']?', "token", Severity.HIGH),
    (r'auth[_-]?token\s*[=:]\s*["\']?([a-zA-Z0-9_\-]{16,})["\']?', "auth_token", Severity.HIGH),
    (r'access[_-]?token\s*[=:]\s*["\']?([a-zA-Z0-9_\-]{16,})["\']?', "access_token", Severity.HIGH),
    # AWS
    (r"AKIA[0-9A-Z]{16}", "aws_access_key", Severity.CRITICAL),
    (
        r'aws[_-]?secret[_-]?access[_-]?key\s*[=:]\s*["\']?([a-zA-Z0-9/+=]{40})["\']?',
        "aws_secret",
        Severity.CRITICAL,
    ),
    # Database
    (r"mysql://[^:]+:([^@]+)@", "mysql_password", Severity.HIGH),
    (r"postgres://[^:]+:([^@]+)@", "postgres_password", Severity.HIGH),
    (r"mongodb://[^:]+:([^@]+)@", "mongodb_password", Severity.HIGH),
    # Private keys
    (r"-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----", "private_key", Severity.CRITICAL),
    (r"-----BEGIN PGP PRIVATE KEY BLOCK-----", "pgp_private_key", Severity.CRITICAL),
]

# Common weak/default passwords
WEAK_PASSWORDS = {
    "admin",
    "password",
    "root",
    "123456",
    "12345678",
    "admin123",
    "password123",
    "default",
    "guest",
    "user",
    "test",
    "qwerty",
    "1234",
    "administrator",
    "changeme",
    "letmein",
    "welcome",
}

# Known hash formats
HASH_PATTERNS = {
    "md5": (r"^[a-f0-9]{32}$", "MD5"),
    "sha1": (r"^[a-f0-9]{40}$", "SHA1"),
    "sha256": (r"^[a-f0-9]{64}$", "SHA256"),
    "sha512": (r"^[a-f0-9]{128}$", "SHA512"),
    "des": (r"^[a-zA-Z0-9./]{13}$", "DES"),
    "md5crypt": (r"^\$1\$[a-zA-Z0-9./]{8}\$[a-zA-Z0-9./]{22}$", "MD5-Crypt"),
    "sha256crypt": (r"^\$5\$[a-zA-Z0-9./]+\$[a-zA-Z0-9./]{43}$", "SHA256-Crypt"),
    "sha512crypt": (r"^\$6\$[a-zA-Z0-9./]+\$[a-zA-Z0-9./]{86}$", "SHA512-Crypt"),
}


@ScannerRegistry.register("credentials")
class CredentialScanner(BaseScanner):
    """
    Scanner for hardcoded credentials and secrets.
    """

    @property
    def name(self) -> str:
        return "credential_scanner"

    @property
    def scan_type(self) -> str:
        return "credentials"

    def __init__(self, config: Config):
        super().__init__(config)
        self._found_credentials: Set[str] = set()

    def scan(self, target: str, firmware: FirmwareInfo, **kwargs) -> ScanResult:
        """
        Scan firmware for hardcoded credentials.

        Args:
            target: Path to extracted rootfs
            firmware: FirmwareInfo context
        """
        result = self._create_result()
        self._start_scan(result)
        self._found_credentials.clear()

        try:
            rootfs = Path(target)

            # Phase 1: Analyze /etc/passwd and /etc/shadow
            logger.info(f"[{self.name}] Analyzing passwd/shadow files")
            passwd_vulns = self._analyze_passwd_shadow(rootfs)
            result.vulnerabilities.extend(passwd_vulns)

            # Phase 2: Search configuration files
            logger.info(f"[{self.name}] Scanning configuration files")
            config_vulns = self._scan_config_files(rootfs)
            result.vulnerabilities.extend(config_vulns)

            # Phase 3: Search scripts
            logger.info(f"[{self.name}] Scanning script files")
            script_vulns = self._scan_scripts(rootfs)
            result.vulnerabilities.extend(script_vulns)

            # Phase 4: Find private keys
            logger.info(f"[{self.name}] Searching for private keys")
            key_vulns = self._find_private_keys(rootfs)
            result.vulnerabilities.extend(key_vulns)

            # Phase 5: Search web application files
            logger.info(f"[{self.name}] Scanning web files")
            web_vulns = self._scan_web_files(rootfs)
            result.vulnerabilities.extend(web_vulns)

            # Phase 6: Check for common credential files
            logger.info(f"[{self.name}] Checking common credential locations")
            common_vulns = self._check_common_locations(rootfs)
            result.vulnerabilities.extend(common_vulns)

            result.items_scanned = len(self._found_credentials)
            self._complete_scan(result)

        except Exception as e:
            self._fail_scan(result, str(e))

        return result

    def _analyze_passwd_shadow(self, rootfs: Path) -> List[Vulnerability]:
        """Analyze /etc/passwd and /etc/shadow for weak credentials."""
        vulnerabilities = []

        passwd_path = rootfs / "etc" / "passwd"
        shadow_path = rootfs / "etc" / "shadow"

        # Parse passwd file
        users = {}
        if passwd_path.exists():
            try:
                content = passwd_path.read_text()
                for line in content.strip().split("\n"):
                    if ":" in line:
                        parts = line.split(":")
                        if len(parts) >= 7:
                            username = parts[0]
                            password_field = parts[1]
                            uid = parts[2]
                            shell = parts[6]

                            users[username] = {
                                "password_field": password_field,
                                "uid": uid,
                                "shell": shell,
                            }

                            # Check for password in passwd file (very bad)
                            if password_field and password_field not in ["x", "*", "!", "!!"]:
                                vuln = self._create_vulnerability(
                                    title=f"Password Hash in /etc/passwd: {username}",
                                    description=f"User '{username}' has password hash directly in /etc/passwd instead of /etc/shadow",
                                    severity=Severity.HIGH,
                                    vuln_type=VulnerabilityType.HARDCODED_CREDENTIALS,
                                    file_path="etc/passwd",
                                    evidence=f"Hash type: {self._identify_hash(password_field)}",
                                    remediation="Move password hashes to /etc/shadow with proper permissions",
                                )
                                vulnerabilities.append(vuln)

                            # Check for empty password
                            if password_field == "":
                                vuln = self._create_vulnerability(
                                    title=f"Empty Password: {username}",
                                    description=f"User '{username}' has no password set",
                                    severity=Severity.CRITICAL,
                                    vuln_type=VulnerabilityType.AUTHENTICATION_BYPASS,
                                    file_path="etc/passwd",
                                    remediation="Set a strong password for all users",
                                )
                                vulnerabilities.append(vuln)

            except Exception as e:
                logger.debug(f"Failed to parse passwd: {e}")

        # Parse shadow file
        if shadow_path.exists():
            try:
                content = shadow_path.read_text()
                for line in content.strip().split("\n"):
                    if ":" in line:
                        parts = line.split(":")
                        if len(parts) >= 2:
                            username = parts[0]
                            password_hash = parts[1]

                            # Check for empty/disabled passwords
                            if password_hash in ["", "*", "!", "!!", "x"]:
                                if password_hash == "":
                                    vuln = self._create_vulnerability(
                                        title=f"Empty Password in Shadow: {username}",
                                        description=f"User '{username}' has empty password hash in shadow file",
                                        severity=Severity.CRITICAL,
                                        vuln_type=VulnerabilityType.AUTHENTICATION_BYPASS,
                                        file_path="etc/shadow",
                                        remediation="Set a strong password",
                                    )
                                    vulnerabilities.append(vuln)
                            else:
                                # Try to crack common passwords
                                cracked = self._try_crack_hash(password_hash, username)
                                if cracked:
                                    vuln = self._create_vulnerability(
                                        title=f"Weak Password: {username}",
                                        description=f"User '{username}' has a weak/common password",
                                        severity=Severity.CRITICAL,
                                        vuln_type=VulnerabilityType.HARDCODED_CREDENTIALS,
                                        file_path="etc/shadow",
                                        evidence=f"Password is a common/weak password",
                                        remediation="Use a strong, unique password",
                                    )
                                    vulnerabilities.append(vuln)
                                    self._found_credentials.add(f"{username}:{cracked}")

            except PermissionError:
                pass
            except Exception as e:
                logger.debug(f"Failed to parse shadow: {e}")

        return vulnerabilities

    def _identify_hash(self, hash_str: str) -> str:
        """Identify hash type."""
        for hash_type, (pattern, name) in HASH_PATTERNS.items():
            if re.match(pattern, hash_str):
                return name
        return "Unknown"

    def _try_crack_hash(self, hash_str: str, username: str) -> Optional[str]:
        """Try to crack hash against common passwords."""
        # Try username as password
        test_passwords = list(WEAK_PASSWORDS) + [username, username + "123", username + "1"]

        for password in test_passwords:
            # MD5 crypt
            if hash_str.startswith("$1$"):
                try:
                    import crypt

                    if crypt.crypt(password, hash_str) == hash_str:
                        return password
                except:
                    pass

            # SHA512 crypt
            elif hash_str.startswith("$6$"):
                try:
                    import crypt

                    if crypt.crypt(password, hash_str) == hash_str:
                        return password
                except:
                    pass

            # Plain MD5
            elif re.match(r"^[a-f0-9]{32}$", hash_str):
                if hashlib.md5(password.encode(), usedforsecurity=False).hexdigest() == hash_str:
                    return password

        return None

    def _scan_config_files(self, rootfs: Path) -> List[Vulnerability]:
        """Scan configuration files for credentials."""
        vulnerabilities = []

        config_patterns = [
            "**/*.conf",
            "**/*.cfg",
            "**/*.ini",
            "**/*.xml",
            "**/*.json",
            "**/*.yaml",
            "**/*.yml",
            "**/*.properties",
        ]

        config_dirs = ["etc", "var", "usr/local/etc", "opt"]

        for config_dir in config_dirs:
            search_dir = rootfs / config_dir
            if not search_dir.exists():
                continue

            for pattern in config_patterns:
                for config_file in search_dir.glob(pattern):
                    if config_file.is_file():
                        vulns = self._scan_file_for_credentials(config_file, rootfs)
                        vulnerabilities.extend(vulns)

        return vulnerabilities

    def _scan_scripts(self, rootfs: Path) -> List[Vulnerability]:
        """Scan script files for hardcoded credentials."""
        vulnerabilities = []

        script_patterns = ["**/*.sh", "**/*.lua", "**/*.pl", "**/*.py", "**/*.php"]

        for pattern in script_patterns:
            for script_file in rootfs.glob(pattern):
                if script_file.is_file():
                    vulns = self._scan_file_for_credentials(script_file, rootfs)
                    vulnerabilities.extend(vulns)

        # Also check common script locations
        script_dirs = ["etc/init.d", "etc/rc.d", "usr/bin", "usr/sbin"]

        for script_dir in script_dirs:
            search_dir = rootfs / script_dir
            if search_dir.exists():
                for script_file in search_dir.iterdir():
                    if script_file.is_file():
                        vulns = self._scan_file_for_credentials(script_file, rootfs)
                        vulnerabilities.extend(vulns)

        return vulnerabilities

    def _scan_file_for_credentials(self, file_path: Path, rootfs: Path) -> List[Vulnerability]:
        """Scan a single file for credential patterns."""
        vulnerabilities = []
        relative_path = str(file_path.relative_to(rootfs))

        # Skip common system binaries that contain help text, not real credentials
        # These are standard Unix utilities that will have "password" in help strings
        skip_binaries = {
            "passwd",
            "login",
            "su",
            "sudo",
            "chpasswd",
            "newusers",
            "ssh",
            "sshd",
            "dropbear",
            "telnetd",
            "ftpd",
            "busybox",
            "ash",
            "bash",
            "sh",
            "csh",
            "zsh",
            "useradd",
            "usermod",
            "userdel",
            "groupadd",
            "cmp",
            "diff",
            "grep",
            "awk",
            "sed",
            "cat",
            "ls",
            "free",
            "top",
            "ps",
            "mount",
            "umount",
            "df",
            "openssl",
            "curl",
            "wget",
        }

        # Check if this is a known system binary
        if file_path.name in skip_binaries:
            return vulnerabilities

        # Also skip if the path indicates this is a standard system binary
        binary_paths = {"usr/bin", "usr/sbin", "bin", "sbin"}
        path_parts = relative_path.split("/")
        if len(path_parts) >= 2:
            parent_path = "/".join(path_parts[:-1])
            if parent_path in binary_paths:
                # Only scan scripts, not compiled binaries
                try:
                    # Check if it's a text file by looking at first bytes
                    with open(file_path, "rb") as f:
                        header = f.read(512)
                        # Skip if it contains many null bytes (likely binary)
                        null_count = header.count(b"\x00")
                        if null_count > len(header) * 0.1:  # More than 10% null bytes
                            return vulnerabilities
                        # Check for ELF magic number
                        if header.startswith(b"\x7fELF"):
                            return vulnerabilities
                except Exception:
                    pass

        try:
            content = file_path.read_text(errors="ignore")

            for pattern, cred_type, severity in CREDENTIAL_PATTERNS:
                matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE)

                for match in matches:
                    credential = match.group(1) if match.lastindex else match.group(0)

                    # Skip if already found
                    cred_key = f"{relative_path}:{cred_type}:{credential[:20]}"
                    if cred_key in self._found_credentials:
                        continue
                    self._found_credentials.add(cred_key)

                    # Skip obvious false positives
                    if self._is_false_positive(credential, cred_type):
                        continue

                    # Find line number
                    line_num = content[: match.start()].count("\n") + 1

                    vuln = self._create_vulnerability(
                        title=f"Hardcoded {cred_type.replace('_', ' ').title()}",
                        description=f"Found hardcoded {cred_type} in {file_path.name}",
                        severity=severity,
                        vuln_type=VulnerabilityType.HARDCODED_CREDENTIALS,
                        file_path=relative_path,
                        line_number=line_num,
                        evidence=f"Pattern match: {match.group(0)[:50]}...",
                        remediation="Remove hardcoded credentials and use secure configuration management",
                    )
                    vulnerabilities.append(vuln)

        except Exception as e:
            logger.debug(f"Failed to scan {file_path}: {e}")

        return vulnerabilities

    def _is_false_positive(self, credential: str, cred_type: str) -> bool:
        """Check if credential is likely a false positive."""
        cred_lower = credential.lower()

        # Skip placeholders and documentation text
        placeholders = [
            "your_password",
            "enter_password",
            "password_here",
            "xxx",
            "yyy",
            "zzz",
            "example",
            "sample",
            "test",
            "changeme",
            "placeholder",
            "insert",
            "todo",
        ]

        if any(p in cred_lower for p in placeholders):
            return True

        # Skip very short credentials
        if len(credential) < 4:
            return True

        # Skip if all same character
        if len(set(credential)) == 1:
            return True

        # Skip common config patterns
        if credential.startswith("$") and cred_type == "password":
            return True  # Variable reference

        # Skip help text / UI strings commonly found in binaries
        # These are prompts, error messages, and UI labels, not actual credentials
        help_text_patterns = [
            # Password prompts and help text
            "retype",
            "re-type",
            "reenter",
            "re-enter",
            "confirm",
            "incorrect",
            "invalid",
            "wrong",
            "error",
            "failed",
            "enter",
            "input",
            "type",
            "provide",
            "specify",
            "new",
            "old",
            "current",
            "previous",
            "passwords",
            "must",
            "should",
            "cannot",
            "required",
            "minimum",
            "maximum",
            "length",
            "character",
            "match",
            "matches",
            "matching",
            "mismatch",
            "expire",
            "expired",
            "expiration",
            "expires",
            "change",
            "changed",
            "changing",
            "reset",
            "authentication",
            "authenticate",
            "authenticating",
            "login",
            "logon",
            "logout",
            "logged",
            "please",
            "press",
            "click",
            "select",
            "prompt",
            "dialog",
            "message",
            "warning",
            "success",
            "successful",
            "successfully",
            "denied",
            "rejected",
            "refused",
            "forbidden",
            "empty",
            "blank",
            "missing",
            "null",
            "none",
            "usage",
            "help",
            "info",
            "hint",
            "option",
            "encryption",
            "encrypted",
            "decrypt",
            "verify",
            "verified",
            "verification",
            "enabled",
            "disabled",
            "enable",
            "disable",
            "set",
            "unset",
            "clear",
            "cleared",
        ]

        if any(pattern in cred_lower for pattern in help_text_patterns):
            return True

        # Skip if it looks like a sentence or description (contains spaces after splitting)
        if " " in credential.strip():
            return True

        # Skip common UI/shell command help patterns
        # These typically appear as "password: <description>" in binary strings
        if cred_type == "password":
            # Check if the "credential" looks like help text syntax
            if any(
                credential.startswith(prefix)
                for prefix in [
                    "Password",
                    "Passwords",
                    "Re",
                    "New",
                    "Old",
                    "Enter",
                    "Type",
                    "Invalid",
                    "Incorrect",
                    "Wrong",
                    "Bad",
                    "Your",
                    "The",
                    "A ",
                    "An ",
                ]
            ):
                return True

        # Skip generic programming/config tokens that aren't real secrets
        generic_tokens = [
            "true",
            "false",
            "null",
            "none",
            "undefined",
            "string",
            "integer",
            "boolean",
            "array",
            "object",
            "default",
            "value",
            "name",
            "path",
            "file",
            "dir",
            "required",
            "optional",
            "deprecated",
        ]

        if cred_lower in generic_tokens:
            return True

        return False

    def _find_private_keys(self, rootfs: Path) -> List[Vulnerability]:
        """Find private key files."""
        vulnerabilities = []

        key_patterns = ["**/*.pem", "**/*.key", "**/*.p12", "**/*.pfx"]
        key_dirs = ["etc/ssl", "etc/pki", "root/.ssh", "home/*/.ssh", "var/lib"]

        found_keys: Set[str] = set()

        # Search by pattern
        for pattern in key_patterns:
            for key_file in rootfs.glob(pattern):
                if key_file.is_file():
                    rel_path = str(key_file.relative_to(rootfs))
                    if rel_path not in found_keys:
                        found_keys.add(rel_path)

        # Search in common directories
        for key_dir in key_dirs:
            for search_dir in rootfs.glob(key_dir):
                if search_dir.exists():
                    for item in search_dir.iterdir():
                        if item.is_file():
                            rel_path = str(item.relative_to(rootfs))
                            if rel_path not in found_keys:
                                found_keys.add(rel_path)

        # Analyze found files
        for rel_path in found_keys:
            file_path = rootfs / rel_path

            try:
                content = file_path.read_text(errors="ignore")

                # Check for private key markers
                if "-----BEGIN" in content and "PRIVATE KEY" in content:
                    # Determine key type
                    if "RSA PRIVATE KEY" in content:
                        key_type = "RSA"
                    elif "DSA PRIVATE KEY" in content:
                        key_type = "DSA"
                    elif "EC PRIVATE KEY" in content:
                        key_type = "EC"
                    elif "OPENSSH PRIVATE KEY" in content:
                        key_type = "OpenSSH"
                    else:
                        key_type = "Unknown"

                    # Check if encrypted
                    is_encrypted = "ENCRYPTED" in content or "Proc-Type: 4,ENCRYPTED" in content

                    severity = Severity.HIGH if is_encrypted else Severity.CRITICAL

                    vuln = self._create_vulnerability(
                        title=f"Private Key Found: {key_type}",
                        description=f"Private key file found in firmware: {rel_path}",
                        severity=severity,
                        vuln_type=VulnerabilityType.HARDCODED_CREDENTIALS,
                        file_path=rel_path,
                        evidence=f"Key type: {key_type}, Encrypted: {is_encrypted}",
                        remediation="Remove private keys from firmware or ensure they are properly secured",
                    )
                    vulnerabilities.append(vuln)
                    self._found_credentials.add(f"private_key:{rel_path}")

            except Exception as e:
                logger.debug(f"Failed to analyze {file_path}: {e}")

        return vulnerabilities

    def _scan_web_files(self, rootfs: Path) -> List[Vulnerability]:
        """Scan web application files for credentials."""
        vulnerabilities = []

        web_dirs = ["www", "var/www", "usr/share/www", "home/httpd", "srv/http"]
        web_patterns = ["**/*.php", "**/*.cgi", "**/*.lua", "**/*.js", "**/*.html"]

        for web_dir in web_dirs:
            search_dir = rootfs / web_dir
            if not search_dir.exists():
                continue

            for pattern in web_patterns:
                for web_file in search_dir.glob(pattern):
                    if web_file.is_file():
                        vulns = self._scan_file_for_credentials(web_file, rootfs)
                        vulnerabilities.extend(vulns)

        return vulnerabilities

    def _check_common_locations(self, rootfs: Path) -> List[Vulnerability]:
        """Check common credential storage locations."""
        vulnerabilities = []

        # Common credential files
        credential_files = [
            "etc/config/wireless",
            "etc/config/network",
            "etc/config/system",
            "tmp/config",
            "var/etc/httpasswd",
            "etc/httpd.conf",
            "etc/lighttpd.conf",
            "etc/dropbear/dropbear_rsa_host_key",
            "etc/openvpn/server.key",
        ]

        for cred_file in credential_files:
            file_path = rootfs / cred_file
            if file_path.exists() and file_path.is_file():
                vulns = self._scan_file_for_credentials(file_path, rootfs)
                vulnerabilities.extend(vulns)

        return vulnerabilities
