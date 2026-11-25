"""
Credential Scanner.

Scans firmware for hardcoded credentials, API keys, and secrets:
- /etc/passwd and /etc/shadow analysis
- Hardcoded passwords in scripts and configs
- API keys and tokens
- Private keys and certificates
- Database credentials
"""

import os
import re
import hashlib
import base64
from pathlib import Path
from typing import List, Dict, Optional, Set
from datetime import datetime

from .base import BaseScanner, ScannerRegistry
from ..core.config import Config
from ..core.logger import get_logger
from ..core.models import FirmwareInfo, ScanResult, Vulnerability, Severity, VulnerabilityType

logger = get_logger(__name__)


# High-precision patterns that match the secret itself (the value carries its
# own structure), so they rarely false-positive and need no value validation.
STANDALONE_PATTERNS = [
    (re.compile(r"AKIA[0-9A-Z]{16}"), "aws_access_key", Severity.CRITICAL),
    (
        re.compile(r"-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----"),
        "private_key",
        Severity.CRITICAL,
    ),
    (re.compile(r"-----BEGIN PGP PRIVATE KEY BLOCK-----"), "pgp_private_key", Severity.CRITICAL),
    (
        re.compile(r"(?:ghp|gho|ghs|ghr|github_pat)_[0-9A-Za-z_]{20,}"),
        "github_token",
        Severity.HIGH,
    ),
    # user:password embedded in a connection URI
    (
        re.compile(
            r"(?:mysql|postgres(?:ql)?|mongodb|redis|ftp|amqp)://" r"[^:@/\s]+:([^@\s/'\"]{3,})@"
        ),
        "db_password",
        Severity.HIGH,
    ),
]

# keyword = "value" assignment patterns. The value is validated separately
# (``_is_plausible_secret``) so we don't flag variable references, code tokens
# or identifiers. Fields: (keyword alternation, cred_type, severity, min_len,
# high_entropy) -- high_entropy means the value must look random (keys/tokens).
ASSIGN_SPECS = [
    (r"password|passwd", "password", Severity.HIGH, 4, False),
    (r"passphrase", "passphrase", Severity.HIGH, 4, False),
    (r"secret[_-]?key|secretkey|client[_-]?secret", "secret_key", Severity.CRITICAL, 8, True),
    (r"api[_-]?key|apikey", "api_key", Severity.HIGH, 12, True),
    (r"(?:auth|access|bearer)[_-]?token|access_?key", "token", Severity.HIGH, 12, True),
    (r"aws[_-]?secret[_-]?access[_-]?key", "aws_secret", Severity.CRITICAL, 20, True),
]

# key[=:] value, where value is a "double"/'single' quoted literal or a bare
# token. Capturing the *whole* quoted literal (not a delimiter-truncated
# fragment) lets the validator see and reject things like "psk=${key}". The
# \b stops matches inside words such as "bypass", "compass" or "keyboard".
ASSIGN_PATTERNS = [
    (
        re.compile(
            r"\b(?:" + kw + r")\b\s*[:=]\s*"
            r"(?:\"([^\"\n]{" + str(mlen) + r",})\""
            r"|'([^'\n]{" + str(mlen) + r",})'"
            r"|([^\s'\"#,;)}\]]{" + str(mlen) + r",}))",
            re.IGNORECASE,
        ),
        ctype,
        sev,
        mlen,
        entropy,
    )
    for (kw, ctype, sev, mlen, entropy) in ASSIGN_SPECS
]

# Values that are obviously not real secrets.
_CODE_TOKENS = {
    "true",
    "false",
    "null",
    "none",
    "nil",
    "undefined",
    "yes",
    "no",
    "on",
    "off",
    "function",
    "self",
    "this",
    "new",
    "var",
    "let",
    "const",
    "return",
    "void",
    "default",
    "enable",
    "enabled",
    "disable",
    "disabled",
    "required",
    "optional",
    "string",
    "integer",
    "boolean",
    "object",
    "array",
    "text",
    "value",
}
# Values that are clearly placeholders, not real secrets. We deliberately do
# NOT list the credential words themselves (password/secret/token/...) here:
# real secrets routinely contain them (e.g. "MyPassword1", "root_secret_42"),
# so matching them as substrings caused false negatives.
_PLACEHOLDER_EXACT = {
    "example",
    "sample",
    "test",
    "testing",
    "changeme",
    "change_me",
    "default",
    "placeholder",
    "none",
    "null",
    "your_password",
    "password_here",
    "enter_password",
    "redacted",
    "todo",
    "tbd",
    "n/a",
    "na",
    "xxx",
    "yyy",
    "zzz",
}
_PLACEHOLDER_SUBSTR = (
    "example",
    "changeme",
    "placeholder",
    "your_",
    "yourpassword",
    "redacted",
    "xxxxx",
    "foobar",
    "dummy",
    "<",
    ">",
    "lorem",
)

# File extensions that contain code (a bare identifier on the RHS is a variable
# reference, not a literal secret) vs. data/config (RHS is a literal value).
_CODE_SUFFIXES = {
    ".sh",
    ".bash",
    ".py",
    ".pl",
    ".php",
    ".lua",
    ".js",
    ".mjs",
    ".ts",
    ".c",
    ".cc",
    ".cpp",
    ".h",
    ".hpp",
    ".java",
    ".rb",
    ".go",
    ".html",
    ".htm",
    ".tcl",
    ".awk",
}

# Shell dialects: a *bare* (unquoted) RHS word is a literal value, not a
# variable reference (shell references use $VAR / ${VAR}). So, unlike the other
# languages above, PASSWORD=admin123 in a shell script is a real hardcoded
# credential and must not be filtered out as an "identifier".
_SHELL_SUFFIXES = {".sh", ".bash", ".ash", ".dash", ".ksh"}
_SHELL_SHEBANG = ("/sh", "/ash", "/bash", "/dash", "/ksh", "busybox")
_NONSHELL_SHEBANG = ("python", "perl", "lua", "node", "ruby", "php", "tclsh", "expect")

# Directory names marking UI string / localization resources. Their
# ``PASSWORD: "Wachtwoord"`` style entries are translation labels, not secrets.
_LOCALE_DIR_NAMES = {
    "locale",
    "locales",
    "i18n",
    "l10n",
    "nls",
    "lang",
    "langs",
    "language",
    "languages",
    "translation",
    "translations",
    "intl",
}

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

    @staticmethod
    def _is_textual_file(file_path: Path) -> bool:
        """Heuristic: is this a text file we should regex-scan?

        Binaries (busybox and friends) read as text produce enormous numbers of
        false "credential" matches, so we skip anything that is ELF or contains
        NUL bytes in its first block. Those belong to the binary scanner's
        strings-based path, not the credential regexes.
        """
        try:
            with open(file_path, "rb") as fh:
                head = fh.read(4096)
        except OSError:
            return False
        if not head:
            return False
        if head[:4] == b"\x7fELF" or head[:2] in (b"MZ",) or head[:4] == b"\xca\xfe\xba\xbe":
            return False
        return b"\x00" not in head

    def _scan_file_for_credentials(self, file_path: Path, rootfs: Path) -> List[Vulnerability]:
        """Scan a single *text* file for credential patterns."""
        vulnerabilities = []

        if not self._is_textual_file(file_path):
            return vulnerabilities

        try:
            content = file_path.read_text(errors="ignore")
        except Exception as e:
            logger.debug(f"Failed to read {file_path}: {e}")
            return vulnerabilities

        try:
            relative_path = str(file_path.relative_to(rootfs))
        except Exception:
            relative_path = str(file_path)

        # Skip UI string / localization resources: their PASSWORD:"<word>"
        # entries are translation labels, not credentials.
        if any(part.lower() in _LOCALE_DIR_NAMES for part in Path(relative_path).parts):
            return vulnerabilities

        # A "reference language" is one where an unquoted bare word on the RHS
        # is a variable/property reference, not a literal (JS, Python, Lua, ...).
        # Shell is NOT one of those (bare words are literals there), so
        # PASSWORD=admin123 in a shell script stays a real finding.
        suffix = file_path.suffix.lower()
        shebang = content[:80].split("\n", 1)[0] if content.startswith("#!") else ""
        is_shell = suffix in _SHELL_SUFFIXES or (
            bool(shebang)
            and any(s in shebang for s in _SHELL_SHEBANG)
            and not any(s in shebang for s in _NONSHELL_SHEBANG)
        )
        ref_lang = (suffix in _CODE_SUFFIXES or bool(shebang)) and not is_shell

        def _emit(cred_type, severity, evidence, start):
            line_num = content[:start].count("\n") + 1
            vulnerabilities.append(
                self._create_vulnerability(
                    title=f"Hardcoded {cred_type.replace('_', ' ').title()}",
                    description=f"Found hardcoded {cred_type} in {file_path.name}",
                    severity=severity,
                    vuln_type=VulnerabilityType.HARDCODED_CREDENTIALS,
                    file_path=relative_path,
                    line_number=line_num,
                    evidence=evidence,
                    confidence=0.75,
                    remediation="Remove hardcoded credentials; use secure/externalised "
                    "configuration or a secrets store.",
                )
            )

        # 1. High-precision standalone secrets (keys, tokens, URI passwords).
        for rx, cred_type, severity in STANDALONE_PATTERNS:
            for m in rx.finditer(content):
                value = m.group(1) if m.lastindex else m.group(0)
                key = f"{relative_path}:{cred_type}:{value[:24]}"
                if key in self._found_credentials:
                    continue
                self._found_credentials.add(key)
                _emit(cred_type, severity, f"{m.group(0)[:60]}", m.start())

        # 2. keyword = value assignments, with the value validated.
        for rx, cred_type, severity, min_len, high_entropy in ASSIGN_PATTERNS:
            for m in rx.finditer(content):
                # Skip shell/template parameter expansions such as
                # ${password:+...} or {{password}} -- the ':' there is an
                # expansion operator, not an assignment.
                if content[max(0, m.start() - 2) : m.start()].endswith("{"):
                    continue
                dq, sq, bare = m.group(1), m.group(2), m.group(3)
                if dq is not None:
                    value, quoted = dq, True
                elif sq is not None:
                    value, quoted = sq, True
                else:
                    value, quoted = (bare or ""), False
                value = value.strip()
                if not self._is_plausible_secret(value, quoted, high_entropy, ref_lang):
                    continue
                key = f"{relative_path}:{cred_type}:{value[:24]}"
                if key in self._found_credentials:
                    continue
                self._found_credentials.add(key)
                shown = m.group(0)[:60]
                _emit(cred_type, severity, f"{shown}", m.start())

        return vulnerabilities

    def _is_plausible_secret(
        self, value: str, quoted: bool, high_entropy: bool, ref_lang: bool
    ) -> bool:
        """Decide whether an assignment value is a real literal secret.

        Rejects variable references ($VAR, ${x}), template/interpolation, code
        expressions (calls, property access), placeholders and obvious code
        tokens. In *reference languages* (JS/Python/Lua/..., not shell) an
        unquoted bare identifier is a variable reference, not a literal, so it
        is rejected too. It deliberately does NOT reject a value merely for
        containing the word "password"/"secret"/"token" -- real secrets do.
        """
        v = value.strip().strip("\"'")
        if len(v) < 4 or len(set(v)) == 1:
            return False
        low = v.lower()
        if low in _CODE_TOKENS or low in _PLACEHOLDER_EXACT:
            return False
        if any(sub in low for sub in _PLACEHOLDER_SUBSTR):
            return False
        # variable reference / template / interpolation / expression
        if v[0] in "$%@&<>{}([":
            return False
        if any(tok in v for tok in ("${", "$(", "%(", "{{", "}}", "</", "/>")):
            return False
        # function call, property access or indexing -> code, not a literal
        if any(c in v for c in "()[]"):
            return False
        # nested assignment fragment (e.g. psk=${key} truncated to "psk=\\") or a
        # trailing escape backslash left by a truncated quoted string
        if re.match(r"^[A-Za-z_]\w*=", v) or v.endswith("\\"):
            return False
        # format specifiers / ellipsis placeholders
        if "%s" in low or "%d" in low or "%x" in low or "..." in v:
            return False
        # In a reference language, an unquoted RHS that is a plain identifier or
        # a dotted property chain is a reference to another symbol, not a secret.
        # (Shell is excluded: a bare word there is a literal value.)
        if ref_lang and not quoted:
            if re.fullmatch(r"[A-Za-z_]\w*", v) or re.fullmatch(r"[A-Za-z_][\w.]*", v):
                return False
        # Keys/tokens must actually look random (mix of character classes),
        # which rules out dictionary-word identifiers like getAuthToken.
        if high_entropy:
            classes = sum(bool(re.search(p, v)) for p in (r"[a-z]", r"[A-Z]", r"\d"))
            if classes < 2:
                return False
        return True

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
