"""
Cryptographic Vulnerability Scanner.

Analyzes firmware for cryptographic weaknesses:
- Weak cipher usage
- Hardcoded encryption keys
- Insecure random number generation
- Weak hash algorithms
- SSL/TLS configuration issues
"""

import re
import struct
from pathlib import Path
from typing import List, Dict, Optional, Set
from datetime import datetime

from .base import BaseScanner, ScannerRegistry
from ..core.config import Config
from ..core.logger import get_logger
from ..core.models import (
    FirmwareInfo, ScanResult, Vulnerability,
    Severity, VulnerabilityType
)

logger = get_logger(__name__)


# Weak cryptographic patterns
WEAK_CRYPTO_PATTERNS = [
    # Weak ciphers
    (r'\bDES\b(?!3)', 'DES cipher (weak)', Severity.HIGH),
    (r'\bRC4\b', 'RC4 cipher (weak)', Severity.HIGH),
    (r'\bRC2\b', 'RC2 cipher (weak)', Severity.HIGH),
    (r'\bMD5\b', 'MD5 hash (weak for security)', Severity.MEDIUM),
    (r'\bSHA1\b', 'SHA1 hash (deprecated)', Severity.LOW),
    (r'\bBlowfish\b', 'Blowfish cipher', Severity.LOW),
    
    # Weak modes
    (r'\bECB\b', 'ECB mode (insecure)', Severity.HIGH),
    (r'AES.*ECB|ECB.*AES', 'AES-ECB mode (insecure)', Severity.HIGH),
    
    # Insecure random
    (r'\brand\(\)', 'rand() - weak PRNG', Severity.MEDIUM),
    (r'\bsrand\(time', 'srand(time()) - predictable seed', Severity.MEDIUM),
    (r'\brandom\(\)', 'random() - weak PRNG', Severity.MEDIUM),
    
    # Hardcoded keys/IVs
    (r'(?:key|iv|secret)\s*=\s*["\'][0-9a-fA-F]{16,}["\']', 'Hardcoded crypto key/IV', Severity.CRITICAL),
    (r'(?:AES|DES)_KEY\s*=\s*["\'][^"\']+["\']', 'Hardcoded encryption key', Severity.CRITICAL),
    
    # Weak key sizes
    (r'keysize\s*=\s*(?:40|56|64|512)\b', 'Weak key size', Severity.HIGH),
    (r'key_?length\s*=\s*(?:40|56|64|512)\b', 'Weak key size', Severity.HIGH),
]

# Known weak crypto constants
KNOWN_WEAK_KEYS = [
    b'\x00' * 16,  # All zeros
    b'\xff' * 16,  # All ones
    b'0123456789abcdef',  # Sequential
    b'1234567890123456',  # Common test key
    b'AAAAAAAAAAAAAAAA',  # Repeated character
]


@ScannerRegistry.register('crypto')
class CryptoScanner(BaseScanner):
    """
    Scanner for cryptographic vulnerabilities.
    """
    
    @property
    def name(self) -> str:
        return "crypto_scanner"
    
    @property
    def scan_type(self) -> str:
        return "crypto"
    
    def __init__(self, config: Config):
        super().__init__(config)
        self._findings: Set[str] = set()
    
    def scan(
        self,
        target: str,
        firmware: FirmwareInfo,
        **kwargs
    ) -> ScanResult:
        """
        Scan firmware for cryptographic weaknesses.
        
        Args:
            target: Path to extracted rootfs
            firmware: FirmwareInfo context
        """
        result = self._create_result()
        self._start_scan(result)
        self._findings.clear()
        
        try:
            rootfs = Path(target)
            
            # Phase 1: Scan source/script files for weak crypto usage
            logger.info(f"[{self.name}] Scanning for weak crypto patterns")
            pattern_vulns = self._scan_crypto_patterns(rootfs)
            result.vulnerabilities.extend(pattern_vulns)
            
            # Phase 2: Analyze SSL/TLS certificates
            logger.info(f"[{self.name}] Analyzing certificates")
            cert_vulns = self._analyze_certificates(rootfs)
            result.vulnerabilities.extend(cert_vulns)
            
            # Phase 3: Check for weak crypto in binaries
            logger.info(f"[{self.name}] Scanning binaries for crypto issues")
            binary_vulns = self._scan_binaries_crypto(rootfs)
            result.vulnerabilities.extend(binary_vulns)
            
            # Phase 4: Check OpenSSL/crypto library configuration
            logger.info(f"[{self.name}] Checking crypto library configuration")
            config_vulns = self._check_crypto_config(rootfs)
            result.vulnerabilities.extend(config_vulns)
            
            # Phase 5: Search for hardcoded keys in firmware
            logger.info(f"[{self.name}] Searching for hardcoded keys")
            key_vulns = self._search_hardcoded_keys(rootfs)
            result.vulnerabilities.extend(key_vulns)
            
            result.items_scanned = len(self._findings)
            self._complete_scan(result)
            
        except Exception as e:
            self._fail_scan(result, str(e))
        
        return result
    
    def _scan_crypto_patterns(self, rootfs: Path) -> List[Vulnerability]:
        """Scan files for weak cryptographic patterns."""
        vulnerabilities = []
        
        # File types to scan
        scan_patterns = [
            '**/*.c', '**/*.cpp', '**/*.h', '**/*.hpp',
            '**/*.py', '**/*.php', '**/*.lua', '**/*.sh',
            '**/*.conf', '**/*.cfg', '**/*.xml', '**/*.json',
        ]
        
        for pattern in scan_patterns:
            for file_path in rootfs.glob(pattern):
                if file_path.is_file():
                    vulns = self._scan_file_crypto(file_path, rootfs)
                    vulnerabilities.extend(vulns)
        
        return vulnerabilities
    
    def _scan_file_crypto(self, file_path: Path, rootfs: Path) -> List[Vulnerability]:
        """Scan a single file for weak crypto patterns."""
        vulnerabilities = []
        
        try:
            content = file_path.read_text(errors='ignore')
            relative_path = str(file_path.relative_to(rootfs))
            
            for pattern, description, severity in WEAK_CRYPTO_PATTERNS:
                matches = re.finditer(pattern, content, re.IGNORECASE)
                
                for match in matches:
                    finding_key = f"{relative_path}:{pattern}:{match.start()}"
                    if finding_key in self._findings:
                        continue
                    self._findings.add(finding_key)
                    
                    line_num = content[:match.start()].count('\n') + 1
                    
                    vuln = self._create_vulnerability(
                        title=f"Weak Crypto: {description}",
                        description=f"Potentially weak cryptographic usage found in {file_path.name}",
                        severity=severity,
                        vuln_type=VulnerabilityType.WEAK_CRYPTO,
                        file_path=relative_path,
                        line_number=line_num,
                        evidence=f"Match: {match.group(0)[:100]}",
                        remediation="Use strong, modern cryptographic algorithms (AES-256, SHA-256+, etc.)",
                    )
                    vulnerabilities.append(vuln)
                    
        except Exception as e:
            logger.debug(f"Failed to scan {file_path}: {e}")
        
        return vulnerabilities
    
    def _analyze_certificates(self, rootfs: Path) -> List[Vulnerability]:
        """Analyze SSL/TLS certificates for weaknesses."""
        vulnerabilities = []
        
        cert_patterns = ['**/*.crt', '**/*.pem', '**/*.cer', '**/*.der']
        cert_dirs = ['etc/ssl', 'etc/pki', 'usr/share/ca-certificates']
        
        found_certs: Set[str] = set()
        
        # Find certificates
        for pattern in cert_patterns:
            for cert_file in rootfs.glob(pattern):
                if cert_file.is_file():
                    found_certs.add(str(cert_file))
        
        for cert_dir in cert_dirs:
            search_dir = rootfs / cert_dir
            if search_dir.exists():
                for item in search_dir.rglob('*'):
                    if item.is_file():
                        found_certs.add(str(item))
        
        # Analyze certificates
        for cert_path in found_certs:
            vulns = self._analyze_certificate(Path(cert_path), rootfs)
            vulnerabilities.extend(vulns)
        
        return vulnerabilities
    
    def _analyze_certificate(self, cert_path: Path, rootfs: Path) -> List[Vulnerability]:
        """Analyze a single certificate file."""
        vulnerabilities = []
        
        try:
            content = cert_path.read_text(errors='ignore')
            relative_path = str(cert_path.relative_to(rootfs))
            
            # Check for certificate markers
            if '-----BEGIN CERTIFICATE-----' not in content:
                return vulnerabilities
            
            # Try to parse with openssl if available
            import subprocess
            
            try:
                result = subprocess.run(
                    ['openssl', 'x509', '-in', str(cert_path), '-text', '-noout'],
                    capture_output=True, text=True, timeout=10
                )
                
                cert_info = result.stdout
                
                # Check signature algorithm
                if 'sha1WithRSAEncryption' in cert_info or 'md5WithRSAEncryption' in cert_info:
                    vuln = self._create_vulnerability(
                        title="Weak Certificate Signature Algorithm",
                        description=f"Certificate uses weak signature algorithm",
                        severity=Severity.MEDIUM,
                        vuln_type=VulnerabilityType.WEAK_CRYPTO,
                        file_path=relative_path,
                        evidence="SHA1 or MD5 signature algorithm",
                        remediation="Use SHA-256 or stronger for certificate signatures",
                    )
                    vulnerabilities.append(vuln)
                
                # Check key size
                key_size_match = re.search(r'Public-Key:\s*\((\d+)\s*bit\)', cert_info)
                if key_size_match:
                    key_size = int(key_size_match.group(1))
                    if key_size < 2048:
                        vuln = self._create_vulnerability(
                            title=f"Weak Certificate Key Size: {key_size} bits",
                            description=f"Certificate has weak key size ({key_size} bits)",
                            severity=Severity.HIGH if key_size < 1024 else Severity.MEDIUM,
                            vuln_type=VulnerabilityType.WEAK_CRYPTO,
                            file_path=relative_path,
                            evidence=f"Key size: {key_size} bits",
                            remediation="Use at least 2048-bit RSA or 256-bit ECC keys",
                        )
                        vulnerabilities.append(vuln)
                
                # Check expiration
                if 'Not After' in cert_info:
                    # Could add expiration check here
                    pass
                    
            except FileNotFoundError:
                # OpenSSL not available, do basic analysis
                pass
            except subprocess.TimeoutExpired:
                pass
                
        except Exception as e:
            logger.debug(f"Failed to analyze certificate {cert_path}: {e}")
        
        return vulnerabilities
    
    def _scan_binaries_crypto(self, rootfs: Path) -> List[Vulnerability]:
        """Scan binaries for crypto-related strings."""
        vulnerabilities = []
        
        import subprocess
        
        # Find binaries
        bin_dirs = ['bin', 'sbin', 'usr/bin', 'usr/sbin', 'lib', 'usr/lib']
        
        for bin_dir in bin_dirs:
            search_dir = rootfs / bin_dir
            if not search_dir.exists():
                continue
            
            for binary in search_dir.iterdir():
                if not binary.is_file():
                    continue
                
                try:
                    # Get strings from binary
                    result = subprocess.run(
                        ['strings', str(binary)],
                        capture_output=True, text=True, timeout=30
                    )
                    
                    strings_output = result.stdout
                    relative_path = str(binary.relative_to(rootfs))
                    
                    # Check for weak crypto indicators
                    weak_indicators = [
                        ('DES_', 'DES encryption'),
                        ('RC4', 'RC4 cipher'),
                        ('MD5_', 'MD5 hashing'),
                        ('SSLv2', 'SSLv2 protocol'),
                        ('SSLv3', 'SSLv3 protocol'),
                    ]
                    
                    for indicator, description in weak_indicators:
                        if indicator in strings_output:
                            finding_key = f"{relative_path}:{indicator}"
                            if finding_key in self._findings:
                                continue
                            self._findings.add(finding_key)
                            
                            vuln = self._create_vulnerability(
                                title=f"Binary Uses {description}",
                                description=f"Binary {binary.name} appears to use {description}",
                                severity=Severity.MEDIUM,
                                vuln_type=VulnerabilityType.WEAK_CRYPTO,
                                file_path=relative_path,
                                evidence=f"Found string: {indicator}",
                                remediation="Update to use modern cryptographic algorithms",
                            )
                            vulnerabilities.append(vuln)
                            
                except subprocess.TimeoutExpired:
                    continue
                except Exception as e:
                    logger.debug(f"Failed to scan binary {binary}: {e}")
        
        return vulnerabilities
    
    def _check_crypto_config(self, rootfs: Path) -> List[Vulnerability]:
        """Check crypto library configurations."""
        vulnerabilities = []
        
        # OpenSSL configuration
        openssl_conf = rootfs / "etc" / "ssl" / "openssl.cnf"
        if openssl_conf.exists():
            vulns = self._analyze_openssl_config(openssl_conf, rootfs)
            vulnerabilities.extend(vulns)
        
        # SSH configuration
        ssh_config = rootfs / "etc" / "ssh" / "sshd_config"
        if ssh_config.exists():
            vulns = self._analyze_ssh_config(ssh_config, rootfs)
            vulnerabilities.extend(vulns)
        
        return vulnerabilities
    
    def _analyze_openssl_config(self, config_path: Path, rootfs: Path) -> List[Vulnerability]:
        """Analyze OpenSSL configuration."""
        vulnerabilities = []
        
        try:
            content = config_path.read_text()
            relative_path = str(config_path.relative_to(rootfs))
            
            # Check for weak settings
            if 'SSLv2' in content or 'SSLv3' in content:
                vuln = self._create_vulnerability(
                    title="Weak SSL/TLS Protocol Enabled",
                    description="OpenSSL configuration allows SSLv2 or SSLv3",
                    severity=Severity.HIGH,
                    vuln_type=VulnerabilityType.WEAK_CRYPTO,
                    file_path=relative_path,
                    remediation="Disable SSLv2 and SSLv3, use TLS 1.2 or higher",
                )
                vulnerabilities.append(vuln)
                
        except Exception as e:
            logger.debug(f"Failed to analyze OpenSSL config: {e}")
        
        return vulnerabilities
    
    def _analyze_ssh_config(self, config_path: Path, rootfs: Path) -> List[Vulnerability]:
        """Analyze SSH configuration for crypto issues."""
        vulnerabilities = []
        
        try:
            content = config_path.read_text()
            relative_path = str(config_path.relative_to(rootfs))
            
            # Check for weak ciphers
            weak_ciphers = ['arcfour', '3des-cbc', 'blowfish-cbc', 'cast128-cbc']
            
            for cipher in weak_ciphers:
                if cipher in content.lower():
                    vuln = self._create_vulnerability(
                        title=f"Weak SSH Cipher: {cipher}",
                        description=f"SSH configuration allows weak cipher: {cipher}",
                        severity=Severity.MEDIUM,
                        vuln_type=VulnerabilityType.WEAK_CRYPTO,
                        file_path=relative_path,
                        remediation="Remove weak ciphers from SSH configuration",
                    )
                    vulnerabilities.append(vuln)
                    
        except Exception as e:
            logger.debug(f"Failed to analyze SSH config: {e}")
        
        return vulnerabilities
    
    def _search_hardcoded_keys(self, rootfs: Path) -> List[Vulnerability]:
        """Search for hardcoded encryption keys in firmware."""
        vulnerabilities = []
        
        # Search for common key patterns in files
        key_patterns = [
            # Hex keys
            r'(?:key|secret|password)\s*=\s*["\']?([0-9a-fA-F]{32,})["\']?',
            # Base64 keys
            r'(?:key|secret)\s*=\s*["\']([A-Za-z0-9+/]{20,}={0,2})["\']',
        ]
        
        # Search config and source files
        search_patterns = ['**/*.conf', '**/*.cfg', '**/*.c', '**/*.h', '**/*.lua']
        
        for search_pattern in search_patterns:
            for file_path in rootfs.glob(search_pattern):
                if not file_path.is_file():
                    continue
                
                try:
                    content = file_path.read_text(errors='ignore')
                    relative_path = str(file_path.relative_to(rootfs))
                    
                    for pattern in key_patterns:
                        matches = re.finditer(pattern, content, re.IGNORECASE)
                        
                        for match in matches:
                            key_value = match.group(1)
                            
                            # Skip obvious placeholders
                            if self._is_placeholder_key(key_value):
                                continue
                            
                            finding_key = f"{relative_path}:hardcoded_key:{key_value[:16]}"
                            if finding_key in self._findings:
                                continue
                            self._findings.add(finding_key)
                            
                            line_num = content[:match.start()].count('\n') + 1
                            
                            vuln = self._create_vulnerability(
                                title="Hardcoded Encryption Key",
                                description=f"Hardcoded encryption key found in {file_path.name}",
                                severity=Severity.CRITICAL,
                                vuln_type=VulnerabilityType.HARDCODED_CREDENTIALS,
                                file_path=relative_path,
                                line_number=line_num,
                                evidence=f"Key pattern: {match.group(0)[:50]}...",
                                remediation="Use secure key management, never hardcode keys",
                            )
                            vulnerabilities.append(vuln)
                            
                except Exception:
                    continue
        
        return vulnerabilities
    
    def _is_placeholder_key(self, key: str) -> bool:
        """Check if key is a placeholder."""
        placeholders = [
            '0' * 32, 'f' * 32, 'F' * 32,
            '1234567890', 'abcdef', 'ABCDEF',
            'your_key', 'enter_key', 'change_me',
        ]
        
        key_lower = key.lower()
        
        # Check against known placeholders
        for p in placeholders:
            if p.lower() in key_lower:
                return True
        
        # Check for repeating patterns
        if len(set(key)) <= 2:
            return True
        
        return False
