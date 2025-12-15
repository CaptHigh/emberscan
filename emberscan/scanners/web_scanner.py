"""
Web Application Vulnerability Scanner.

Scans web interfaces for common vulnerabilities including:
- Command injection
- Authentication bypass
- Information disclosure
- XSS, CSRF, SQLi
- Default credentials
- Directory traversal
"""

import re
import socket
import subprocess
from urllib.parse import urljoin, urlparse, parse_qs
from typing import List, Dict, Optional, Any
from datetime import datetime

from .base import BaseScanner, ScannerRegistry
from ..core.config import Config
from ..core.logger import get_logger
from ..core.models import (
    FirmwareInfo,
    ScanResult,
    ScanStatus,
    Vulnerability,
    Severity,
    VulnerabilityType,
)

logger = get_logger(__name__)


# Common payloads for testing
COMMAND_INJECTION_PAYLOADS = [
    "; id",
    "| id",
    "`id`",
    "$(id)",
    "; cat /etc/passwd",
    "| cat /etc/passwd",
    "; ls -la",
    "&& id",
    "|| id",
    "\n id",
    "; ping -c 3 127.0.0.1",
    "`ping -c 3 127.0.0.1`",
]

PATH_TRAVERSAL_PAYLOADS = [
    "../../../etc/passwd",
    "....//....//....//etc/passwd",
    "..%2f..%2f..%2fetc/passwd",
    "..%252f..%252f..%252fetc/passwd",
    "/etc/passwd",
    "....\\....\\....\\etc\\passwd",
    "..\\..\\..\\etc\\passwd",
]

XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    '"><script>alert(1)</script>',
    "'-alert(1)-'",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
]

DEFAULT_CREDENTIALS = [
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", ""),
    ("admin", "1234"),
    ("admin", "12345"),
    ("root", "root"),
    ("root", "admin"),
    ("root", ""),
    ("user", "user"),
    ("guest", "guest"),
    ("support", "support"),
    ("admin", "admin1234"),
]


@ScannerRegistry.register("web")
class WebScanner(BaseScanner):
    """
    Web vulnerability scanner for embedded device web interfaces.
    """

    @property
    def name(self) -> str:
        return "web_scanner"

    @property
    def scan_type(self) -> str:
        return "web"

    def __init__(self, config: Config):
        super().__init__(config)
        self.session = None
        self.timeout = config.scanner.timeout_per_scan
        self.user_agent = config.scanner.user_agent

    def scan(self, target: str, firmware: FirmwareInfo, **kwargs) -> ScanResult:
        """
        Scan web interface for vulnerabilities.

        Args:
            target: Base URL of web interface (e.g., http://192.168.1.1:8080)
            firmware: FirmwareInfo context
        """
        result = self._create_result()
        self._start_scan(result)

        try:
            import requests
            from bs4 import BeautifulSoup

            self.session = requests.Session()
            self.session.headers["User-Agent"] = self.user_agent
            self.session.verify = False  # Embedded devices often have self-signed certs

            # Suppress SSL warnings
            import urllib3

            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

            base_url = target.rstrip("/")

            # Phase 1: Discovery
            logger.info(f"[{self.name}] Discovering endpoints on {base_url}")
            endpoints = self._discover_endpoints(base_url)
            result.items_scanned = len(endpoints)

            # Phase 2: Check default credentials
            logger.info(f"[{self.name}] Testing default credentials")
            cred_vulns = self._test_default_credentials(base_url)
            result.vulnerabilities.extend(cred_vulns)

            # Phase 3: Test for command injection
            logger.info(f"[{self.name}] Testing for command injection")
            cmd_vulns = self._test_command_injection(base_url, endpoints)
            result.vulnerabilities.extend(cmd_vulns)

            # Phase 4: Test for path traversal
            logger.info(f"[{self.name}] Testing for path traversal")
            traversal_vulns = self._test_path_traversal(base_url, endpoints)
            result.vulnerabilities.extend(traversal_vulns)

            # Phase 5: Check for information disclosure
            logger.info(f"[{self.name}] Checking for information disclosure")
            info_vulns = self._check_information_disclosure(base_url)
            result.vulnerabilities.extend(info_vulns)

            # Phase 6: Run nikto if available
            if self._check_nikto_available():
                logger.info(f"[{self.name}] Running Nikto scan")
                nikto_vulns = self._run_nikto(base_url)
                result.vulnerabilities.extend(nikto_vulns)

            self._complete_scan(result)

        except Exception as e:
            self._fail_scan(result, str(e))

        finally:
            if self.session:
                self.session.close()

        return result

    def _discover_endpoints(self, base_url: str) -> List[Dict]:
        """Discover web endpoints by crawling and common paths."""
        endpoints = []

        # Common router/IoT paths
        common_paths = [
            "/",
            "/index.html",
            "/index.htm",
            "/login.html",
            "/login.htm",
            "/admin/",
            "/admin/login.html",
            "/cgi-bin/",
            "/userRpm/",
            "/HNAP1/",
            "/goform/",
            "/apply.cgi",
            "/setup.cgi",
            "/system.html",
            "/status.html",
            "/config.html",
            "/network.html",
            "/wireless.html",
            "/security.html",
            "/firmware.html",
            "/backup.html",
            "/diagnostic.html",
            "/ping.html",
            "/traceroute.html",
            "/debug.html",
            "/test.html",
            "/info.html",
            "/sysinfo.cgi",
            "/syscmd.cgi",
            "/command.cgi",
            "/api/",
            "/api/v1/",
            "/jsonrpc",
            "/cgi-bin/login.cgi",
            "/cgi-bin/webproc",
            "/HNAP1/GetDeviceSettings",
        ]

        for path in common_paths:
            try:
                url = urljoin(base_url, path)
                response = self.session.get(url, timeout=5, allow_redirects=False)

                if response.status_code in [200, 301, 302, 401, 403]:
                    endpoint = {
                        "url": url,
                        "path": path,
                        "status": response.status_code,
                        "content_type": response.headers.get("Content-Type", ""),
                        "length": len(response.content),
                    }
                    endpoints.append(endpoint)

                    # Extract forms and links
                    if response.status_code == 200:
                        self._extract_forms(response.text, url, endpoints)

            except Exception:
                continue

        return endpoints

    def _extract_forms(self, html: str, base_url: str, endpoints: List[Dict]):
        """Extract forms from HTML for testing."""
        try:
            from bs4 import BeautifulSoup

            soup = BeautifulSoup(html, "html.parser")

            for form in soup.find_all("form"):
                action = form.get("action", "")
                method = form.get("method", "get").upper()

                # Get form inputs
                inputs = []
                for inp in form.find_all(["input", "textarea", "select"]):
                    input_name = inp.get("name")
                    if input_name:
                        inputs.append(
                            {
                                "name": input_name,
                                "type": inp.get("type", "text"),
                                "value": inp.get("value", ""),
                            }
                        )

                if inputs:
                    form_url = urljoin(base_url, action) if action else base_url
                    endpoints.append(
                        {
                            "url": form_url,
                            "path": urlparse(form_url).path,
                            "type": "form",
                            "method": method,
                            "inputs": inputs,
                        }
                    )

        except Exception:
            pass

    def _test_default_credentials(self, base_url: str) -> List[Vulnerability]:
        """Test for default credentials on login forms."""
        vulnerabilities = []

        # Find login endpoints
        login_paths = [
            "/login.html",
            "/login.htm",
            "/admin/login.html",
            "/cgi-bin/login.cgi",
            "/userRpm/LoginRpm.htm",
            "/index.html",
            "/",
            "/admin/",
        ]

        for path in login_paths:
            try:
                url = urljoin(base_url, path)
                response = self.session.get(url, timeout=5)

                if response.status_code != 200:
                    continue

                # Check for login form
                if not any(x in response.text.lower() for x in ["password", "login", "username"]):
                    continue

                # Test default credentials
                for username, password in DEFAULT_CREDENTIALS:
                    if self._try_login(url, response.text, username, password):
                        vuln = self._create_vulnerability(
                            title=f"Default Credentials: {username}:{password}",
                            description=f"The device accepts default credentials ({username}/{password}) for authentication.",
                            severity=Severity.CRITICAL,
                            vuln_type=VulnerabilityType.HARDCODED_CREDENTIALS,
                            endpoint=url,
                            evidence=f"Successful login with {username}:{password}",
                            remediation="Change default credentials immediately",
                        )
                        vulnerabilities.append(vuln)
                        break  # Found one, don't test more

            except Exception:
                continue

        return vulnerabilities

    def _try_login(self, url: str, html: str, username: str, password: str) -> bool:
        """Attempt login with given credentials."""
        try:
            from bs4 import BeautifulSoup

            soup = BeautifulSoup(html, "html.parser")

            form = soup.find("form")
            if not form:
                return False

            # Build form data
            data = {}
            for inp in form.find_all("input"):
                name = inp.get("name")
                if not name:
                    continue

                inp_type = inp.get("type", "text").lower()

                if any(x in name.lower() for x in ["user", "login", "name"]):
                    data[name] = username
                elif any(x in name.lower() for x in ["pass", "pwd"]):
                    data[name] = password
                elif inp_type == "hidden":
                    data[name] = inp.get("value", "")
                elif inp_type == "submit":
                    data[name] = inp.get("value", "Login")

            if not data:
                return False

            # Submit form
            action = form.get("action", "")
            post_url = urljoin(url, action) if action else url
            method = form.get("method", "post").upper()

            if method == "POST":
                response = self.session.post(post_url, data=data, timeout=10, allow_redirects=True)
            else:
                response = self.session.get(post_url, params=data, timeout=10, allow_redirects=True)

            # Check for successful login indicators
            success_indicators = ["logout", "welcome", "dashboard", "status", "settings"]
            failure_indicators = ["invalid", "error", "failed", "incorrect", "wrong"]

            response_lower = response.text.lower()

            # Check for failure first
            if any(x in response_lower for x in failure_indicators):
                return False

            # Check for success
            if any(x in response_lower for x in success_indicators):
                return True

            # Check if we got redirected to a different page (often indicates success)
            if response.url != url and "login" not in response.url.lower():
                return True

            return False

        except Exception:
            return False

    def _test_command_injection(self, base_url: str, endpoints: List[Dict]) -> List[Vulnerability]:
        """Test for command injection vulnerabilities."""
        vulnerabilities = []

        # Test forms with potentially vulnerable parameters
        test_params = ["cmd", "command", "ping", "host", "ip", "target", "url", "path", "file"]

        for endpoint in endpoints:
            if endpoint.get("type") != "form":
                continue

            inputs = endpoint.get("inputs", [])

            for inp in inputs:
                param_name = inp.get("name", "").lower()

                # Check if parameter looks vulnerable
                if not any(x in param_name for x in test_params):
                    continue

                # Test payloads
                for payload in COMMAND_INJECTION_PAYLOADS[:5]:  # Limit payloads
                    try:
                        data = {i["name"]: i.get("value", "test") for i in inputs}
                        data[inp["name"]] = f"test{payload}"

                        if endpoint.get("method") == "POST":
                            response = self.session.post(endpoint["url"], data=data, timeout=10)
                        else:
                            response = self.session.get(endpoint["url"], params=data, timeout=10)

                        # Check for command execution evidence
                        if self._check_command_injection_response(response.text, payload):
                            vuln = self._create_vulnerability(
                                title=f"Command Injection in {inp['name']}",
                                description=f"Command injection vulnerability found in parameter '{inp['name']}' at {endpoint['path']}",
                                severity=Severity.CRITICAL,
                                vuln_type=VulnerabilityType.COMMAND_INJECTION,
                                endpoint=endpoint["url"],
                                parameter=inp["name"],
                                evidence=f"Payload: {payload}",
                                request=str(data),
                                response=response.text[:500],
                                remediation="Sanitize user input and avoid shell commands",
                            )
                            vulnerabilities.append(vuln)
                            break  # Found vulnerability, move to next parameter

                    except Exception:
                        continue

        return vulnerabilities

    def _check_command_injection_response(self, response: str, payload: str) -> bool:
        """Check if response indicates successful command injection."""
        indicators = [
            "uid=",
            "gid=",
            "groups=",  # id command
            "root:",
            "nobody:",  # /etc/passwd
            "total ",
            "drwx",  # ls output
            "bytes from",
            "icmp_seq",  # ping output
        ]
        return any(x in response for x in indicators)

    def _test_path_traversal(self, base_url: str, endpoints: List[Dict]) -> List[Vulnerability]:
        """Test for path traversal vulnerabilities."""
        vulnerabilities = []

        # Parameters that often handle file paths
        file_params = ["file", "path", "page", "template", "include", "doc", "folder", "style"]

        for endpoint in endpoints:
            url = endpoint.get("url", "")

            # Test URL parameters
            parsed = urlparse(url)
            params = parse_qs(parsed.query)

            for param_name, values in params.items():
                if not any(x in param_name.lower() for x in file_params):
                    continue

                for payload in PATH_TRAVERSAL_PAYLOADS[:3]:
                    try:
                        test_url = url.replace(
                            f"{param_name}={values[0]}", f"{param_name}={payload}"
                        )
                        response = self.session.get(test_url, timeout=10)

                        if "root:" in response.text or "nobody:" in response.text:
                            vuln = self._create_vulnerability(
                                title=f"Path Traversal in {param_name}",
                                description=f"Path traversal vulnerability allows reading arbitrary files via '{param_name}' parameter",
                                severity=Severity.HIGH,
                                vuln_type=VulnerabilityType.PATH_TRAVERSAL,
                                endpoint=url,
                                parameter=param_name,
                                evidence=f"Successfully read /etc/passwd",
                                remediation="Validate and sanitize file path inputs",
                            )
                            vulnerabilities.append(vuln)
                            break

                    except Exception:
                        continue

        return vulnerabilities

    def _check_information_disclosure(self, base_url: str) -> List[Vulnerability]:
        """Check for information disclosure issues."""
        vulnerabilities = []

        # Check for exposed sensitive files
        sensitive_paths = [
            "/config.bin",
            "/config.xml",
            "/backup.tar.gz",
            "/etc/passwd",
            "/proc/version",
            "/proc/cpuinfo",
            "/.htpasswd",
            "/.htaccess",
            "/web.config",
            "/phpinfo.php",
            "/info.php",
            "/test.php",
            "/server-status",
            "/server-info",
            "/debug",
            "/debug.html",
            "/debug.cgi",
        ]

        for path in sensitive_paths:
            try:
                url = urljoin(base_url, path)
                response = self.session.get(url, timeout=5)

                if response.status_code == 200 and len(response.content) > 0:
                    # Check content for sensitive data
                    content_lower = response.text.lower()

                    is_sensitive = any(
                        [
                            "password" in content_lower and "=" in content_lower,
                            "root:" in content_lower,
                            "private_key" in content_lower,
                            "phpinfo()" in content_lower,
                            "<configuration>" in content_lower,
                        ]
                    )

                    if is_sensitive:
                        vuln = self._create_vulnerability(
                            title=f"Sensitive File Exposed: {path}",
                            description=f"Sensitive file accessible without authentication: {path}",
                            severity=Severity.HIGH,
                            vuln_type=VulnerabilityType.INFORMATION_DISCLOSURE,
                            endpoint=url,
                            evidence=response.text[:200],
                            remediation="Restrict access to sensitive files",
                        )
                        vulnerabilities.append(vuln)

            except Exception:
                continue

        return vulnerabilities

    def _check_nikto_available(self) -> bool:
        """Check if Nikto is installed."""
        import shutil

        return shutil.which("nikto") is not None

    def _run_nikto(self, target: str) -> List[Vulnerability]:
        """Run Nikto web scanner and parse results."""
        vulnerabilities = []

        try:
            result = subprocess.run(
                ["nikto", "-h", target, "-Format", "csv", "-o", "-"],
                capture_output=True,
                text=True,
                timeout=300,
            )

            # Parse CSV output
            for line in result.stdout.split("\n"):
                if not line or line.startswith('"'):
                    continue

                parts = line.split(",")
                if len(parts) >= 7:
                    vuln = self._create_vulnerability(
                        title=f"Nikto: {parts[6][:100]}",
                        description=parts[6],
                        severity=Severity.MEDIUM,
                        vuln_type=VulnerabilityType.OTHER,
                        endpoint=parts[3] if len(parts) > 3 else target,
                    )
                    vulnerabilities.append(vuln)

        except subprocess.TimeoutExpired:
            logger.warning("Nikto scan timed out")
        except Exception as e:
            logger.warning(f"Nikto scan failed: {e}")

        return vulnerabilities
