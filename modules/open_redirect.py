"""
open_redirect.py - Open Redirect vulnerability detector
"""
import httpx
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from rich.console import Console

console = Console()

REDIRECT_PAYLOADS = [
    "https://evil.com",
    "//evil.com",
    "/\\evil.com",
    "https://evil.com/%2F..",
    "https:evil.com",
]

REDIRECT_PARAMS = [
    "redirect", "url", "next", "return", "returnUrl", "return_url",
    "goto", "target", "link", "continue", "to", "out", "view",
    "redirect_uri", "callback", "redir", "destination",
]


class OpenRedirectScanner:
    def __init__(self, timeout: int = 8):
        self.timeout = timeout

    async def scan_url(self, url: str, client: httpx.AsyncClient) -> list[dict]:
        results = []
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        # Check existing params + common redirect param names
        all_params = set(params.keys()) | set(REDIRECT_PARAMS)

        for param in all_params:
            for payload in REDIRECT_PAYLOADS:
                test_params = dict(params)
                test_params[param] = [payload]
                test_url = urlunparse(parsed._replace(query=urlencode(test_params, doseq=True)))
                try:
                    resp = await client.get(test_url, follow_redirects=False)
                    location = resp.headers.get("location", "")
                    if resp.status_code in (301, 302, 303, 307, 308) and "evil.com" in location:
                        vuln = {
                            "type": "Open Redirect",
                            "severity": "MEDIUM",
                            "url": url,
                            "parameter": param,
                            "payload": payload,
                            "evidence": f"Redirects to: {location}",
                        }
                        results.append(vuln)
                        console.print(f"  [yellow bold][OPEN REDIRECT][/yellow bold] {url} | param={param}")
                        break
                except Exception:
                    pass

        return results
