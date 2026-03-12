"""
xss.py - Cross-Site Scripting (XSS) vulnerability detector
"""
import httpx
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from rich.console import Console

console = Console()

XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "'\"><script>alert(1)</script>",
    "<svg onload=alert(1)>",
    "javascript:alert(1)",
    "<body onload=alert(1)>",
    "\"><img src=x onerror=alert(1)>",
    "<iframe src=javascript:alert(1)>",
]


class XSSScanner:
    def __init__(self, timeout: int = 10, config: dict | None = None, waf_name: str = ""):
        self.timeout = timeout
        self.config = config or {}
        self.waf_name = waf_name

    def _inject_url(self, url: str, param: str, payload: str) -> str:
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        params[param] = [payload]
        return urlunparse(parsed._replace(query=urlencode(params, doseq=True)))

    async def scan_url(self, url: str, client: httpx.AsyncClient) -> list[dict]:
        results = []
        params = parse_qs(urlparse(url).query)
        if not params:
            return results

        for param in params:
            for payload in XSS_PAYLOADS:
                test_url = self._inject_url(url, param, payload)
                try:
                    resp = await client.get(test_url)
                    if payload in resp.text:
                        vuln = {
                            "type": "Cross-Site Scripting (XSS)",
                            "severity": "MEDIUM",
                            "url": url,
                            "parameter": param,
                            "payload": payload,
                            "evidence": "Payload reflected in response",
                        }
                        results.append(vuln)
                        console.print(f"  [yellow bold][XSS FOUND][/yellow bold] {url} | param={param}")
                        break
                except Exception:
                    pass

        return results

    async def scan_form(self, form: dict, client: httpx.AsyncClient) -> list[dict]:
        results = []
        reported = set()  # Suppress duplicate log per (url, input)
        for inp in form["inputs"]:
            if not inp["name"] or inp["type"] in ("hidden", "submit", "button"):
                continue
            for payload in XSS_PAYLOADS[:4]:
                data = {i["name"]: i["value"] or "test" for i in form["inputs"]}
                data[inp["name"]] = payload
                try:
                    if form["method"] == "POST":
                        resp = await client.post(form["url"], data=data)
                    else:
                        resp = await client.get(form["url"], params=data)

                    if payload in resp.text:
                        vuln = {
                            "type": "XSS (Reflected via Form)",
                            "severity": "MEDIUM",
                            "url": form["url"],
                            "parameter": inp["name"],
                            "payload": payload,
                            "evidence": "Payload reflected in form response",
                        }
                        results.append(vuln)
                        log_key = f"{form['url']}|{inp['name']}"
                        if log_key not in reported:
                            console.print(f"  [yellow bold][XSS FORM][/yellow bold] {form['url']} | input={inp['name']}")
                            reported.add(log_key)
                        break
                except Exception:
                    pass
        return results