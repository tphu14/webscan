"""
sqli.py - SQL Injection vulnerability detector
"""
import httpx
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from rich.console import Console

console = Console()

# Common SQLi payloads
PAYLOADS = [
    "'",
    "''",
    "' OR '1'='1",
    "' OR 1=1--",
    "\" OR \"\"=\"",
    "'; DROP TABLE users--",
    "1' ORDER BY 1--",
    "1' ORDER BY 2--",
    "1 AND 1=1",
    "1 AND 1=2",
]

# Error signatures from popular databases
ERROR_SIGNATURES = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "sql syntax",
    "syntax error",
    "mysql_fetch",
    "pg_query",
    "sqlite3",
    "odbc driver",
    "microsoft ole db",
    "ora-01756",
    "postgresql",
]


class SQLiScanner:
    def __init__(self, timeout: int = 10, config: dict | None = None, waf_name: str = ""):
        self.timeout = timeout
        self.config = config or {}
        self.waf_name = waf_name
        self.vulnerabilities = []

    def _inject_payload(self, url: str, param: str, payload: str) -> str:
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        params[param] = [payload]
        new_query = urlencode(params, doseq=True)
        return urlunparse(parsed._replace(query=new_query))

    def _has_error(self, text: str) -> bool:
        lower = text.lower()
        return any(sig in lower for sig in ERROR_SIGNATURES)

    async def scan_url(self, url: str, client: httpx.AsyncClient) -> list[dict]:
        results = []
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        if not params:
            return results

        for param in params:
            for payload in PAYLOADS:
                test_url = self._inject_payload(url, param, payload)
                try:
                    resp = await client.get(test_url)
                    if self._has_error(resp.text):
                        vuln = {
                            "type": "SQL Injection",
                            "severity": "HIGH",
                            "url": url,
                            "parameter": param,
                            "payload": payload,
                            "evidence": "Database error detected in response",
                        }
                        results.append(vuln)
                        console.print(f"  [red bold][SQLI FOUND][/red bold] {url} | param={param}")
                        break  # Found vuln in this param, move to next
                except Exception:
                    pass

        return results

    async def scan_form(self, form: dict, client: httpx.AsyncClient) -> list[dict]:
        results = []
        reported = set()  # Suppress duplicate log per (url, input)
        for inp in form["inputs"]:
            if not inp["name"]:
                continue
            for payload in PAYLOADS[:5]:  # Fewer payloads for forms
                data = {i["name"]: i["value"] or "test" for i in form["inputs"]}
                data[inp["name"]] = payload
                try:
                    if form["method"] == "POST":
                        resp = await client.post(form["url"], data=data)
                    else:
                        resp = await client.get(form["url"], params=data)

                    if self._has_error(resp.text):
                        vuln = {
                            "type": "SQL Injection (Form)",
                            "severity": "HIGH",
                            "url": form["url"],
                            "parameter": inp["name"],
                            "payload": payload,
                            "evidence": "Database error in form submission",
                        }
                        results.append(vuln)
                        log_key = f"{form['url']}|{inp['name']}"
                        if log_key not in reported:
                            console.print(f"  [red bold][SQLI FORM][/red bold] {form['url']} | input={inp['name']}")
                            reported.add(log_key)
                        break
                except Exception:
                    pass
        return results