"""
csrf.py - Cross-Site Request Forgery (CSRF) detector
Phân tích forms để phát hiện thiếu CSRF token hoặc CSRF protection yếu.
"""
import httpx
import re
from urllib.parse import urlparse
from rich.console import Console

console = Console()

# Tên các CSRF token field phổ biến
CSRF_TOKEN_NAMES = [
    "csrf", "csrftoken", "csrf_token", "_csrf", "_token",
    "authenticity_token", "csrf_middleware_token",
    "__requestverificationtoken", "xsrf_token", "_xsrf",
    "antiforgery", "anti_forgery", "nonce", "form_token",
    "token", "verify_token", "state",
]

# CSRF header names
CSRF_HEADERS = [
    "x-csrf-token", "x-xsrf-token", "x-requested-with",
    "x-csrftoken", "csrf-token", "anti-forgery-token",
]

# Method patterns: chỉ POST/PUT/DELETE mới cần CSRF protection
PROTECTED_METHODS = {"POST", "PUT", "DELETE", "PATCH"}


class CSRFScanner:
    def __init__(self, timeout: int = 10, config: dict | None = None):
        self.timeout = timeout
        self.config  = config or {}

    def _has_csrf_token(self, form: dict) -> tuple[bool, str]:
        """Kiểm tra form có CSRF token field không."""
        for inp in form["inputs"]:
            name_lower = inp.get("name", "").lower()
            if any(csrf_name in name_lower for csrf_name in CSRF_TOKEN_NAMES):
                return True, f"CSRF token found: '{inp['name']}'"

        # Check hidden fields với value trông như token (random string)
        for inp in form["inputs"]:
            if inp.get("type") == "hidden" and inp.get("value"):
                val = inp["value"]
                # Token thường dài và có ký tự random
                if len(val) >= 16 and re.search(r"[A-Za-z0-9+/=_-]{16,}", val):
                    return True, f"Potential token in hidden field: '{inp.get('name', 'unnamed')}'"

        return False, ""

    def _has_samesite_cookie(self, resp: httpx.Response) -> bool:
        """Kiểm tra cookies có SameSite attribute không."""
        for header_name, header_val in resp.headers.items():
            if header_name.lower() == "set-cookie":
                if "samesite=strict" in header_val.lower() or "samesite=lax" in header_val.lower():
                    return True
        return False

    def _form_has_sensitive_action(self, form: dict) -> bool:
        """Heuristic: form URL có vẻ là sensitive action không."""
        url_lower = form["url"].lower()
        sensitive_keywords = [
            "password", "passwd", "email", "account", "profile",
            "settings", "admin", "delete", "remove", "update",
            "change", "transfer", "payment", "checkout", "order",
            "submit", "post", "create", "login", "register",
        ]
        return any(kw in url_lower for kw in sensitive_keywords)

    async def scan_forms(self, forms: list[dict], client: httpx.AsyncClient) -> list[dict]:
        results = []
        seen_urls = set()

        for form in forms:
            method = form.get("method", "GET").upper()

            # Chỉ quan tâm POST/PUT/DELETE forms
            if method not in PROTECTED_METHODS:
                continue

            # Tránh duplicate URL
            form_key = f"{form['url']}:{method}"
            if form_key in seen_urls:
                continue
            seen_urls.add(form_key)

            has_token, token_evidence = self._has_csrf_token(form)
            is_sensitive = self._form_has_sensitive_action(form)

            # Check SameSite cookie từ page
            try:
                resp = await client.get(form.get("source_page", form["url"]))
                has_samesite = self._has_samesite_cookie(resp)
            except Exception:
                has_samesite = False

            if not has_token:
                # Không có CSRF token
                severity   = "HIGH" if is_sensitive else "MEDIUM"
                confidence = 0.85   if is_sensitive else 0.65

                # Nếu có SameSite cookie, giảm severity (partial protection)
                if has_samesite:
                    severity   = "LOW"
                    confidence = 0.50
                    evidence   = (
                        f"No CSRF token found in {method} form, but SameSite cookie "
                        f"provides partial protection. Form inputs: "
                        f"{[i['name'] for i in form['inputs'] if i['name']]}"
                    )
                else:
                    evidence = (
                        f"No CSRF token in {method} form — "
                        f"{'sensitive action detected, ' if is_sensitive else ''}"
                        f"no SameSite cookie protection. "
                        f"Inputs: {[i['name'] for i in form['inputs'] if i['name']]}"
                    )

                console.print(
                    f"  [yellow bold][CSRF][/yellow bold] {form['url']} | "
                    f"method={method} | severity={severity}"
                )
                results.append({
                    "type":        "Cross-Site Request Forgery (CSRF)",
                    "severity":    severity,
                    "url":         form["url"],
                    "parameter":   "form",
                    "payload":     f"{method} form without CSRF token",
                    "evidence":    evidence,
                    "confidence":  confidence,
                    "cvss_score":  6.5 if severity == "HIGH" else 4.3,
                    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N",
                    "cwe":         "CWE-352",
                })

            elif has_token:
                # Có token nhưng kiểm tra độ mạnh
                await self._verify_token_strength(form, has_token, token_evidence, client, results)

        return results

    async def _verify_token_strength(
        self,
        form: dict,
        has_token: bool,
        evidence: str,
        client: httpx.AsyncClient,
        results: list,
    ):
        """Thử submit form với token sai để xem server có validate không."""
        method = form.get("method", "POST").upper()

        # Tạo data với fake CSRF token
        data = {}
        fake_token_field = None
        for inp in form["inputs"]:
            if inp.get("name"):
                name_lower = inp["name"].lower()
                if any(csrf in name_lower for csrf in CSRF_TOKEN_NAMES):
                    data[inp["name"]] = "INVALID_CSRF_TOKEN_12345"
                    fake_token_field  = inp["name"]
                else:
                    data[inp["name"]] = inp.get("value") or "test"

        if not fake_token_field:
            return

        try:
            if method == "POST":
                resp = await client.post(form["url"], data=data)
            else:
                resp = await client.get(form["url"], params=data)

            # Nếu server trả 200 với token sai → token không được validate đúng
            if resp.status_code == 200 and "error" not in resp.text.lower() and "invalid" not in resp.text.lower():
                console.print(
                    f"  [yellow bold][CSRF WEAK TOKEN][/yellow bold] {form['url']} | "
                    f"Server accepted invalid CSRF token"
                )
                results.append({
                    "type":        "CSRF Token Not Validated",
                    "severity":    "HIGH",
                    "url":         form["url"],
                    "parameter":   fake_token_field,
                    "payload":     "INVALID_CSRF_TOKEN_12345",
                    "evidence":    f"Server returned HTTP 200 with invalid CSRF token in field '{fake_token_field}'",
                    "confidence":  0.75,
                    "cvss_score":  7.5,
                    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N",
                    "cwe":         "CWE-352",
                })
        except Exception:
            pass