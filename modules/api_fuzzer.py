"""
api_fuzzer.py - REST API Endpoint Fuzzer
Tự động khám phá và fuzz các API endpoints ẩn, test authorization bypass.
"""
import httpx
import json
from urllib.parse import urlparse, urljoin
from rich.console import Console

console = Console()

# Common API endpoint patterns
API_WORDLIST = [
    # Auth
    "/api/login", "/api/logout", "/api/register", "/api/auth",
    "/api/token", "/api/refresh", "/api/reset-password",
    # Users
    "/api/users", "/api/users/me", "/api/user", "/api/profile",
    "/api/account", "/api/accounts", "/api/members",
    # Admin
    "/api/admin", "/api/admin/users", "/api/admin/config",
    "/api/dashboard", "/api/settings", "/api/config",
    # Data
    "/api/data", "/api/records", "/api/export",
    "/api/reports", "/api/logs", "/api/audit",
    # Versioned
    "/api/v1/users", "/api/v2/users", "/api/v1/admin",
    "/api/v1/config", "/api/v1/health", "/api/v1/status",
    # Common
    "/api/health", "/api/status", "/api/version", "/api/info",
    "/api/ping", "/api/metrics", "/api/debug",
    # Files
    "/api/files", "/api/upload", "/api/download",
    "/api/images", "/api/attachments",
]

# HTTP methods để test mỗi endpoint
METHODS_TO_TEST = ["GET", "POST", "PUT", "DELETE", "PATCH"]

# Headers để test auth bypass
AUTH_BYPASS_HEADERS = [
    {},  # No auth
    {"X-Original-URL": "/admin"},
    {"X-Rewrite-URL": "/admin"},
    {"X-Custom-IP-Authorization": "127.0.0.1"},
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Remote-IP": "127.0.0.1"},
    {"X-Client-IP": "127.0.0.1"},
    {"X-Real-IP": "127.0.0.1"},
]


class APIFuzzer:
    def __init__(self, timeout: int = 8, config: dict | None = None):
        self.timeout = timeout
        self.config  = config or {}

    async def scan(self, base_url: str, client: httpx.AsyncClient) -> list[dict]:
        results  = []
        base     = base_url.rstrip("/")
        found_apis = []

        # Step 1: Discover endpoints
        console.print(f"  [dim]→ Fuzzing {len(API_WORDLIST)} API endpoints...[/dim]")
        for path in API_WORDLIST:
            url = base + path
            try:
                resp = await client.get(url, follow_redirect=False)
                if resp.status_code not in (404, 410):
                    found_apis.append((url, resp.status_code))
                    if resp.status_code in (200, 201):
                        console.print(
                            f"  [green]→ API found:[/green] {url} [{resp.status_code}]"
                        )
            except Exception:
                pass

        # Step 2: Analyze found endpoints
        for url, status in found_apis:
            # Test unauthorized access
            if status == 200:
                unauth_result = await self._test_unauthorized(url, client)
                if unauth_result:
                    results.append(unauth_result)

            # Test auth bypass headers
            if status in (401, 403):
                bypass_result = await self._test_auth_bypass(url, status, client)
                if bypass_result:
                    results.append(bypass_result)

            # Test HTTP method confusion
            method_result = await self._test_method_confusion(url, client)
            if method_result:
                results.append(method_result)

        return results

    async def _test_unauthorized(
        self, url: str, client: httpx.AsyncClient
    ) -> dict | None:
        """API endpoint accessible without authentication."""
        try:
            resp = await client.get(url, headers={})  # No auth headers

            if resp.status_code == 200:
                # Check nếu response trông như sensitive data
                body_lower = resp.text.lower()
                sensitive  = ["password", "email", "token", "secret", "api_key",
                              "admin", "config", "user", "account", "credit"]

                found = [s for s in sensitive if s in body_lower]
                if found or len(resp.text) > 100:
                    console.print(
                        f"  [yellow bold][API UNAUTH][/yellow bold] {url} | "
                        f"accessible without auth"
                    )
                    return {
                        "type":        "API Endpoint Exposed Without Authentication",
                        "severity":    "HIGH" if found else "MEDIUM",
                        "url":         url,
                        "parameter":   "Authorization header",
                        "payload":     "No authentication",
                        "evidence": (
                            f"API endpoint returns HTTP 200 without credentials"
                            + (f". Sensitive keywords: {found}" if found else "")
                        ),
                        "confidence":  0.80,
                        "cvss_score":  7.5 if found else 5.3,
                        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                        "cwe":         "CWE-306",
                    }
        except Exception:
            pass
        return None

    async def _test_auth_bypass(
        self, url: str, original_status: int, client: httpx.AsyncClient
    ) -> dict | None:
        """Test các header tricks để bypass 401/403."""
        for bypass_headers in AUTH_BYPASS_HEADERS[1:]:  # Skip empty headers
            try:
                resp = await client.get(url, headers=bypass_headers)
                if resp.status_code == 200 and len(resp.text) > 50:
                    header_used = list(bypass_headers.keys())[0]
                    console.print(
                        f"  [red bold][AUTH BYPASS][/red bold] {url} | "
                        f"via {header_used}"
                    )
                    return {
                        "type":        "API Authentication Bypass via Header",
                        "severity":    "CRITICAL",
                        "url":         url,
                        "parameter":   header_used,
                        "payload":     str(bypass_headers),
                        "evidence": (
                            f"Original response: HTTP {original_status}. "
                            f"With header {bypass_headers}: HTTP 200. "
                            "Authorization control bypassed."
                        ),
                        "confidence":  0.88,
                        "cvss_score":  9.1,
                        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                        "cwe":         "CWE-284",
                    }
            except Exception:
                pass
        return None

    async def _test_method_confusion(
        self, url: str, client: httpx.AsyncClient
    ) -> dict | None:
        """Test nếu DELETE/PUT không có auth protection."""
        for method in ["DELETE", "PUT"]:
            try:
                if method == "DELETE":
                    resp = await client.delete(url)
                else:
                    resp = await client.put(url, json={})

                # 200/204 với method nguy hiểm mà không có auth = vấn đề
                if resp.status_code in (200, 204):
                    console.print(
                        f"  [yellow bold][HTTP METHOD][/yellow bold] {url} | "
                        f"{method} returned {resp.status_code}"
                    )
                    return {
                        "type":        f"Unprotected HTTP {method} Method",
                        "severity":    "HIGH",
                        "url":         url,
                        "parameter":   "HTTP Method",
                        "payload":     f"{method} {url}",
                        "evidence": (
                            f"HTTP {method} returns {resp.status_code} without authentication — "
                            "destructive operations may be possible"
                        ),
                        "confidence":  0.72,
                        "cvss_score":  8.1,
                        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H",
                        "cwe":         "CWE-650",
                    }
            except Exception:
                pass
        return None