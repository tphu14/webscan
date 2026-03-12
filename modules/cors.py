"""
cors.py - CORS Misconfiguration detector
Phát hiện: wildcard origin, reflect-any-origin, null origin bypass, credentialed CORS.
"""
import httpx
from rich.console import Console

console = Console()

# Test origins để probe CORS policy
TEST_ORIGINS = [
    "https://evil.com",
    "https://attacker.com",
    "null",
    "https://subdomain.evil.com",
]


class CORSScanner:
    def __init__(self, timeout: int = 10, config: dict | None = None):
        self.timeout = timeout
        self.config  = config or {}

    async def scan(self, base_url: str, urls: list[str], client: httpx.AsyncClient) -> list[dict]:
        results = []
        # Scan base URL + API-like endpoints
        api_candidates = [base_url] + [
            u for u in urls
            if any(x in u for x in ["/api/", "/v1/", "/v2/", "/auth/", "/user", "/account"])
        ][:10]

        seen = set()
        for url in api_candidates:
            if url in seen:
                continue
            seen.add(url)
            url_results = await self._scan_url(url, client)
            results.extend(url_results)

        return results

    async def _scan_url(self, url: str, client: httpx.AsyncClient) -> list[dict]:
        results = []

        for origin in TEST_ORIGINS:
            try:
                resp = await client.get(
                    url,
                    headers={
                        "Origin": origin,
                        "Access-Control-Request-Method": "GET",
                    },
                )
                acao = resp.headers.get("access-control-allow-origin", "")
                acac = resp.headers.get("access-control-allow-credentials", "").lower()

                if not acao:
                    continue

                # Case 1: Wildcard với credentials = impossible but misconfigured
                if acao == "*" and acac == "true":
                    results.append(self._finding(
                        url, origin, acao,
                        "CORS wildcard with credentials=true",
                        "CRITICAL", 0.95, 9.3,
                        "Server returns Access-Control-Allow-Origin: * with Allow-Credentials: true — "
                        "allows any origin to make credentialed requests",
                    ))

                # Case 2: Reflect any origin
                elif acao == origin and origin != "null":
                    if acac == "true":
                        # Worst case: reflect + credentials
                        results.append(self._finding(
                            url, origin, acao,
                            "CORS reflect-any-origin with credentials",
                            "HIGH", 0.90, 8.3,
                            f"Server reflects any Origin value ({origin}) and allows credentials — "
                            "attacker can make authenticated cross-origin requests",
                        ))
                    else:
                        results.append(self._finding(
                            url, origin, acao,
                            "CORS reflect-any-origin (no credentials)",
                            "MEDIUM", 0.85, 6.1,
                            f"Server reflects arbitrary Origin ({origin}) without credentials — "
                            "information disclosure possible",
                        ))

                # Case 3: null origin bypass
                elif origin == "null" and acao == "null":
                    results.append(self._finding(
                        url, origin, acao,
                        "CORS null origin bypass",
                        "HIGH", 0.88, 7.5,
                        "Server trusts 'null' origin — attackers using sandboxed iframes can "
                        "make cross-origin requests",
                    ))

                if results:
                    break  # Đã tìm thấy issue cho URL này

            except Exception:
                pass

        return results

    def _finding(
        self,
        url: str, origin: str, acao: str,
        vuln_type: str, severity: str,
        confidence: float, cvss_score: float,
        evidence: str,
    ) -> dict:
        console.print(f"  [yellow bold][CORS][/yellow bold] {url} | {vuln_type}")
        return {
            "type":        f"CORS Misconfiguration: {vuln_type}",
            "severity":    severity,
            "url":         url,
            "parameter":   "Origin header",
            "payload":     f"Origin: {origin} → ACAO: {acao}",
            "evidence":    evidence,
            "confidence":  confidence,
            "cvss_score":  cvss_score,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N",
            "cwe":         "CWE-942",
        }