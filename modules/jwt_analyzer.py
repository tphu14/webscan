"""
jwt_analyzer.py - JWT Security Analyzer
Phát hiện: alg:none, weak secret, algorithm confusion, missing validation.
"""
import base64
import json
import hmac
import hashlib
import httpx
import re
from rich.console import Console

console = Console()

# Weak secrets thường gặp
WEAK_SECRETS = [
    "secret", "password", "123456", "qwerty", "admin",
    "test", "changeme", "default", "key", "mykey",
    "supersecret", "jwt_secret", "jwtkey", "letmein",
    "abc123", "1234567890", "your-256-bit-secret",
    "your-secret-key", "random-secret-key", "secret123",
    "", "null", "undefined",
]

# None algorithm variants để bypass validation
ALG_NONE_VARIANTS = [
    "none", "None", "NONE", "nOnE",
    "HS256", "RS256",  # Sẽ được swap sang none
]


def _b64_decode(data: str) -> bytes:
    """Base64url decode với padding."""
    data += "=" * (4 - len(data) % 4)
    return base64.urlsafe_b64decode(data)


def _b64_encode(data: bytes) -> str:
    """Base64url encode không có padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _parse_jwt(token: str) -> tuple[dict, dict, str] | None:
    """Parse JWT → (header, payload, signature). Trả None nếu invalid."""
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        header  = json.loads(_b64_decode(parts[0]))
        payload = json.loads(_b64_decode(parts[1]))
        return header, payload, parts[2]
    except Exception:
        return None


def _make_jwt(header: dict, payload: dict, secret: str = "") -> str:
    """Tạo JWT với HMAC-SHA256."""
    h = _b64_encode(json.dumps(header, separators=(",", ":")).encode())
    p = _b64_encode(json.dumps(payload, separators=(",", ":")).encode())
    msg = f"{h}.{p}".encode()
    sig = hmac.new(secret.encode(), msg, hashlib.sha256).digest()
    return f"{h}.{p}.{_b64_encode(sig)}"


def _make_none_jwt(header: dict, payload: dict) -> str:
    """Tạo JWT với alg:none (không có signature)."""
    header_none = dict(header)
    header_none["alg"] = "none"
    h = _b64_encode(json.dumps(header_none, separators=(",", ":")).encode())
    p = _b64_encode(json.dumps(payload, separators=(",", ":")).encode())
    return f"{h}.{p}."


def _extract_jwt_from_response(text: str) -> list[str]:
    """Tìm JWT tokens trong HTTP response body."""
    pattern = re.compile(
        r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*"
    )
    return pattern.findall(text)


def _extract_jwt_from_headers(headers: dict) -> list[str]:
    """Tìm JWT trong Authorization header."""
    tokens = []
    auth = headers.get("authorization", "")
    if auth.lower().startswith("bearer "):
        tokens.append(auth[7:].strip())
    return tokens


class JWTAnalyzer:
    def __init__(self, timeout: int = 10, config: dict | None = None):
        self.timeout = timeout
        self.config  = config or {}

    async def scan(self, base_url: str, client: httpx.AsyncClient) -> list[dict]:
        results = []

        # Collect JWT tokens từ các response
        tokens_found = await self._collect_tokens(base_url, client)

        for token, source_url in tokens_found:
            parsed = _parse_jwt(token)
            if not parsed:
                continue
            header, payload, signature = parsed

            console.print(
                f"  [cyan]→ JWT found[/cyan] at {source_url} | "
                f"alg={header.get('alg','?')}"
            )

            # Test 1: alg:none bypass
            none_result = await self._test_alg_none(
                token, header, payload, base_url, source_url, client
            )
            if none_result:
                results.append(none_result)

            # Test 2: Weak secret brute-force
            weak_result = self._test_weak_secret(token, header, payload, signature, source_url)
            if weak_result:
                results.append(weak_result)

            # Test 3: Static analysis (không cần request)
            static_results = self._static_analysis(header, payload, source_url)
            results.extend(static_results)

        return results

    async def _collect_tokens(
        self, base_url: str, client: httpx.AsyncClient
    ) -> list[tuple[str, str]]:
        """Collect JWTs từ base URL và common endpoints."""
        tokens = []
        endpoints = [
            base_url,
            base_url + "/api/me",
            base_url + "/api/user",
            base_url + "/api/profile",
            base_url + "/auth/token",
            base_url + "/login",
        ]
        for url in endpoints:
            try:
                resp = await client.get(url)
                found = _extract_jwt_from_response(resp.text)
                found += _extract_jwt_from_headers(dict(resp.headers))
                for t in found:
                    tokens.append((t, url))
            except Exception:
                pass
        return tokens

    async def _test_alg_none(
        self,
        token: str,
        header: dict,
        payload: dict,
        base_url: str,
        source_url: str,
        client: httpx.AsyncClient,
    ) -> dict | None:
        """Test alg:none bypass — server có chấp nhận token không có chữ ký không."""
        none_token = _make_none_jwt(header, payload)

        try:
            resp = await client.get(
                source_url,
                headers={"Authorization": f"Bearer {none_token}"},
            )
            # Nếu server vẫn trả 200 với token alg:none → vulnerable
            if resp.status_code == 200 and len(resp.text) > 50:
                console.print(
                    f"  [red bold][JWT ALG:NONE][/red bold] {source_url} | "
                    f"Server accepted unsigned token!"
                )
                return {
                    "type":        "JWT Algorithm None Bypass",
                    "severity":    "CRITICAL",
                    "url":         source_url,
                    "parameter":   "Authorization: Bearer",
                    "payload":     none_token[:80] + "...",
                    "evidence":    "Server accepted JWT with alg:none — signature validation disabled",
                    "confidence":  0.92,
                    "cvss_score":  9.8,
                    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    "cwe":         "CWE-347",
                }
        except Exception:
            pass
        return None

    def _test_weak_secret(
        self,
        token: str,
        header: dict,
        payload: dict,
        signature: str,
        source_url: str,
    ) -> dict | None:
        """Brute-force weak HMAC secret."""
        if header.get("alg", "").upper() not in ("HS256", "HS384", "HS512"):
            return None

        parts    = token.split(".")
        msg      = f"{parts[0]}.{parts[1]}".encode()
        alg_map  = {
            "HS256": hashlib.sha256,
            "HS384": hashlib.sha384,
            "HS512": hashlib.sha512,
        }
        hash_fn  = alg_map.get(header["alg"].upper(), hashlib.sha256)

        for secret in WEAK_SECRETS:
            expected_sig = _b64_encode(
                hmac.new(secret.encode(), msg, hash_fn).digest()
            )
            if expected_sig == signature:
                console.print(
                    f"  [red bold][JWT WEAK SECRET][/red bold] {source_url} | "
                    f"Secret='{secret}'"
                )
                return {
                    "type":        "JWT Weak Secret",
                    "severity":    "CRITICAL",
                    "url":         source_url,
                    "parameter":   "Authorization: Bearer",
                    "payload":     f"alg={header.get('alg')} | secret='{secret}'",
                    "evidence": (
                        f"JWT HMAC secret cracked: '{secret}'. "
                        f"Attacker can forge arbitrary tokens."
                    ),
                    "confidence":  0.99,
                    "cvss_score":  9.8,
                    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    "cwe":         "CWE-321",
                }
        return None

    def _static_analysis(
        self, header: dict, payload: dict, source_url: str
    ) -> list[dict]:
        """Phân tích tĩnh JWT không cần gửi request."""
        results = []

        # Check không có expiration
        if "exp" not in payload:
            results.append({
                "type":        "JWT Missing Expiration (exp)",
                "severity":    "MEDIUM",
                "url":         source_url,
                "parameter":   "JWT payload",
                "payload":     "Missing 'exp' claim",
                "evidence":    "JWT has no expiration claim — tokens never expire",
                "confidence":  0.95,
                "cvss_score":  5.3,
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                "cwe":         "CWE-613",
            })

        # Check weak algorithm
        alg = header.get("alg", "").upper()
        if alg in ("HS256",):
            # HS256 là symmetric — nếu secret leak thì toàn bộ JWT bị compromise
            results.append({
                "type":        "JWT Symmetric Algorithm (HS256)",
                "severity":    "LOW",
                "url":         source_url,
                "parameter":   "JWT header.alg",
                "payload":     f"alg={alg}",
                "evidence":    "Symmetric algorithm HS256 used. Consider RS256/ES256 for better key separation.",
                "confidence":  0.90,
                "cvss_score":  3.1,
                "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
                "cwe":         "CWE-327",
            })

        # Check sensitive data in payload
        sensitive_keys = ["password", "passwd", "secret", "credit_card", "ssn", "cvv"]
        for key in sensitive_keys:
            if key in str(payload).lower():
                results.append({
                    "type":        "Sensitive Data in JWT Payload",
                    "severity":    "HIGH",
                    "url":         source_url,
                    "parameter":   "JWT payload",
                    "payload":     f"Found key: {key}",
                    "evidence":    f"Sensitive field '{key}' found in JWT payload (base64-decoded, not encrypted)",
                    "confidence":  0.90,
                    "cvss_score":  7.5,
                    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                    "cwe":         "CWE-312",
                })
                break

        return results