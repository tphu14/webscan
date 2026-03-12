"""
headers.py - Check for missing or misconfigured security headers
"""
import httpx
from rich.console import Console

console = Console()

SECURITY_HEADERS = {
    "X-Frame-Options": {
        "description": "Prevents clickjacking attacks",
        "severity": "MEDIUM",
        "recommended": "DENY or SAMEORIGIN",
    },
    "X-Content-Type-Options": {
        "description": "Prevents MIME sniffing",
        "severity": "LOW",
        "recommended": "nosniff",
    },
    "Strict-Transport-Security": {
        "description": "Enforces HTTPS (HSTS)",
        "severity": "MEDIUM",
        "recommended": "max-age=31536000; includeSubDomains",
    },
    "Content-Security-Policy": {
        "description": "Prevents XSS and data injection",
        "severity": "HIGH",
        "recommended": "default-src 'self'",
    },
    "X-XSS-Protection": {
        "description": "Browser XSS filter (legacy)",
        "severity": "LOW",
        "recommended": "1; mode=block",
    },
    "Referrer-Policy": {
        "description": "Controls referrer information",
        "severity": "LOW",
        "recommended": "strict-origin-when-cross-origin",
    },
    "Permissions-Policy": {
        "description": "Controls browser features access",
        "severity": "LOW",
        "recommended": "geolocation=(), microphone=()",
    },
}

DANGEROUS_HEADERS = {
    "Server": "Exposes server software version",
    "X-Powered-By": "Exposes technology stack",
    "X-AspNet-Version": "Exposes ASP.NET version",
}


class HeadersScanner:
    async def scan(self, url: str, client: httpx.AsyncClient) -> list[dict]:
        results = []
        try:
            resp = await client.get(url)
            headers = {k.lower(): v for k, v in resp.headers.items()}

            # Check missing security headers
            for header, info in SECURITY_HEADERS.items():
                if header.lower() not in headers:
                    results.append({
                        "type": f"Missing Security Header: {header}",
                        "severity": info["severity"],
                        "url": url,
                        "parameter": header,
                        "payload": "N/A",
                        "evidence": f"{info['description']}. Recommended: {info['recommended']}",
                    })

            # Check dangerous headers
            for header, desc in DANGEROUS_HEADERS.items():
                if header.lower() in headers:
                    results.append({
                        "type": f"Information Disclosure: {header}",
                        "severity": "LOW",
                        "url": url,
                        "parameter": header,
                        "payload": "N/A",
                        "evidence": f"{desc}. Value: {headers[header.lower()]}",
                    })

        except Exception as e:
            console.print(f"  [red]Header scan error:[/red] {e}")

        return results
