"""
subdomain_takeover.py - Subdomain Takeover detector
Phát hiện subdomains trỏ đến services đã bị xóa/unclaimed.

Kỹ thuật:
1. Enumerate subdomains từ common wordlist
2. Kiểm tra DNS resolve (CNAME → external service)
3. Kiểm tra service có "unclaimed" fingerprint không
"""
import asyncio
import socket
import httpx
import re
from rich.console import Console

console = Console()

# Common subdomain wordlist
SUBDOMAIN_WORDLIST = [
    "www", "mail", "remote", "blog", "webmail", "server",
    "ns1", "ns2", "smtp", "secure", "vpn", "m", "shop",
    "ftp", "mail2", "test", "portal", "ns", "ww1", "host",
    "support", "dev", "beta", "api", "staging", "admin",
    "app", "docs", "status", "cdn", "media", "assets",
    "help", "forum", "store", "old", "new", "legacy",
    "demo", "preview", "v2", "dashboard", "analytics",
    "static", "images", "img", "login", "auth", "sso",
]

# Fingerprints của services hay bị subdomain takeover
# Format: (service_name, cname_pattern, fingerprint_in_body)
TAKEOVER_FINGERPRINTS = [
    ("GitHub Pages",    r"github\.io",           "There isn't a GitHub Pages site here"),
    ("Heroku",         r"herokuapp\.com",        "No such app"),
    ("Shopify",        r"myshopify\.com",        "Sorry, this shop is currently unavailable"),
    ("Fastly",         r"fastly\.net",           "Fastly error: unknown domain"),
    ("Ghost",          r"ghost\.io",             "The thing you were looking for is no longer here"),
    ("Surge.sh",       r"surge\.sh",             "project not found"),
    ("Zendesk",        r"zendesk\.com",          "Help Center Closed"),
    ("HubSpot",        r"hubspot\.com",          "Domain not found"),
    ("Tumblr",         r"tumblr\.com",           "Whatever you were looking for doesn't live here"),
    ("WordPress.com",  r"wordpress\.com",        "Do you want to register"),
    ("Pantheon",       r"pantheonsite\.io",      "The gods are wise"),
    ("Amazon S3",      r"s3\.amazonaws\.com",    "NoSuchBucket"),
    ("Amazon CloudFront", r"cloudfront\.net",    "Bad request"),
    ("Azure",          r"azurewebsites\.net",    "404 Web Site not found"),
    ("Netlify",        r"netlify\.app",          "Not Found - Request ID"),
    ("Vercel",         r"vercel\.app",           "The deployment could not be found"),
    ("ReadTheDocs",    r"readthedocs\.io",       "isn't found here"),
    ("Intercom",       r"custom\.intercom\.io",  "This page is reserved for artistic"),
    ("Helpjuice",      r"helpjuice\.com",        "We could not find what you're looking for"),
    ("UserVoice",      r"uservoice\.com",        "This UserVoice subdomain is currently available"),
    ("Pingdom",        r"pingdom\.com",          "Sorry, couldn't find the status page"),
    ("Strikingly",     r"strikingly\.com",       "page not found"),
    ("Unbounce",       r"unbouncepages\.com",    "The requested URL was not found on this server"),
    ("Tilda",          r"tilda\.ws",             "Please renew your subscription"),
]


def _resolve_cname(hostname: str) -> str | None:
    """DNS lookup để lấy CNAME."""
    try:
        # getaddrinfo không trả CNAME, dùng socket để check nếu resolve được
        socket.gethostbyname(hostname)
        # Simple approach: check nếu hostname resolve
        return hostname
    except socket.gaierror:
        return None  # NXDOMAIN → unclaimed subdomain


async def _check_takeover(
    subdomain: str,
    base_domain: str,
    client: httpx.AsyncClient,
) -> dict | None:
    """Kiểm tra 1 subdomain có bị takeover không."""
    full_domain = f"{subdomain}.{base_domain}"

    # Step 1: DNS check
    try:
        loop = asyncio.get_event_loop()
        resolved = await loop.run_in_executor(None, socket.gethostbyname, full_domain)
    except socket.gaierror:
        # NXDOMAIN — subdomain không tồn tại
        return None

    # Step 2: HTTP request để check fingerprint
    for url_scheme in [f"https://{full_domain}", f"http://{full_domain}"]:
        try:
            resp = await client.get(url_scheme, timeout=8, follow_redirects=True)
            body = resp.text

            # Check từng service fingerprint
            for service, cname_pattern, fingerprint in TAKEOVER_FINGERPRINTS:
                # Check nếu resolved IP/domain trông như service này
                if re.search(cname_pattern, full_domain, re.IGNORECASE):
                    if fingerprint.lower() in body.lower():
                        return {
                            "type":        f"Subdomain Takeover — {service}",
                            "severity":    "HIGH",
                            "url":         url_scheme,
                            "parameter":   "DNS/CNAME",
                            "payload":     full_domain,
                            "evidence": (
                                f"Subdomain '{full_domain}' resolves to {service} "
                                f"but shows unclaimed fingerprint: '{fingerprint}'"
                            ),
                            "confidence":  0.88,
                            "cvss_score":  8.1,
                            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                            "cwe":         "CWE-284",
                        }

                # Kiểm tra body fingerprint dù không match CNAME pattern
                elif fingerprint.lower() in body.lower():
                    if resp.status_code in (404, 410, 200):
                        return {
                            "type":        f"Potential Subdomain Takeover — {service}",
                            "severity":    "MEDIUM",
                            "url":         url_scheme,
                            "parameter":   "DNS",
                            "payload":     full_domain,
                            "evidence": (
                                f"Subdomain '{full_domain}' shows {service} "
                                f"'unclaimed' fingerprint (HTTP {resp.status_code})"
                            ),
                            "confidence":  0.65,
                            "cvss_score":  6.5,
                            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
                            "cwe":         "CWE-284",
                        }
            break  # Chỉ cần check 1 scheme thành công

        except Exception:
            continue

    return None


class SubdomainTakeoverScanner:
    def __init__(self, timeout: int = 8, config: dict | None = None):
        self.timeout = timeout
        self.config  = config or {}
        self.max_subdomains = config.get("subdomain_limit", 30) if config else 30

    async def scan(self, base_url: str, client: httpx.AsyncClient) -> list[dict]:
        results = []
        parsed  = httpx.URL(base_url)
        host    = parsed.host

        # Lấy base domain (bỏ subdomain nếu có)
        parts = host.split(".")
        if len(parts) >= 2:
            base_domain = ".".join(parts[-2:])
        else:
            return results

        console.print(
            f"  [dim]→ Checking {min(self.max_subdomains, len(SUBDOMAIN_WORDLIST))} "
            f"subdomains for {base_domain}...[/dim]"
        )

        # Scan theo batch để tránh quá nhiều concurrent requests
        wordlist = SUBDOMAIN_WORDLIST[:self.max_subdomains]
        batch_size = 10

        for i in range(0, len(wordlist), batch_size):
            batch = wordlist[i:i + batch_size]
            tasks = [
                _check_takeover(sub, base_domain, client)
                for sub in batch
            ]
            batch_results = await asyncio.gather(*tasks, return_exceptions=True)
            for result in batch_results:
                if isinstance(result, dict):
                    console.print(
                        f"  [yellow bold][SUBDOMAIN TAKEOVER][/yellow bold] "
                        f"{result['url']} | {result['type']}"
                    )
                    results.append(result)

        return results