"""
sensitive_files.py - Detect exposed sensitive files and directories
"""
import httpx
from rich.console import Console

console = Console()

SENSITIVE_PATHS = [
    # Configs & secrets
    "/.env",
    "/.env.local",
    "/.env.production",
    "/.env.backup",
    "/config.php",
    "/config.yml",
    "/config.yaml",
    "/settings.py",
    "/wp-config.php",
    "/configuration.php",
    # Backups
    "/backup.zip",
    "/backup.tar.gz",
    "/backup.sql",
    "/db.sql",
    "/database.sql",
    "/dump.sql",
    # Common admin
    "/admin",
    "/admin/",
    "/administrator",
    "/phpmyadmin",
    "/phpMyAdmin",
    "/wp-admin",
    "/cpanel",
    # Info files
    "/robots.txt",
    "/sitemap.xml",
    "/.git/HEAD",
    "/.git/config",
    "/.svn/entries",
    "/server-info",
    "/server-status",
    # Common logs
    "/error.log",
    "/access.log",
    "/debug.log",
    "/application.log",
    # API
    "/api/v1/users",
    "/api/users",
    "/swagger.json",
    "/swagger-ui.html",
    "/api-docs",
    "/openapi.json",
]

# Content patterns indicating real exposure
SENSITIVE_PATTERNS = {
    "/.git/HEAD": "ref:",
    "/.git/config": "[core]",
    "/.env": "=",
    "/wp-config.php": "DB_",
    "/phpinfo.php": "PHP Version",
}


class SensitiveFileScanner:
    def __init__(self, timeout: int = 8):
        self.timeout = timeout

    async def scan(self, base_url: str, client: httpx.AsyncClient) -> list[dict]:
        results = []
        base = base_url.rstrip("/")

        for path in SENSITIVE_PATHS:
            url = base + path
            try:
                resp = await client.get(url)
                if resp.status_code in (200, 403):
                    severity = "HIGH" if resp.status_code == 200 else "LOW"
                    evidence = f"HTTP {resp.status_code}"

                    # Check for real content
                    pattern = SENSITIVE_PATTERNS.get(path)
                    if pattern and pattern in resp.text:
                        severity = "CRITICAL"
                        evidence = f"Sensitive content exposed: found '{pattern}'"

                    vuln = {
                        "type": "Sensitive File Exposure",
                        "severity": severity,
                        "url": url,
                        "parameter": "N/A",
                        "payload": path,
                        "evidence": evidence,
                    }
                    results.append(vuln)
                    color = "red" if severity == "CRITICAL" else "yellow"
                    console.print(f"  [{color} bold][FILE EXPOSED][/{color} bold] {url} [{resp.status_code}]")

            except Exception:
                pass

        return results
