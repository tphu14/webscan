"""
crawler.py - Auto crawl all URLs from a target website
"""
import asyncio
from urllib.parse import urljoin, urlparse
from collections import deque
import httpx
from bs4 import BeautifulSoup
from rich.console import Console

console = Console()


class Crawler:
    def __init__(self, base_url: str, max_depth: int = 3, max_pages: int = 100, timeout: int = 10):
        self.base_url = base_url.rstrip("/")
        self.base_domain = urlparse(base_url).netloc
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.timeout = timeout
        self.visited: set[str] = set()
        self.found_urls: list[str] = []
        self.forms: list[dict] = []

    def _is_same_domain(self, url: str) -> bool:
        return urlparse(url).netloc == self.base_domain

    def _normalize_url(self, url: str) -> str:
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

    def _extract_links(self, html: str, current_url: str) -> list[str]:
        soup = BeautifulSoup(html, "lxml")
        links = []
        for tag in soup.find_all("a", href=True):
            href = tag["href"]
            full_url = urljoin(current_url, href)
            normalized = self._normalize_url(full_url)
            if self._is_same_domain(normalized) and normalized not in self.visited:
                links.append(normalized)
        return links

    def _extract_forms(self, html: str, current_url: str):
        soup = BeautifulSoup(html, "lxml")
        for form in soup.find_all("form"):
            action = form.get("action", "")
            method = form.get("method", "get").upper()
            full_action = urljoin(current_url, action) if action else current_url
            inputs = []
            for inp in form.find_all(["input", "textarea", "select"]):
                inputs.append({
                    "name": inp.get("name", ""),
                    "type": inp.get("type", "text"),
                    "value": inp.get("value", ""),
                })
            self.forms.append({
                "url": full_action,
                "method": method,
                "inputs": inputs,
                "source_page": current_url,
            })

    async def crawl(self) -> dict:
        queue = deque([(self.base_url, 0)])
        self.visited.add(self.base_url)

        async with httpx.AsyncClient(
            timeout=self.timeout,
            follow_redirects=True,
            headers={"User-Agent": "WebVulnScanner/1.0 (Educational)"},
            verify=False,
        ) as client:
            while queue and len(self.found_urls) < self.max_pages:
                url, depth = queue.popleft()
                try:
                    console.print(f"  [dim]Crawling:[/dim] {url}")
                    resp = await client.get(url)
                    if "text/html" not in resp.headers.get("content-type", ""):
                        continue

                    self.found_urls.append(url)
                    html = resp.text
                    self._extract_forms(html, url)

                    if depth < self.max_depth:
                        for link in self._extract_links(html, url):
                            if link not in self.visited:
                                self.visited.add(link)
                                queue.append((link, depth + 1))

                except Exception as e:
                    console.print(f"  [yellow]Skip[/yellow] {url}: {e}")

        return {
            "urls": self.found_urls,
            "forms": self.forms,
            "total_urls": len(self.found_urls),
            "total_forms": len(self.forms),
        }
