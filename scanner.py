"""
scanner.py - Core Engine Phase 2
Tích hợp đầy đủ: WAF → Crawl → Phase1 modules → Phase2 modules
Phase 2 adds: Time-based SQLi, SSRF, CSRF, IDOR, JWT, CORS, GraphQL, API Fuzzer
"""
import asyncio
import httpx
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn

from core.crawler import Crawler

# ── Phase 1 optional imports ─────────────────────────────────────────────────
try:
    from core.scheduler.rate_limiter import TokenBucketRateLimiter
    _HAS_RATE_LIMITER = True
except ImportError:
    _HAS_RATE_LIMITER = False

try:
    from detection.waf_detector import WAFDetector
    _HAS_WAF = True
except ImportError:
    _HAS_WAF = False

try:
    from detection.cvss_calculator import CVSSCalculator
    _HAS_CVSS = True
except ImportError:
    _HAS_CVSS = False

try:
    from utils.config_loader import load_config
    _HAS_CONFIG = True
except ImportError:
    _HAS_CONFIG = False

# ── Phase 1 modules ──────────────────────────────────────────────────────────
from modules.sqli import SQLiScanner
from modules.xss import XSSScanner
from modules.sensitive_files import SensitiveFileScanner
from modules.open_redirect import OpenRedirectScanner
from modules.headers import HeadersScanner

# ── Phase 2 modules ──────────────────────────────────────────────────────────
from modules.sqli_blind_time import TimeSQLiScanner
from modules.ssrf import SSRFScanner
from modules.csrf import CSRFScanner
from modules.idor import IDORScanner
from modules.jwt_analyzer import JWTAnalyzer
from modules.cors import CORSScanner
from modules.graphql import GraphQLScanner
from modules.api_fuzzer import APIFuzzer

from reports.generator import ReportGenerator

console = Console()


def _default_config() -> dict:
    return {
        "scanner": {
            "max_depth": 3, "max_pages": 50, "timeout": 10,
            "concurrency": 8, "rate_limit": 8.0, "burst": 15,
            "user_agent": "WebVulnScanner/2.0 (Security Research)",
            "verify_ssl": False, "follow_redirects": True,
        },
        "modules": {
            "sqli": True, "xss": True, "sensitive_files": True,
            "open_redirect": True, "headers": True, "waf_detect": True,
            "time_sqli": True, "ssrf": True, "csrf": True,
            "idor": True, "jwt": True, "cors": True,
            "graphql": True, "api_fuzzer": True,
        },
        "detection": {
            "use_response_differ": True, "use_payload_mutator": True,
            "confidence_threshold": 0.65, "differ_threshold": 0.93,
        },
        "reporting": {"cvss_scoring": True, "include_waf_info": True},
        "logging": {"level": "INFO", "log_file": None},
    }


class Scanner:
    def __init__(
        self,
        target: str,
        config_path: str | None = None,
        max_depth: int | None = None,
        max_pages: int | None = None,
        timeout: int | None = None,
        # Phase 1
        scan_sqli: bool = True,
        scan_xss: bool = True,
        scan_files: bool = True,
        scan_redirect: bool = True,
        scan_headers: bool = True,
        # Phase 2
        scan_time_sqli: bool = True,
        scan_ssrf: bool = True,
        scan_csrf: bool = True,
        scan_idor: bool = True,
        scan_jwt: bool = True,
        scan_cors: bool = True,
        scan_graphql: bool = True,
        scan_api: bool = True,
    ):
        self.target = target.rstrip("/")
        self.config = load_config(config_path) if _HAS_CONFIG else _default_config()

        sc = self.config["scanner"]
        self.max_depth = max_depth or sc["max_depth"]
        self.max_pages = max_pages or sc["max_pages"]
        self.timeout   = timeout   or sc["timeout"]

        mod = self.config["modules"]
        self.options = {
            "sqli":     scan_sqli     and mod.get("sqli", True),
            "xss":      scan_xss      and mod.get("xss", True),
            "files":    scan_files    and mod.get("sensitive_files", True),
            "redirect": scan_redirect and mod.get("open_redirect", True),
            "headers":  scan_headers  and mod.get("headers", True),
            "waf":      mod.get("waf_detect", True),
            "time_sqli": scan_time_sqli and mod.get("time_sqli", True),
            "ssrf":      scan_ssrf     and mod.get("ssrf", True),
            "csrf":      scan_csrf     and mod.get("csrf", True),
            "idor":      scan_idor     and mod.get("idor", True),
            "jwt":       scan_jwt      and mod.get("jwt", True),
            "cors":      scan_cors     and mod.get("cors", True),
            "graphql":   scan_graphql  and mod.get("graphql", True),
            "api":       scan_api      and mod.get("api_fuzzer", True),
        }

        self.rate_limiter = (
            TokenBucketRateLimiter(sc.get("rate_limit", 8.0), sc.get("burst", 15))
            if _HAS_RATE_LIMITER else None
        )
        self.cvss_calc   = CVSSCalculator() if _HAS_CVSS else None
        self.vulnerabilities: list[dict] = []
        self.waf_result = None

    def _make_client(self) -> httpx.AsyncClient:
        sc = self.config["scanner"]
        return httpx.AsyncClient(
            timeout=self.timeout,
            follow_redirects=sc.get("follow_redirects", True),
            headers={"User-Agent": sc.get("user_agent", "WebVulnScanner/2.0")},
            verify=sc.get("verify_ssl", False),
        )

    async def run(self) -> dict:
        console.print(f"\n[bold cyan]╔══════════════════════════════════════╗[/bold cyan]")
        console.print(f"[bold cyan]║   WebVulnScanner v2.0 — Phase 2      ║[/bold cyan]")
        console.print(f"[bold cyan]╚══════════════════════════════════════╝[/bold cyan]")
        console.print(f"\n  [dim]Target :[/dim] [bold]{self.target}[/bold]")
        active = sum(v for v in self.options.values())
        console.print(f"  [dim]Modules:[/dim] {active}/{len(self.options)} active\n")

        async with self._make_client() as client:

            # ── STEP 0: WAF Detection ────────────────────────────────────────
            waf_name = "Unknown"
            if self.options["waf"] and _HAS_WAF:
                console.print("[bold]STEP 0:[/bold] WAF Detection...")
                self.waf_result = await WAFDetector().detect(self.target, client)
                if self.waf_result.detected:
                    console.print(
                        f"  [bold yellow]⚠ WAF:[/bold yellow] {self.waf_result.waf_name} "
                        f"(conf={self.waf_result.confidence:.0%})"
                    )
                    waf_name = self.waf_result.waf_name
                else:
                    console.print(f"  [green]✓ No WAF detected[/green]")
                console.print()

            # ── STEP 1: Crawl ────────────────────────────────────────────────
            console.print("[bold]STEP 1:[/bold] Crawling...")
            crawl = await Crawler(self.target, self.max_depth, self.max_pages, self.timeout).crawl()
            urls  = crawl["urls"]
            forms = crawl["forms"]
            console.print(f"\n  ✓ [green]{len(urls)}[/green] URLs | [green]{len(forms)}[/green] forms\n")

            # ── STEP 2: Phase 1 Scans ────────────────────────────────────────
            console.print("[bold]STEP 2:[/bold] Phase 1 — Core Scanning...\n")

            if self.options["headers"]:
                console.print("[cyan]→ Security Headers[/cyan]")
                self._add(await HeadersScanner().scan(self.target, client))

            if self.options["files"]:
                console.print("[cyan]→ Sensitive Files[/cyan]")
                self._add(await SensitiveFileScanner(self.timeout).scan(self.target, client))

            sqli_s      = SQLiScanner(self.timeout, self.config, waf_name)
            xss_s       = XSSScanner(self.timeout, self.config, waf_name)
            redir_s     = OpenRedirectScanner(self.timeout)
            time_sqli_s = TimeSQLiScanner(max(self.timeout, 15), self.config)
            idor_s      = IDORScanner(self.timeout, self.config)
            ssrf_s      = SSRFScanner(self.timeout, self.config)

            if urls:
                console.print(f"\n[cyan]→ URL Scanning ({len(urls)} URLs)[/cyan]")
                with Progress(
                    SpinnerColumn(), BarColumn(bar_width=28),
                    TextColumn("{task.percentage:>3.0f}%"), TextColumn("•"),
                    TimeElapsedColumn(), console=console, transient=True,
                ) as prog:
                    task = prog.add_task("", total=len(urls))
                    for url in urls:
                        tasks = []
                        if self.options["sqli"]:      tasks.append(sqli_s.scan_url(url, client))
                        if self.options["xss"]:       tasks.append(xss_s.scan_url(url, client))
                        if self.options["redirect"]:  tasks.append(redir_s.scan_url(url, client))
                        if self.options["idor"]:      tasks.append(idor_s.scan_url(url, client))
                        if self.options["ssrf"]:      tasks.append(ssrf_s.scan_url(url, client))
                        if self.options["time_sqli"]: tasks.append(time_sqli_s.scan_url(url, client))
                        for res in await asyncio.gather(*tasks, return_exceptions=True):
                            if isinstance(res, list): self._add(res)
                        prog.advance(task)
                console.print(f"  ✓ URL scan complete\n")

            if forms:
                console.print(f"[cyan]→ Form Scanning ({len(forms)} forms)[/cyan]")
                for form in forms:
                    tasks = []
                    if self.options["sqli"]:      tasks.append(sqli_s.scan_form(form, client))
                    if self.options["xss"]:       tasks.append(xss_s.scan_form(form, client))
                    if self.options["time_sqli"]: tasks.append(time_sqli_s.scan_form(form, client))
                    for res in await asyncio.gather(*tasks, return_exceptions=True):
                        if isinstance(res, list): self._add(res)

                if self.options["csrf"]:
                    self._add(await CSRFScanner(self.timeout, self.config).scan_forms(forms, client))
                console.print(f"  ✓ Form scan complete\n")

            # ── STEP 3: Phase 2 Advanced Scans ──────────────────────────────
            console.print("[bold]STEP 3:[/bold] Phase 2 — Advanced Scanning...\n")

            if self.options["cors"]:
                console.print("[cyan]→ CORS Misconfiguration[/cyan]")
                self._add(await CORSScanner(self.timeout, self.config).scan(self.target, urls, client))

            if self.options["graphql"]:
                console.print("[cyan]→ GraphQL Security[/cyan]")
                self._add(await GraphQLScanner(self.timeout, self.config).scan(self.target, client))

            if self.options["jwt"]:
                console.print("[cyan]→ JWT Analysis[/cyan]")
                self._add(await JWTAnalyzer(self.timeout, self.config).scan(self.target, client))

            if self.options["api"]:
                console.print("[cyan]→ API Fuzzing[/cyan]")
                self._add(await APIFuzzer(self.timeout, self.config).scan(self.target, client))

            console.print()

        return {
            "target":          self.target,
            "vulnerabilities": self.vulnerabilities,
            "crawled_urls":    urls,
            "total_forms":     len(forms),
            "waf": {
                "detected":          getattr(self.waf_result, "detected", False),
                "name":              getattr(self.waf_result, "waf_name", "N/A"),
                "confidence":        getattr(self.waf_result, "confidence", 0.0),
                "evidence":          getattr(self.waf_result, "evidence", ""),
                "bypass_strategies": getattr(self.waf_result, "bypass_strategies", []),
            },
        }

    def _add(self, findings: list[dict]):
        for f in findings:
            if self.cvss_calc and self.config["reporting"].get("cvss_scoring"):
                if not f.get("cvss_score"):
                    cvss = self.cvss_calc.calculate(f.get("type", ""))
                    f["cvss_score"]    = cvss.score
                    f["cvss_vector"]   = cvss.vector
                    f["cvss_severity"] = cvss.severity
                elif "cvss_severity" not in f:
                    f["cvss_severity"] = self.cvss_calc._label(f["cvss_score"])
            if "confidence" not in f:
                f["confidence"] = 0.75
            self.vulnerabilities.append(f)

    def generate_report(self, results: dict, output: str = "report.html") -> str:
        return ReportGenerator().generate(
            target=results["target"],
            vulnerabilities=results["vulnerabilities"],
            crawled_urls=results["crawled_urls"],
            total_forms=results["total_forms"],
            waf_info=results.get("waf", {}),
            output_path=output,
        )