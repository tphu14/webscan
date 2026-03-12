#!/usr/bin/env python3
"""main.py - WebVulnScanner v3.0 CLI"""
import asyncio, sys, click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from datetime import datetime

console = Console()

BANNER = """[bold red]
 ██╗    ██╗███████╗██████╗ ███████╗ ██████╗ █████╗ ███╗   ██╗
 ██║    ██║██╔════╝██╔══██╗██╔════╝██╔════╝██╔══██╗████╗  ██║
 ██║ █╗ ██║█████╗  ██████╔╝███████╗██║     ███████║██╔██╗ ██║
 ██║███╗██║██╔══╝  ██╔══██╗╚════██║██║     ██╔══██║██║╚██╗██║
 ╚███╔███╔╝███████╗██████╔╝███████║╚██████╗██║  ██║██║ ╚████║
  ╚══╝╚══╝ ╚══════╝╚═════╝ ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
[/bold red][dim]Web Vulnerability Scanner v3.0 — Educational Use Only[/dim]
"""

@click.group()
def cli():
    """WebVulnScanner v3.0"""
    pass

@cli.command()
@click.argument("target")
@click.option("--depth",   "-d", default=3,  help="Crawl depth (default: 3)")
@click.option("--pages",   "-p", default=50, help="Max pages (default: 50)")
@click.option("--timeout", "-t", default=10, help="Timeout seconds (default: 10)")
@click.option("--output",  "-o", default="report.html", help="Output HTML file")
@click.option("--json",    "save_json", is_flag=True, help="Also save JSON")
@click.option("--config",  "-c", default=None, help="Path to config.yaml")
# Phase 1
@click.option("--no-sqli",     is_flag=True)
@click.option("--no-xss",      is_flag=True)
@click.option("--no-files",    is_flag=True)
@click.option("--no-redirect", is_flag=True)
@click.option("--no-headers",  is_flag=True)
# Phase 2
@click.option("--no-time-sqli", is_flag=True)
@click.option("--no-ssrf",      is_flag=True)
@click.option("--no-csrf",      is_flag=True)
@click.option("--no-idor",      is_flag=True)
@click.option("--no-jwt",       is_flag=True)
@click.option("--no-cors",      is_flag=True)
@click.option("--no-graphql",   is_flag=True)
@click.option("--no-api",       is_flag=True)
# Phase 3
@click.option("--no-ssti",      is_flag=True, help="Skip SSTI scan")
@click.option("--no-lfi",       is_flag=True, help="Skip LFI/Path Traversal")
@click.option("--no-xxe",       is_flag=True, help="Skip XXE injection")
@click.option("--no-subdomain", is_flag=True, help="Skip subdomain takeover")
# Modes
@click.option("--quick", is_flag=True, help="Quick mode: Phase 1 only")
def scan(
    target, depth, pages, timeout, output, save_json, config,
    no_sqli, no_xss, no_files, no_redirect, no_headers,
    no_time_sqli, no_ssrf, no_csrf, no_idor, no_jwt, no_cors, no_graphql, no_api,
    no_ssti, no_lfi, no_xxe, no_subdomain, quick,
):
    """
    Scan a target URL for vulnerabilities.

    \b
    Examples:
      python main.py scan http://testphp.vulnweb.com
      python main.py scan http://testphp.vulnweb.com --quick
      python main.py scan http://testphp.vulnweb.com --no-ssrf --no-subdomain
    """
    console.print(BANNER)
    if not target.startswith(("http://", "https://")):
        console.print("[red]Error:[/red] Target must start with http:// or https://")
        sys.exit(1)

    if quick:
        no_time_sqli = no_ssrf = no_csrf = no_idor = True
        no_jwt = no_cors = no_graphql = no_api = True
        no_ssti = no_lfi = no_xxe = no_subdomain = True
        console.print("[yellow]⚡ Quick mode:[/yellow] Phase 2+3 disabled\n")

    console.print(Panel.fit(
        f"[bold]Target  :[/bold] {target}\n"
        f"[bold]Depth   :[/bold] {depth} | [bold]Pages:[/bold] {pages} | [bold]Timeout:[/bold] {timeout}s\n"
        f"[bold]Output  :[/bold] {output}",
        title="Scan Configuration v3.0", border_style="cyan",
    ))
    console.print("\n[yellow bold]⚠ WARNING:[/yellow bold] Only scan systems you own or have explicit permission to test.\n")

    try:
        from scanner_v2 import Scanner
    except ImportError:
        from scanner import Scanner

    scanner = Scanner(
        target=target, config_path=config,
        max_depth=depth, max_pages=pages, timeout=timeout,
        scan_sqli=not no_sqli, scan_xss=not no_xss,
        scan_files=not no_files, scan_redirect=not no_redirect, scan_headers=not no_headers,
        scan_time_sqli=not no_time_sqli, scan_ssrf=not no_ssrf,
        scan_csrf=not no_csrf, scan_idor=not no_idor, scan_jwt=not no_jwt,
        scan_cors=not no_cors, scan_graphql=not no_graphql, scan_api=not no_api,
        scan_ssti=not no_ssti, scan_lfi=not no_lfi,
        scan_xxe=not no_xxe, scan_subdomain=not no_subdomain,
    )

    start   = datetime.now()
    results = asyncio.run(scanner.run())
    elapsed = int((datetime.now() - start).total_seconds())

    vulns = results["vulnerabilities"]
    sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for v in vulns:
        sev = v.get("severity", "LOW")
        sev_counts[sev] = sev_counts.get(sev, 0) + 1

    risk_score = (
        sev_counts["CRITICAL"] * 10 + sev_counts["HIGH"] * 7 +
        sev_counts["MEDIUM"] * 4  + sev_counts["LOW"] * 1
    )

    console.print(f"\n[bold]═══ SCAN COMPLETE ({elapsed}s) ═══[/bold]")
    raw = results.get("raw_count", len(vulns))
    if raw != len(vulns):
        console.print(f"  Raw findings → After dedup: [dim]{raw}[/dim] → [bold green]{len(vulns)}[/bold green]")

    table = Table(show_header=True, header_style="bold dim", box=None)
    table.add_column("Severity", min_width=10)
    table.add_column("Count", justify="right")
    table.add_row("[red]CRITICAL[/red]", str(sev_counts["CRITICAL"]))
    table.add_row("[orange1]HIGH[/orange1]",     str(sev_counts["HIGH"]))
    table.add_row("[yellow]MEDIUM[/yellow]",   str(sev_counts["MEDIUM"]))
    table.add_row("[green]LOW[/green]",       str(sev_counts["LOW"]))
    table.add_row("─" * 12, "─" * 5)
    table.add_row("[bold]TOTAL[/bold]",       f"[bold]{len(vulns)}[/bold]")
    table.add_row("[bold cyan]RISK SCORE[/bold cyan]", f"[bold cyan]{risk_score}[/bold cyan]")
    console.print(table)

    report_path = scanner.generate_report(results, output)
    console.print(f"\n[green]✓ HTML Report:[/green] {report_path}")

    if save_json:
        from reports.generator import ReportGenerator
        json_path = output.replace(".html", ".json")
        ReportGenerator().save_json(results, json_path)
        console.print(f"[green]✓ JSON:[/green] {json_path}")
    console.print()


@cli.command()
def modules():
    """List all scan modules."""
    console.print("\n[bold cyan]Available Modules — WebVulnScanner v3.0[/bold cyan]\n")
    table = Table(show_header=True, header_style="bold dim")
    table.add_column("Module")
    table.add_column("Phase")
    table.add_column("Flag")
    table.add_column("Description")

    rows = [
        ("SQLi (Error-based)",    "1", "--no-sqli",      "SQL injection via error patterns"),
        ("XSS (Reflected)",       "1", "--no-xss",       "Cross-site scripting reflection"),
        ("Sensitive Files",       "1", "--no-files",     "Exposed .env, .git, admin panels"),
        ("Open Redirect",         "1", "--no-redirect",  "Unvalidated redirect parameters"),
        ("Security Headers",      "1", "--no-headers",   "Missing HTTP security headers"),
        ("Blind SQLi (Time)",     "2", "--no-time-sqli", "SLEEP/WAITFOR timing attack"),
        ("SSRF",                  "2", "--no-ssrf",      "Server-Side Request Forgery (FP-fixed)"),
        ("CSRF",                  "2", "--no-csrf",      "Missing/weak CSRF tokens"),
        ("IDOR",                  "2", "--no-idor",      "Insecure Direct Object Reference"),
        ("JWT Analysis",          "2", "--no-jwt",       "alg:none, weak secret, no exp"),
        ("CORS",                  "2", "--no-cors",      "Misconfigured cross-origin policy"),
        ("GraphQL",               "2", "--no-graphql",   "Introspection + injection"),
        ("API Fuzzer",            "2", "--no-api",       "Hidden endpoints + auth bypass"),
        ("SSTI",                  "3", "--no-ssti",      "Server-Side Template Injection (RCE)"),
        ("LFI / Path Traversal",  "3", "--no-lfi",       "Local file read via traversal"),
        ("XXE Injection",         "3", "--no-xxe",       "XML External Entity injection"),
        ("Subdomain Takeover",    "3", "--no-subdomain", "Unclaimed subdomain fingerprinting"),
    ]
    colors = {"1": "cyan", "2": "magenta", "3": "yellow"}
    for name, phase, flag, desc in rows:
        c = colors[phase]
        table.add_row(f"[{c}]{name}[/{c}]", f"Ph.{phase}", flag, desc)
    console.print(table)
    console.print()


@cli.command()
def targets():
    """Show safe testing targets."""
    console.print("\n[bold cyan]Safe Testing Targets:[/bold cyan]")
    targets = [
        ("http://testphp.vulnweb.com",  "Acunetix PHP — SQLi, XSS, LFI"),
        ("http://dvwa.local",           "DVWA (docker run -p 80:80 vulnerables/web-dvwa)"),
        ("http://localhost:3000",        "Juice Shop (docker run -p 3000:3000 bkimminich/juice-shop)"),
        ("http://localhost:8080/WebGoat","WebGoat (docker run -p 8080:8080 webgoat/webgoat)"),
    ]
    for url, desc in targets:
        console.print(f"  [green]{url}[/green]")
        console.print(f"    [dim]{desc}[/dim]")
    console.print()


if __name__ == "__main__":
    cli()