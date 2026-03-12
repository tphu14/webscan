"""
generator.py - Report generator (Phase 1 upgrade)
Hỗ trợ CVSS score, WAF info, confidence level trong report.
"""
import json
from datetime import datetime
from jinja2 import Environment, FileSystemLoader
from pathlib import Path


class ReportGenerator:
    def __init__(self):
        template_dir = Path(__file__).parent / "templates"
        self.env = Environment(loader=FileSystemLoader(str(template_dir)))

    def generate(
        self,
        target: str,
        vulnerabilities: list[dict],
        crawled_urls: list[str],
        total_forms: int,
        waf_info: dict | None = None,
        output_path: str = "report.html",
    ) -> str:
        # Count by severity
        sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for v in vulnerabilities:
            sev = v.get("severity", "LOW")
            sev_counts[sev] = sev_counts.get(sev, 0) + 1

        # Risk score: weighted sum
        weights = {"CRITICAL": 10, "HIGH": 7, "MEDIUM": 4, "LOW": 1, "INFO": 0}
        risk_score = sum(weights.get(v.get("severity", "LOW"), 1) for v in vulnerabilities)
        risk_label = (
            "CRITICAL" if risk_score >= 50 else
            "HIGH"     if risk_score >= 20 else
            "MEDIUM"   if risk_score >= 8  else
            "LOW"
        )

        template = self.env.get_template("report.html")
        html = template.render(
            target=target,
            scan_time=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            total_urls=len(crawled_urls),
            total_forms=total_forms,
            total_vulns=len(vulnerabilities),
            severity_counts=sev_counts,
            vulnerabilities=vulnerabilities,
            crawled_urls=crawled_urls,
            waf_info=waf_info or {},
            risk_score=risk_score,
            risk_label=risk_label,
        )

        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html)
        return output_path

    def save_json(self, data: dict, output_path: str = "results.json") -> str:
        # Convert non-serializable items
        clean = {
            "target": data["target"],
            "scan_time": datetime.now().isoformat(),
            "waf": data.get("waf", {}),
            "summary": {
                "total": len(data["vulnerabilities"]),
                "by_severity": {},
            },
            "vulnerabilities": data["vulnerabilities"],
            "crawled_urls": data["crawled_urls"],
        }
        for v in data["vulnerabilities"]:
            sev = v.get("severity", "LOW")
            clean["summary"]["by_severity"][sev] = clean["summary"]["by_severity"].get(sev, 0) + 1

        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(clean, f, indent=2, ensure_ascii=False)
        return output_path