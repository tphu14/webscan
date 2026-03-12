"""
deduplicator.py - Finding deduplication + false-positive suppression engine
Phase 3: Giải quyết vấn đề duplicate findings từ Phase 2

Logic:
1. Dedup: cùng (type, url, parameter, payload_category) → giữ 1 cái confidence cao nhất
2. FP filter: confidence < threshold → drop
3. Group consolidation: nhiều SQLi cùng URL → gộp với representative finding
"""
from urllib.parse import urlparse
import re


# Nhóm payload theo category để dedup
PAYLOAD_CATEGORIES = {
    # SQLi
    r"sleep|waitfor|pg_sleep|randomblob": "sqli_time",
    r"'.*or.*'|union.*select|1=1|1=2":   "sqli_error",
    r"<script|onerror|alert\(|javascript:": "xss",
    r"127\.0\.0\.1|localhost|169\.254|metadata": "ssrf",
    r"http://|https://|//":               "redirect",
}


def _payload_category(payload: str) -> str:
    """Nhóm payload vào category để dedup."""
    p = payload.lower()
    for pattern, cat in PAYLOAD_CATEGORIES.items():
        if re.search(pattern, p):
            return cat
    return payload[:30]  # Fallback: dùng 30 ký tự đầu


def _finding_key(finding: dict) -> str:
    """Key duy nhất cho 1 finding."""
    url    = finding.get("url", "")
    ftype  = finding.get("type", "")
    param  = finding.get("parameter", "")
    pcat   = _payload_category(finding.get("payload", ""))
    # Normalize URL: bỏ query string cho một số loại
    parsed = urlparse(url)
    base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    return f"{ftype}|{base_url}|{param}|{pcat}"


def deduplicate(findings: list[dict], confidence_threshold: float = 0.50) -> list[dict]:
    """
    Main dedup + FP filter function.
    
    Args:
        findings: Raw list from all scanners
        confidence_threshold: Drop findings below this confidence
    
    Returns:
        Cleaned, deduplicated list sorted by severity + confidence
    """
    # Step 1: Drop obvious false positives (low confidence)
    filtered = [
        f for f in findings
        if f.get("confidence", 0.75) >= confidence_threshold
    ]

    # Step 2: Dedup — keep highest-confidence per key
    seen: dict[str, dict] = {}
    for finding in filtered:
        key = _finding_key(finding)
        if key not in seen:
            seen[key] = finding
        else:
            # Giữ cái có confidence cao hơn
            existing = seen[key]
            if finding.get("confidence", 0) > existing.get("confidence", 0):
                seen[key] = finding

    deduped = list(seen.values())

    # Step 3: Sort by severity → confidence
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    deduped.sort(key=lambda f: (
        severity_order.get(f.get("severity", "LOW"), 5),
        -f.get("confidence", 0),
        -f.get("cvss_score", 0),
    ))

    return deduped


def summarize_reduction(original: list[dict], deduped: list[dict]) -> dict:
    """Stats về dedup để log."""
    orig_by_sev:  dict[str, int] = {}
    dedup_by_sev: dict[str, int] = {}
    for f in original:
        s = f.get("severity", "LOW")
        orig_by_sev[s] = orig_by_sev.get(s, 0) + 1
    for f in deduped:
        s = f.get("severity", "LOW")
        dedup_by_sev[s] = dedup_by_sev.get(s, 0) + 1

    return {
        "original_count":  len(original),
        "deduped_count":   len(deduped),
        "removed":         len(original) - len(deduped),
        "reduction_pct":   round((1 - len(deduped) / max(len(original), 1)) * 100, 1),
        "by_severity_before": orig_by_sev,
        "by_severity_after":  dedup_by_sev,
    }