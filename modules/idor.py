"""
idor.py - Insecure Direct Object Reference (IDOR) detector
Phát hiện các parameter số/ID có thể bị thay đổi để truy cập resource của user khác.
"""
import httpx
import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from rich.console import Console

console = Console()

# Pattern nhận diện ID parameter
ID_PARAM_PATTERNS = re.compile(
    r"^(id|user_?id|uid|account_?id|account|member_?id|order_?id|"
    r"invoice_?id|doc_?id|file_?id|item_?id|product_?id|record_?id|"
    r"profile_?id|customer_?id|ticket_?id|report_?id|entry_?id|"
    r"post_?id|comment_?id|message_?id|session_?id|obj_?id|"
    r"ref|reference|num|number|no|key|pk|idx)$",
    re.IGNORECASE,
)

# Pattern nhận diện giá trị là số nguyên (ID tiềm năng)
INT_VALUE_PATTERN = re.compile(r"^\d{1,10}$")

# UUID pattern
UUID_PATTERN = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)

# ID trong path như /users/123, /order/456
PATH_ID_PATTERN = re.compile(r"/(\w+)/(\d{1,10})(?:/|$|\?)")


class IDORScanner:
    def __init__(self, timeout: int = 10, config: dict | None = None):
        self.timeout = timeout
        self.config  = config or {}

    def _is_id_param(self, name: str, value: str) -> bool:
        """Kiểm tra param có phải là ID không."""
        if ID_PARAM_PATTERNS.match(name):
            return True
        if INT_VALUE_PATTERN.match(str(value)):
            # Giá trị là số nhỏ (ID tiêu biểu 1-9999999)
            num = int(value)
            if 1 <= num <= 9_999_999:
                return True
        return False

    def _generate_id_variants(self, value: str) -> list[str]:
        """Tạo các ID liền kề để test."""
        variants = []
        if INT_VALUE_PATTERN.match(str(value)):
            num = int(value)
            # Test ±1, ±2, và một số cách xa hơn
            for delta in [-2, -1, 1, 2, 100, 999]:
                candidate = num + delta
                if candidate > 0:
                    variants.append(str(candidate))
        return variants

    def _inject(self, url: str, param: str, value: str) -> str:
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        params[param] = [value]
        return urlunparse(parsed._replace(query=urlencode(params, doseq=True)))

    def _responses_differ_meaningfully(
        self, r1: str, r2: str, status1: int, status2: int
    ) -> tuple[bool, str]:
        """
        Kiểm tra 2 response có khác nhau theo cách đáng ngờ không.
        IDOR = response khác nhau = có thể đang trả resource của user khác.
        """
        # Cùng status, nội dung khác = trả data khác nhau
        if status1 == status2 == 200 and r1 != r2:
            len_diff = abs(len(r1) - len(r2))
            if len_diff > 100:  # Chênh lệch đáng kể
                return True, f"Different content returned for different IDs (Δlen={len_diff})"

        # Status 403 original → 200 với ID khác = bypass
        if status1 == 403 and status2 == 200:
            return True, "Access control bypass: original=403, modified ID returned 200"

        # Status 404 original → 200 với ID khác = object exists
        if status1 == 404 and status2 == 200:
            return True, "Object enumeration: original=404, adjacent ID returned 200"

        return False, ""

    async def scan_url(self, url: str, client: httpx.AsyncClient) -> list[dict]:
        results = []
        parsed  = urlparse(url)
        params  = parse_qs(parsed.query)

        if not params:
            # Kiểm tra ID trong path
            path_results = await self._scan_path_ids(url, client)
            results.extend(path_results)
            return results

        for param, values in params.items():
            value = values[0] if values else ""
            if not self._is_id_param(param, value):
                continue

            try:
                # Baseline response với ID gốc
                orig_resp   = await client.get(url)
                orig_status = orig_resp.status_code
                orig_text   = orig_resp.text
            except Exception:
                continue

            for alt_id in self._generate_id_variants(value):
                test_url = self._inject(url, param, alt_id)
                try:
                    alt_resp   = await client.get(test_url)
                    alt_status = alt_resp.status_code
                    alt_text   = alt_resp.text

                    hit, evidence = self._responses_differ_meaningfully(
                        orig_text, alt_text, orig_status, alt_status
                    )
                    if hit:
                        console.print(
                            f"  [yellow bold][IDOR][/yellow bold] {url} | "
                            f"param={param} | original={value} → test={alt_id}"
                        )
                        results.append({
                            "type":        "Insecure Direct Object Reference (IDOR)",
                            "severity":    "HIGH",
                            "url":         url,
                            "parameter":   param,
                            "payload":     f"{value} → {alt_id}",
                            "evidence":    evidence,
                            "confidence":  0.70,
                            "cvss_score":  8.1,
                            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
                            "cwe":         "CWE-639",
                        })
                        break  # Found cho param này

                except Exception:
                    pass

        return results

    async def _scan_path_ids(self, url: str, client: httpx.AsyncClient) -> list[dict]:
        """Scan ID trong URL path: /resource/123"""
        results  = []
        matches  = PATH_ID_PATTERN.findall(url)
        if not matches:
            return results

        try:
            orig_resp   = await client.get(url)
            orig_status = orig_resp.status_code
            orig_text   = orig_resp.text
        except Exception:
            return results

        for resource, id_val in matches:
            for delta in [-1, 1, 2]:
                alt_id   = str(int(id_val) + delta)
                test_url = re.sub(
                    rf"/{re.escape(resource)}/{re.escape(id_val)}",
                    f"/{resource}/{alt_id}",
                    url, count=1,
                )
                try:
                    alt_resp   = await client.get(test_url)
                    hit, evidence = self._responses_differ_meaningfully(
                        orig_text, alt_resp.text, orig_status, alt_resp.status_code
                    )
                    if hit:
                        console.print(
                            f"  [yellow bold][IDOR PATH][/yellow bold] "
                            f"{url} | /{resource}/{id_val} → /{resource}/{alt_id}"
                        )
                        results.append({
                            "type":        "IDOR (Path Parameter)",
                            "severity":    "HIGH",
                            "url":         url,
                            "parameter":   f"path:/{resource}/{{id}}",
                            "payload":     f"{id_val} → {alt_id}",
                            "evidence":    evidence,
                            "confidence":  0.68,
                            "cvss_score":  7.5,
                            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                            "cwe":         "CWE-639",
                        })
                        break
                except Exception:
                    pass

        return results