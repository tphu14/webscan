"""
response_differ.py - So sánh response baseline vs injected để giảm false positive.
Engine cốt lõi cho Blind detection.
"""
import difflib
import re
from dataclasses import dataclass


@dataclass
class DiffResult:
    is_different: bool        # True = response thay đổi đáng kể
    similarity: float         # 0.0 (khác hoàn toàn) - 1.0 (giống hệt)
    length_delta: int         # Độ thay đổi số ký tự
    structure_changed: bool   # Cấu trúc HTML thay đổi
    new_blocks: list[str]     # Nội dung mới xuất hiện
    anomaly_score: float      # 0.0 - 1.0, càng cao càng đáng ngờ


class ResponseDiffer:
    """
    So sánh 2 HTTP response để phát hiện sự khác biệt có ý nghĩa.

    Dùng trong:
    - Blind Boolean SQLi: TRUE_payload ≈ baseline, FALSE_payload ≠ baseline
    - Blind Time SQLi: đo timing delta
    - Stored XSS: baseline trang /comments khác sau khi submit payload
    """

    def __init__(self, threshold: float = 0.95):
        """
        threshold: nếu similarity < threshold → coi là khác biệt đáng kể
        Default 0.95 = cho phép khác 5% nội dung (dynamic content như timestamp)
        """
        self.threshold = threshold

    def diff(self, baseline: str, response: str) -> DiffResult:
        similarity = self._similarity(baseline, response)
        length_delta = len(response) - len(baseline)
        structure_changed = self._structure_changed(baseline, response)
        new_blocks = self._new_blocks(baseline, response)
        anomaly = self._score(similarity, length_delta, structure_changed, new_blocks)

        return DiffResult(
            is_different=(similarity < self.threshold),
            similarity=round(similarity, 4),
            length_delta=length_delta,
            structure_changed=structure_changed,
            new_blocks=new_blocks[:5],
            anomaly_score=round(anomaly, 3),
        )

    def is_error_page(self, response: str) -> bool:
        """Phát hiện error page (500, stack trace, ...) để filter false positive."""
        error_hints = [
            "internal server error", "stack trace", "exception",
            "traceback", "fatal error", "undefined variable",
            "null pointer", "index out of bounds",
        ]
        lower = response.lower()
        return any(h in lower for h in error_hints)

    # ── Private ──────────────────────────────────────────────────────────

    def _similarity(self, a: str, b: str) -> float:
        # Quick length check để tránh tính toán nặng
        if len(a) == 0 and len(b) == 0:
            return 1.0
        if abs(len(a) - len(b)) > max(len(a), len(b)) * 0.5:
            return 0.3  # Quá khác nhau về độ dài → skip SequenceMatcher
        return difflib.SequenceMatcher(None, a[:5000], b[:5000]).ratio()

    def _structure_changed(self, a: str, b: str) -> bool:
        """So sánh danh sách HTML tag (không tính content)."""
        tag_pattern = re.compile(r"</?[a-zA-Z][a-zA-Z0-9]*[^>]*>")
        tags_a = tag_pattern.findall(a)[:200]
        tags_b = tag_pattern.findall(b)[:200]
        return tags_a != tags_b

    def _new_blocks(self, baseline: str, response: str) -> list[str]:
        """Lấy các dòng xuất hiện trong response nhưng không có trong baseline."""
        differ = difflib.unified_diff(
            baseline.splitlines()[:300],
            response.splitlines()[:300],
            n=0, lineterm=""
        )
        additions = []
        for line in differ:
            if line.startswith("+") and not line.startswith("+++"):
                cleaned = line[1:].strip()
                if len(cleaned) > 3:
                    additions.append(cleaned)
        return additions

    def _score(
        self,
        similarity: float,
        length_delta: int,
        structure_changed: bool,
        new_blocks: list[str],
    ) -> float:
        score = 0.0
        # Similarity drop
        if similarity < 0.85:
            score += 0.45
        elif similarity < 0.92:
            score += 0.25
        elif similarity < 0.95:
            score += 0.10
        # Length delta
        if abs(length_delta) > 1000:
            score += 0.25
        elif abs(length_delta) > 300:
            score += 0.10
        # Structure change
        if structure_changed:
            score += 0.20
        # New content blocks
        if len(new_blocks) > 5:
            score += 0.10
        return min(score, 1.0)