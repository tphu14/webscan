"""
payload_mutator.py - Mutate payloads to bypass WAF and filters.
Được tích hợp trực tiếp vào SQLiScanner và XSSScanner.
"""
import random
import urllib.parse
from dataclasses import dataclass


@dataclass
class MutatedPayload:
    original: str
    mutated: str
    technique: str


class PayloadMutator:
    """
    Nhận một payload gốc, trả về danh sách các biến thể
    để bypass WAF, encoding filters, và input sanitizers.
    """

    def mutate_all(self, payload: str) -> list[MutatedPayload]:
        """Trả về tất cả biến thể của payload."""
        results = [MutatedPayload(payload, payload, "original")]
        for method in [
            self._case_vary,
            self._comment_inject,
            self._double_encode,
            self._whitespace_sub,
            self._null_byte,
            self._hex_encode_partial,
        ]:
            try:
                mutated = method(payload)
                if mutated != payload:
                    results.append(MutatedPayload(
                        original=payload,
                        mutated=mutated,
                        technique=method.__name__.lstrip("_"),
                    ))
            except Exception:
                pass
        return results

    def mutate_for_waf(self, payload: str, waf_name: str) -> list[MutatedPayload]:
        """Trả về biến thể phù hợp với WAF đã phát hiện."""
        strategies = {
            "Cloudflare":   [self._case_vary, self._comment_inject, self._double_encode],
            "ModSecurity":  [self._null_byte, self._param_pollution_hint, self._whitespace_sub],
            "AWS WAF":      [self._hex_encode_partial, self._double_encode, self._case_vary],
            "Akamai":       [self._comment_inject, self._whitespace_sub],
            "Unknown":      [self._case_vary, self._comment_inject, self._double_encode],
        }
        methods = strategies.get(waf_name, strategies["Unknown"])
        results = []
        for method in methods:
            try:
                mutated = method(payload)
                if mutated != payload:
                    results.append(MutatedPayload(payload, mutated, method.__name__.lstrip("_")))
            except Exception:
                pass
        return results

    # ── Mutation methods ────────────────────────────────────────────────

    def _case_vary(self, p: str) -> str:
        """SELect -> SeLeCt (evade case-sensitive filters)"""
        return "".join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(p))

    def _comment_inject(self, p: str) -> str:
        """SELECT 1 -> SEL/**/ECT/**/1 (SQL comment bypass)"""
        return p.replace(" ", "/**/")

    def _double_encode(self, p: str) -> str:
        """<script> -> %253Cscript%253E (double URL encoding)"""
        single = urllib.parse.quote(p, safe="")
        return urllib.parse.quote(single, safe="")

    def _whitespace_sub(self, p: str) -> str:
        """Replace space with tab/newline alternatives"""
        subs = ["\t", "%09", "%0a", "%0d", "+"]
        return p.replace(" ", random.choice(subs))

    def _null_byte(self, p: str) -> str:
        """Append null byte to truncate server-side filters"""
        return p + "%00"

    def _hex_encode_partial(self, p: str) -> str:
        """Encode only special chars that trigger WAF"""
        result = ""
        special = set("<>\"'();= ")
        for c in p:
            if c in special:
                result += f"%{ord(c):02x}"
            else:
                result += c
        return result

    def _param_pollution_hint(self, p: str) -> str:
        """HPP: value=legit&value=PAYLOAD (chỉ gợi ý, xử lý ở scanner)"""
        return p  # actual HPP handled at request level