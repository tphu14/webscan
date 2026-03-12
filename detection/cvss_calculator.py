"""
cvss_calculator.py - CVSS v3.1 Base Score Calculator.
Tự động tính điểm CVSS cho từng loại lỗ hổng phát hiện được.
"""
import math
from dataclasses import dataclass


@dataclass
class CVSSResult:
    score: float          # 0.0 - 10.0
    severity: str         # None / Low / Medium / High / Critical
    vector: str           # CVSS:3.1/AV:N/AC:L/...
    exploitability: float
    impact: float


class CVSSCalculator:
    """
    CVSS v3.1 Base Score theo spec: https://www.first.org/cvss/v3.1/specification-document
    """

    # Predefined metric vectors cho từng vulnerability type
    # Format: AV, AC, PR, UI, S, C, I, A
    VECTORS: dict[str, dict] = {
        # Injection
        "SQL Injection":                        dict(AV="N", AC="L", PR="N", UI="N", S="U", C="H", I="H", A="H"),
        "SQL Injection (Form)":                 dict(AV="N", AC="L", PR="N", UI="N", S="U", C="H", I="H", A="H"),
        "Blind SQL Injection (Boolean-Based)":  dict(AV="N", AC="H", PR="N", UI="N", S="U", C="H", I="H", A="H"),
        "Blind SQL Injection (Time-Based)":     dict(AV="N", AC="H", PR="N", UI="N", S="U", C="H", I="H", A="L"),
        # XSS
        "Cross-Site Scripting (XSS)":           dict(AV="N", AC="L", PR="N", UI="R", S="C", C="L", I="L", A="N"),
        "XSS (Reflected via Form)":             dict(AV="N", AC="L", PR="N", UI="R", S="C", C="L", I="L", A="N"),
        "DOM-based XSS":                        dict(AV="N", AC="H", PR="N", UI="R", S="C", C="L", I="L", A="N"),
        # SSRF / LFI / RCE
        "SSRF":                                 dict(AV="N", AC="L", PR="N", UI="N", S="C", C="H", I="H", A="H"),
        "Local File Inclusion":                 dict(AV="N", AC="L", PR="N", UI="N", S="U", C="H", I="N", A="N"),
        # Access Control
        "IDOR":                                 dict(AV="N", AC="L", PR="L", UI="N", S="U", C="H", I="H", A="N"),
        "CSRF":                                 dict(AV="N", AC="L", PR="N", UI="R", S="U", C="N", I="H", A="N"),
        "Open Redirect":                        dict(AV="N", AC="L", PR="N", UI="R", S="U", C="L", I="L", A="N"),
        # Infrastructure
        "Sensitive File Exposure":              dict(AV="N", AC="L", PR="N", UI="N", S="U", C="H", I="N", A="N"),
        "Missing Security Header: Content-Security-Policy": dict(AV="N", AC="H", PR="N", UI="R", S="C", C="L", I="L", A="N"),
        "Missing Security Header: Strict-Transport-Security": dict(AV="N", AC="H", PR="N", UI="R", S="U", C="L", I="L", A="N"),
        "Information Disclosure: Server":       dict(AV="N", AC="L", PR="N", UI="N", S="U", C="L", I="N", A="N"),
        "Information Disclosure: X-Powered-By": dict(AV="N", AC="L", PR="N", UI="N", S="U", C="L", I="N", A="N"),
    }

    # Metric numeric values per CVSS 3.1 spec
    _MV = {
        "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
        "AC": {"L": 0.77, "H": 0.44},
        "PR_U": {"N": 0.85, "L": 0.62, "H": 0.27},  # Scope Unchanged
        "PR_C": {"N": 0.85, "L": 0.68, "H": 0.50},  # Scope Changed
        "UI": {"N": 0.85, "R": 0.62},
        "C": {"N": 0.0, "L": 0.22, "H": 0.56},
        "I": {"N": 0.0, "L": 0.22, "H": 0.56},
        "A": {"N": 0.0, "L": 0.22, "H": 0.56},
    }

    def calculate(self, vuln_type: str) -> CVSSResult:
        # Normalize vuln_type: nếu không tìm thấy, thử match prefix
        m = self.VECTORS.get(vuln_type)
        if not m:
            for key in self.VECTORS:
                if key.lower() in vuln_type.lower() or vuln_type.lower() in key.lower():
                    m = self.VECTORS[key]
                    break
        if not m:
            # Fallback: MEDIUM severity generic
            m = dict(AV="N", AC="L", PR="N", UI="N", S="U", C="L", I="L", A="N")

        score, exploit, impact = self._compute(m)
        vector_str = self._vector_string(m)
        severity = self._label(score)

        return CVSSResult(
            score=score,
            severity=severity,
            vector=vector_str,
            exploitability=round(exploit, 2),
            impact=round(impact, 2),
        )

    def _compute(self, m: dict) -> tuple[float, float, float]:
        mv = self._MV
        scope_changed = m["S"] == "C"

        # ISS - Impact Sub Score
        iss = 1 - (1 - mv["C"][m["C"]]) * (1 - mv["I"][m["I"]]) * (1 - mv["A"][m["A"]])

        # Impact
        if not scope_changed:
            impact = 6.42 * iss
        else:
            impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)

        # Exploitability - PR varies by scope
        pr_table = mv["PR_C"] if scope_changed else mv["PR_U"]
        exploitability = 8.22 * mv["AV"][m["AV"]] * mv["AC"][m["AC"]] * pr_table[m["PR"]] * mv["UI"][m["UI"]]

        if impact <= 0:
            return 0.0, exploitability, 0.0

        if not scope_changed:
            raw = min(impact + exploitability, 10)
        else:
            raw = min(1.08 * (impact + exploitability), 10)

        # Roundup to nearest 0.1
        base_score = math.ceil(raw * 10) / 10
        return base_score, exploitability, impact

    def _label(self, score: float) -> str:
        if score == 0.0:   return "None"
        elif score < 4.0:  return "Low"
        elif score < 7.0:  return "Medium"
        elif score < 9.0:  return "High"
        else:              return "Critical"

    def _vector_string(self, m: dict) -> str:
        return (
            f"CVSS:3.1/AV:{m['AV']}/AC:{m['AC']}/PR:{m['PR']}/"
            f"UI:{m['UI']}/S:{m['S']}/C:{m['C']}/I:{m['I']}/A:{m['A']}"
        )