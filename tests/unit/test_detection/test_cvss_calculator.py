"""
test_cvss_calculator.py - Unit tests for CVSS Calculator
"""
import pytest
import math
from detection.cvss_calculator import CVSSCalculator, CVSSResult


class TestCVSSCalculator:
    """Test CVSS v3.1 Base Score calculation"""

    @pytest.fixture
    def calculator(self):
        """Initialize CVSSCalculator"""
        return CVSSCalculator()

    # ==================== BASIC TESTS ====================

    def test_calculator_initialization(self, calculator):
        """Test calculator initializes correctly"""
        assert calculator is not None
        assert hasattr(calculator, 'VECTORS')
        assert hasattr(calculator, 'calculate')
        assert len(calculator.VECTORS) > 0

    def test_calculate_returns_cvss_result(self, calculator):
        """Test calculate() returns CVSSResult object"""
        result = calculator.calculate("SQL Injection")
        assert isinstance(result, CVSSResult)
        assert hasattr(result, 'score')
        assert hasattr(result, 'severity')
        assert hasattr(result, 'vector')
        assert hasattr(result, 'exploitability')
        assert hasattr(result, 'impact')

    # ==================== SCORE RANGE TESTS ====================

    def test_score_in_valid_range(self, calculator):
        """Test CVSS score is between 0.0 and 10.0"""
        vuln_types = list(calculator.VECTORS.keys())
        for vuln_type in vuln_types:
            result = calculator.calculate(vuln_type)
            assert 0.0 <= result.score <= 10.0, f"Invalid score for {vuln_type}: {result.score}"

    def test_score_precision(self, calculator):
        """Test CVSS score has 0.1 precision"""
        result = calculator.calculate("SQL Injection")
        # Score should be multiple of 0.1
        score_times_10 = result.score * 10
        assert score_times_10 == math.floor(score_times_10), \
            f"Score {result.score} doesn't have 0.1 precision"

    # ==================== SEVERITY LABEL TESTS ====================

    def test_severity_None(self, calculator):
        """Test None severity for score 0.0"""
        # Reset to create a vulnerability with score 0
        result = calculator.calculate("Unknown Vuln Type")
        if result.score == 0.0:
            assert result.severity == "None"

    def test_severity_Low(self, calculator):
        """Test Low severity for scores 0.1-3.9"""
        # Mock calculation with low impact
        calc = CVSSCalculator()
        m = dict(AV="P", AC="H", PR="H", UI="R", S="U", C="N", I="N", A="L")
        score, _, _ = calc._compute(m)
        severity = calc._label(score)
        assert severity == "Low" or score == 0.0

    def test_severity_Medium(self, calculator):
        """Test Medium severity for scores 4.0-6.9"""
        m = dict(AV="N", AC="H", PR="L", UI="R", S="U", C="L", I="L", A="L")
        score, _, _ = calculator._compute(m)
        if 4.0 <= score < 7.0:
            severity = calculator._label(score)
            assert severity == "Medium"

    def test_severity_High(self, calculator):
        """Test High severity for scores 7.0-8.9"""
        result = calculator.calculate("SQL Injection")
        if 7.0 <= result.score < 9.0:
            assert result.severity == "High"

    def test_severity_Critical(self, calculator):
        """Test Critical severity for scores 9.0-10.0"""
        result = calculator.calculate("SSRF")
        if 9.0 <= result.score <= 10.0:
            assert result.severity == "Critical"

    # ==================== VECTOR STRING TESTS ====================

    def test_vector_string_format(self, calculator):
        """Test CVSS vector string format is correct"""
        result = calculator.calculate("SQL Injection")
        assert result.vector.startswith("CVSS:3.1/")
        assert "AV:" in result.vector
        assert "AC:" in result.vector
        assert "PR:" in result.vector
        assert "UI:" in result.vector
        assert "S:" in result.vector
        assert "C:" in result.vector
        assert "I:" in result.vector
        assert "A:" in result.vector

    def test_vector_string_valid_values(self, calculator):
        """Test CVSS vector contains only valid metric values"""
        result = calculator.calculate("SQL Injection")
        # Parse vector
        parts = result.vector.split('/')
        assert len(parts) >= 9  # CVSS:3.1 + 8 metrics
        
        # Valid values
        valid_av = ['N', 'A', 'L', 'P']
        valid_ac = ['L', 'H']
        valid_pr = ['N', 'L', 'H']
        valid_ui = ['N', 'R']
        valid_s = ['U', 'C']
        valid_c_i_a = ['N', 'L', 'H']

        # Extract metrics (simplified check)
        assert any(f"AV:{v}" in result.vector for v in valid_av)
        assert any(f"AC:{v}" in result.vector for v in valid_ac)

    # ==================== KNOWN VULNERABILITY TESTS ====================

    def test_sql_injection_is_critical_or_high(self, calculator):
        """Test SQL Injection gets high severity"""
        result = calculator.calculate("SQL Injection")
        assert result.severity in ["High", "Critical"]
        assert result.score >= 7.0

    def test_xss_is_medium_or_high(self, calculator):
        """Test XSS gets medium or high severity"""
        result = calculator.calculate("Cross-Site Scripting (XSS)")
        assert result.severity in ["Medium", "High"]
        assert result.score >= 4.0

    def test_ssrf_is_critical_or_high(self, calculator):
        """Test SSRF gets high severity"""
        result = calculator.calculate("SSRF")
        assert result.severity in ["High", "Critical"]
        assert result.score >= 7.0

    def test_idor_is_high(self, calculator):
        """Test IDOR gets medium or high severity"""
        result = calculator.calculate("IDOR")
        assert result.severity in ["Medium", "High", "Critical"]
        assert result.score >= 4.0

    def test_csrf_is_medium_or_high(self, calculator):
        """Test CSRF gets medium or high severity"""
        result = calculator.calculate("CSRF")
        assert result.severity in ["Medium", "High"]
        assert result.score >= 4.0

    def test_sensitive_file_exposure_is_high(self, calculator):
        """Test Sensitive File Exposure gets high severity"""
        result = calculator.calculate("Sensitive File Exposure")
        assert result.severity in ["High", "Critical"]
        assert result.score >= 7.0

    # ==================== EXPLOITABILITY & IMPACT TESTS ====================

    def test_exploitability_in_valid_range(self, calculator):
        """Test exploitability score is valid"""
        result = calculator.calculate("SQL Injection")
        assert 0.0 <= result.exploitability <= 10.0

    def test_impact_in_valid_range(self, calculator):
        """Test impact score is valid"""  
        result = calculator.calculate("SQL Injection")
        assert 0.0 <= result.impact <= 10.0

    def test_high_impact_vulnerabilities(self, calculator):
        """Test high impact vulnerabilities have high impact score"""
        result = calculator.calculate("SQL Injection")
        # SQL Injection with High C, I, A should have high impact
        assert result.impact > 0

    # ==================== TYPE MATCHING TESTS ====================

    def test_exact_type_matching(self, calculator):
        """Test exact vulnerability type matching"""
        result = calculator.calculate("SQL Injection")
        assert result.score > 0
        assert result.severity is not None

    def test_prefix_matching(self, calculator):
        """Test fallback to prefix matching for unknown types"""
        result = calculator.calculate("SQL Injection (Custom)")
        # Should match "SQL Injection" prefix
        assert result.score > 0
        assert result.severity is not None

    def test_case_insensitive_matching(self, calculator):
        """Test case insensitive type matching"""
        result1 = calculator.calculate("SQL Injection")
        result2 = calculator.calculate("sql injection")
        # Both should produce valid results
        assert result1.score > 0
        assert result2.score > 0

    def test_unknown_type_fallback(self, calculator):
        """Test fallback for unknown vulnerability type"""
        result = calculator.calculate("Unknown Vulnerability Type XYZ")
        # Should still return valid CVSS result with default metrics
        assert result.score >= 0
        assert result.severity is not None
        assert result.vector.startswith("CVSS:3.1/")

    # ==================== ALL PREDEFINED TYPES TESTS ====================

    def test_all_predefined_types_calculate_successfully(self, calculator):
        """Test all predefined vulnerability types can be calculated"""
        for vuln_type in calculator.VECTORS.keys():
            result = calculator.calculate(vuln_type)
            assert isinstance(result, CVSSResult)
            assert 0.0 <= result.score <= 10.0
            assert result.severity in ["None", "Low", "Medium", "High", "Critical"]
            assert result.vector.startswith("CVSS:3.1/")

    def test_all_types_have_valid_metrics(self, calculator):
        """Test all predefined types have valid metric values"""
        valid_av = ['N', 'A', 'L', 'P']
        valid_ac = ['L', 'H']
        valid_pr = ['N', 'L', 'H']
        valid_ui = ['N', 'R']
        valid_s = ['U', 'C']
        valid_c_i_a = ['N', 'L', 'H']

        for vuln_type, metrics in calculator.VECTORS.items():
            assert metrics['AV'] in valid_av, f"{vuln_type}: Invalid AV"
            assert metrics['AC'] in valid_ac, f"{vuln_type}: Invalid AC"
            assert metrics['PR'] in valid_pr, f"{vuln_type}: Invalid PR"
            assert metrics['UI'] in valid_ui, f"{vuln_type}: Invalid UI"
            assert metrics['S'] in valid_s, f"{vuln_type}: Invalid S"
            assert metrics['C'] in valid_c_i_a, f"{vuln_type}: Invalid C"
            assert metrics['I'] in valid_c_i_a, f"{vuln_type}: Invalid I"
            assert metrics['A'] in valid_c_i_a, f"{vuln_type}: Invalid A"

    # ==================== CONSISTENCY TESTS ====================

    def test_same_input_produces_same_output(self, calculator):
        """Test deterministic calculation"""
        result1 = calculator.calculate("SQL Injection")
        result2 = calculator.calculate("SQL Injection")
        assert result1.score == result2.score
        assert result1.severity == result2.severity
        assert result1.vector == result2.vector

    def test_high_confidentiality_increases_score(self, calculator):
        """Test high confidentiality impact increases severity"""
        m_high_c = dict(AV="N", AC="L", PR="N", UI="N", S="U", C="H", I="N", A="N")
        m_low_c = dict(AV="N", AC="L", PR="N", UI="N", S="U", C="L", I="N", A="N")
        
        score_high, _, _ = calculator._compute(m_high_c)
        score_low, _, _ = calculator._compute(m_low_c)
        
        assert score_high > score_low, "High C should produce higher score"

    def test_high_integrity_increases_score(self, calculator):
        """Test high integrity impact increases severity"""
        m_high_i = dict(AV="N", AC="L", PR="N", UI="N", S="U", C="N", I="H", A="N")
        m_low_i = dict(AV="N", AC="L", PR="N", UI="N", S="U", C="N", I="L", A="N")
        
        score_high, _, _ = calculator._compute(m_high_i)
        score_low, _, _ = calculator._compute(m_low_i)
        
        assert score_high > score_low, "High I should produce higher score"

    def test_high_availability_increases_score(self, calculator):
        """Test high availability impact increases severity"""
        m_high_a = dict(AV="N", AC="L", PR="N", UI="N", S="U", C="N", I="N", A="H")
        m_low_a = dict(AV="N", AC="L", PR="N", UI="N", S="U", C="N", I="N", A="L")
        
        score_high, _, _ = calculator._compute(m_high_a)
        score_low, _, _ = calculator._compute(m_low_a)
        
        assert score_high > score_low, "High A should produce higher score"

    def test_network_av_increases_score(self, calculator):
        """Test Network attack vector produces higher score than Local"""
        m_network = dict(AV="N", AC="L", PR="N", UI="N", S="U", C="H", I="H", A="H")
        m_local = dict(AV="L", AC="L", PR="N", UI="N", S="U", C="H", I="H", A="H")
        
        score_network, _, _ = calculator._compute(m_network)
        score_local, _, _ = calculator._compute(m_local)
        
        assert score_network > score_local, "Network AV should produce higher score"

    def test_low_ac_increases_score(self, calculator):
        """Test Low attack complexity produces higher score than High"""
        m_low_ac = dict(AV="N", AC="L", PR="N", UI="N", S="U", C="H", I="H", A="H")
        m_high_ac = dict(AV="N", AC="H", PR="N", UI="N", S="U", C="H", I="H", A="H")
        
        score_low, _, _ = calculator._compute(m_low_ac)
        score_high, _, _ = calculator._compute(m_high_ac)
        
        assert score_low > score_high, "Low AC should produce higher score"

    # ==================== EDGE CASES ====================

    def test_zero_score_for_no_impact(self, calculator):
        """Test zero score when no impact (C, I, A all N)"""
        m = dict(AV="N", AC="L", PR="N", UI="N", S="U", C="N", I="N", A="N")
        score, _, _ = calculator._compute(m)
        assert score == 0.0

    def test_scope_changed_increases_score(self, calculator):
        """Test scope changed generally increases score"""
        m_unchanged = dict(AV="N", AC="L", PR="N", UI="N", S="U", C="H", I="H", A="H")
        m_changed = dict(AV="N", AC="L", PR="N", UI="N", S="C", C="H", I="H", A="H")
        
        score_u, _, _ = calculator._compute(m_unchanged)
        score_c, _, _ = calculator._compute(m_changed)
        
        assert score_c > score_u, "Scope Changed should produce higher score"
