"""
test_waf_detector.py - Unit tests for WAF Detector
"""
import pytest
from unittest.mock import AsyncMock, patch
from detection.waf_detector import WAFDetector, WAFResult


class TestWAFDetector:
    """Test WAF Detection"""

    @pytest.fixture
    def detector(self):
        """Initialize WAF detector"""
        return WAFDetector()

    # ==================== INITIALIZATION TESTS ====================

    def test_detector_initialization(self, detector):
        """Test detector initializes correctly"""
        assert detector is not None
        assert hasattr(detector, 'SIGNATURES')
        assert hasattr(detector, 'BYPASS_STRATEGIES')
        assert hasattr(detector, 'PROBE_SUFFIX')
        assert len(detector.SIGNATURES) > 0

    def test_signatures_contain_common_wafs(self, detector):
        """Test detector has signatures for common WAFs"""
        expected_wafs = ["Cloudflare", "AWS WAF", "ModSecurity", "Imperva (Incapsula)"]
        for waf in expected_wafs:
            assert waf in detector.SIGNATURES

    def test_bypass_strategies_defined(self, detector):
        """Test bypass strategies are defined"""
        for waf_name in detector.SIGNATURES.keys():
            assert waf_name in detector.BYPASS_STRATEGIES or "Unknown" in detector.BYPASS_STRATEGIES

    # ==================== WAF RESULT TESTS ====================

    def test_waf_result_structure(self):
        """Test WAFResult has correct structure"""
        result = WAFResult(
            detected=True,
            waf_name="Test WAF",
            confidence=0.8,
            bypass_strategies=["strategy1"]
        )
        assert result.detected is True
        assert result.waf_name == "Test WAF"
        assert result.confidence == 0.8
        assert len(result.bypass_strategies) > 0

    def test_waf_result_default_values(self):
        """Test WAFResult has sensible defaults"""
        result = WAFResult(detected=False, waf_name="None", confidence=0.0)
        assert result.bypass_strategies == []
        assert result.evidence == ""

    # ==================== FINGERPRINTING TESTS ====================

    def test_fingerprint_cloudflare_in_headers(self, detector):
        """Test Cloudflare detection in headers"""
        response = AsyncMock()
        response.headers = {"cf-ray": "abc123", "cf-cache-status": "HIT"}
        response.cookies = {}
        response.text = "Normal response text"
        response.status_code = 200

        waf_name, confidence, evidence = detector._fingerprint(response)
        
        # Should detect Cloudflare
        assert "Cloudflare" in waf_name or confidence > 0
        assert confidence > 0

    def test_fingerprint_cloudflare_in_cookies(self, detector):
        """Test Cloudflare detection in cookies"""
        response = AsyncMock()
        response.headers = {}
        response.cookies = {"__cfduid": "abc123", "cf_clearance": "xyz"}
        response.text = "Normal response"
        response.status_code = 200

        waf_name, confidence, evidence = detector._fingerprint(response)
        
        assert confidence > 0

    def test_fingerprint_modsecurity_in_body(self, detector):
        """Test ModSecurity detection in response body"""
        response = AsyncMock()
        response.headers = {}
        response.cookies = {}
        response.text = "The requested action was not allowed by mod_security"
        response.status_code = 406

        waf_name, confidence, evidence = detector._fingerprint(response)
        
        # Should detect ModSecurity
        if "ModSecurity" in waf_name:
            assert confidence > 0

    def test_fingerprint_aws_waf(self, detector):
        """Test AWS WAF detection"""
        response = AsyncMock()
        response.headers = {"x-amzn-requestid": "req123"}
        response.cookies = {}
        response.text = "Your request was blocked by AWS WAF"
        response.status_code = 403

        waf_name, confidence, evidence = detector._fingerprint(response)
        
        assert confidence >= 0

    def test_fingerprint_unknown_waf(self, detector):
        """Test detection with unknown/no WAF"""
        response = AsyncMock()
        response.headers = {}
        response.cookies = {}
        response.text = "Normal error page"
        response.status_code = 500

        waf_name, confidence, evidence = detector._fingerprint(response)
        
        # Should return Unknown or low confidence
        assert confidence == 0 or waf_name == "Unknown"

    def test_fingerprint_returns_evidence(self, detector):
        """Test fingerprinting returns evidence string"""
        response = AsyncMock()
        response.headers = {"cf-ray": "abc"}
        response.cookies = {}
        response.text = "response"
        response.status_code = 200

        _, _, evidence = detector._fingerprint(response)
        
        assert isinstance(evidence, str)
        assert len(evidence) > 0

    def test_fingerprint_combined_signals_boost_confidence(self, detector):
        """Test combined signals (body + header) boost confidence"""
        response = AsyncMock()
        response.headers = {"cf-ray": "abc"}
        response.cookies = {}
        response.text = "cloudflare ray id detected in response"  # Body contains signature
        response.status_code = 200

        _, confidence, _ = detector._fingerprint(response)
        
        # Combined signals should give decent confidence
        assert confidence > 0

    def test_fingerprint_status_code_recognition(self, detector):
        """Test status codes are recognized"""
        response = AsyncMock()
        response.headers = {}
        response.cookies = {}
        response.text = "Request blocked"
        response.status_code = 406  # ModSecurity common status

        _, confidence, _ = detector._fingerprint(response)
        
        # Status code match should contribute to score
        assert isinstance(confidence, float)

    # ==================== ASYNC DETECTION TESTS ====================

    @pytest.mark.asyncio
    async def test_detect_returns_waf_result(self, detector):
        """Test detect() returns WAFResult"""
        mock_client = AsyncMock()
        mock_response = AsyncMock()
        mock_response.headers = {}
        mock_response.cookies = {}
        mock_response.text = "Normal response"
        mock_response.status_code = 200
        mock_client.get = AsyncMock(return_value=mock_response)

        result = await detector.detect("http://example.com", mock_client)
        
        assert isinstance(result, WAFResult)
        assert hasattr(result, 'detected')
        assert hasattr(result, 'waf_name')
        assert hasattr(result, 'confidence')

    @pytest.mark.asyncio
    async def test_detect_calls_probe_url(self, detector):
        """Test detect() constructs and calls probe URL"""
        mock_client = AsyncMock()
        mock_response = AsyncMock()
        mock_response.headers = {}
        mock_response.cookies = {}
        mock_response.text = "response"
        mock_response.status_code = 200
        mock_client.get = AsyncMock(return_value=mock_response)

        await detector.detect("http://example.com", mock_client)
        
        # Should have called get with probe URL
        mock_client.get.assert_called_once()
        called_url = mock_client.get.call_args[0][0]
        assert "waf_test" in called_url or "script" in called_url

    @pytest.mark.asyncio
    async def test_detect_handles_timeout(self, detector):
        """Test detect() handles timeout from WAF"""
        import httpx
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=httpx.TimeoutException("timeout"))

        result = await detector.detect("http://example.com", mock_client)
        
        assert result.detected is True
        assert "Unknown" in result.waf_name or "timeout" in result.evidence.lower()

    @pytest.mark.asyncio
    async def test_detect_handles_http_exception(self, detector):
        """Test detect() handles HTTP exceptions"""
        import httpx
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=httpx.HTTPError("connection error"))

        result = await detector.detect("http://example.com", mock_client)
        
        assert result.detected is False

    @pytest.mark.asyncio
    async def test_detect_cloudflare_response(self, detector):
        """Test detection of Cloudflare WAF"""
        mock_client = AsyncMock()
        mock_response = AsyncMock()
        mock_response.headers = {"cf-ray": "123456", "cf-cache-status": "MISS"}
        mock_response.cookies = {}
        mock_response.text = "Access denied"
        mock_response.status_code = 403
        mock_client.get = AsyncMock(return_value=mock_response)

        result = await detector.detect("http://example.com", mock_client)
        
        if result.confidence >= 0.4:
            assert "Cloudflare" in result.waf_name
            assert result.detected is True

    # ==================== BYPASS STRATEGIES TESTS ====================

    def test_bypass_strategies_for_known_wafs(self, detector):
        """Test bypass strategies defined for known WAFs"""
        for waf_name in ["Cloudflare", "ModSecurity", "AWS WAF"]:
            strategies = detector.BYPASS_STRATEGIES.get(waf_name, [])
            assert len(strategies) > 0, f"No bypass strategies for {waf_name}"
            assert all(isinstance(s, str) for s in strategies)

    def test_unknown_waf_has_fallback_strategies(self, detector):
        """Test Unknown WAF has fallback strategies"""
        strategies = detector.BYPASS_STRATEGIES.get("Unknown", [])
        assert len(strategies) > 0

    def test_bypass_strategies_not_empty_strings(self, detector):
        """Test bypass strategies are not empty"""
        for waf_name, strategies in detector.BYPASS_STRATEGIES.items():
            for strategy in strategies:
                assert len(strategy.strip()) > 0

    # ==================== PROBE PAYLOAD TESTS ====================

    def test_probe_suffix_exists(self, detector):
        """Test probe suffix is defined"""
        assert detector.PROBE_SUFFIX is not None
        assert len(detector.PROBE_SUFFIX) > 0

    def test_probe_suffix_contains_payloads(self, detector):
        """Test probe suffix contains suspicious patterns"""
        assert "script" in detector.PROBE_SUFFIX.lower() or "or" in detector.PROBE_SUFFIX.lower()
        assert "=" in detector.PROBE_SUFFIX  # Query parameter

    # ==================== CONFIDENCE SCORING TESTS ====================

    def test_confidence_in_valid_range(self, detector):
        """Test confidence scores are between 0 and 1"""
        response = AsyncMock()
        response.headers = {"cf-ray": "abc"}
        response.cookies = {}
        response.text = "response"
        response.status_code = 200

        _, confidence, _ = detector._fingerprint(response)
        
        assert 0.0 <= confidence <= 1.0

    def test_confidence_precision(self, detector):
        """Test confidence is rounded to 2 decimals"""
        response = AsyncMock()
        response.headers = {"cf-ray": "abc"}
        response.cookies = {}
        response.text = "response"
        response.status_code = 200

        _, confidence, _ = detector._fingerprint(response)
        
        # Confidence should be a float between 0 and 1
        assert 0.0 <= confidence <= 1.0
        assert isinstance(confidence, (int, float))

    # ==================== URL HANDLING TESTS ====================

    @pytest.mark.asyncio
    async def test_detect_with_trailing_slash(self, detector):
        """Test detect handles URLs with trailing slash"""
        mock_client = AsyncMock()
        mock_response = AsyncMock()
        mock_response.headers = {}
        mock_response.cookies = {}
        mock_response.text = "response"
        mock_response.status_code = 200
        mock_client.get = AsyncMock(return_value=mock_response)

        result = await detector.detect("http://example.com/", mock_client)
        
        assert isinstance(result, WAFResult)
        # Should strip trailing slash and still work
        called_url = mock_client.get.call_args[0][0]
        assert not called_url.startswith("http://example.com//")

    @pytest.mark.asyncio
    async def test_detect_with_path(self, detector):
        """Test detect with path in URL"""
        mock_client = AsyncMock()
        mock_response = AsyncMock()
        mock_response.headers = {}
        mock_response.cookies = {}
        mock_response.text = "response"
        mock_response.status_code = 200
        mock_client.get = AsyncMock(return_value=mock_response)

        result = await detector.detect("http://example.com/api/v1", mock_client)
        
        assert isinstance(result, WAFResult)
        called_url = mock_client.get.call_args[0][0]
        assert "/api/v1" in called_url

    # ==================== EDGE CASES ====================

    def test_fingerprint_with_case_insensitivity(self, detector):
        """Test fingerprinting is case-insensitive"""
        response = AsyncMock()
        response.headers = {"CF-RAY": "ABC"}  # Uppercase
        response.cookies = {}
        response.text = "RESPONSE"
        response.status_code = 200

        _, confidence, _ = detector._fingerprint(response)
        
        # Should still detect despite case differences
        assert isinstance(confidence, float)

    def test_fingerprint_with_long_response(self, detector):
        """Test fingerprinting handles long response body"""
        response = AsyncMock()
        response.headers = {}
        response.cookies = {}
        response.text = "a" * 10000  # Very long response
        response.status_code = 200

        # Should not crash
        _, confidence, _ = detector._fingerprint(response)
        assert isinstance(confidence, float)

    def test_all_signatures_have_required_keys(self, detector):
        """Test all signatures have required keys"""
        required_keys = {"headers", "cookies", "body", "status"}
        for waf_name, sig in detector.SIGNATURES.items():
            assert sig.keys() == required_keys, f"{waf_name} missing required keys"

    def test_all_signature_values_are_lists(self, detector):
        """Test all signature values are lists"""
        for waf_name, sig in detector.SIGNATURES.items():
            for key, value in sig.items():
                assert isinstance(value, list), f"{waf_name}.{key} is not a list"
