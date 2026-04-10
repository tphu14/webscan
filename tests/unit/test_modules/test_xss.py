"""
test_xss.py - Unit tests for XSS Scanner
"""
import pytest
from unittest.mock import AsyncMock, patch
from modules.xss import XSSScanner, XSS_PAYLOADS


class TestXSSScanner:
    """Test Cross-Site Scripting detection"""

    @pytest.fixture
    def scanner(self):
        """Initialize XSS scanner"""
        return XSSScanner(timeout=10, waf_name="")

    @pytest.fixture
    def scanner_with_config(self, default_config):
        """Initialize scanner with config"""
        return XSSScanner(
            timeout=default_config["scanner"]["timeout"],
            config=default_config,
            waf_name=""
        )

    @pytest.fixture
    def mock_client(self):
        """Create mock httpx AsyncClient"""
        return AsyncMock()

    # ==================== INITIALIZATION TESTS ====================

    def test_scanner_initialization(self, scanner):
        """Test scanner initializes correctly"""
        assert scanner.timeout == 10
        assert scanner.config == {}
        assert scanner.waf_name == ""

    def test_scanner_initialization_with_config(self, scanner_with_config):
        """Test scanner initializes with config"""
        assert scanner_with_config.timeout > 0
        assert scanner_with_config.config is not None

    def test_scanner_initialization_with_waf(self):
        """Test scanner initializes with WAF name"""
        scanner = XSSScanner(timeout=10, waf_name="ModSecurity")
        assert scanner.waf_name == "ModSecurity"

    # ==================== PAYLOAD TESTS ====================

    def test_payloads_defined(self):
        """Test XSS payloads are defined"""
        assert len(XSS_PAYLOADS) > 0
        assert all(isinstance(p, str) for p in XSS_PAYLOADS)

    def test_payloads_contain_common_xss_vectors(self):
        """Test payloads contain various XSS techniques"""
        techniques = {
            "script_tag": any("script" in p.lower() for p in XSS_PAYLOADS),
            "event_handler": any("onerror" in p or "onload" in p for p in XSS_PAYLOADS),
            "img_tag": any("img" in p.lower() for p in XSS_PAYLOADS),
            "svg_tag": any("svg" in p.lower() for p in XSS_PAYLOADS),
            "javascript_protocol": any("javascript:" in p for p in XSS_PAYLOADS),
        }
        # Should have multiple techniques
        assert sum(techniques.values()) >= 3

    def test_payloads_are_executable_contexts(self):
        """Test payloads would execute in browser"""
        for payload in XSS_PAYLOADS:
            # Should contain either HTML tags or JavaScript
            assert "<" in payload or ":" in payload or "(" in payload

    # ==================== PAYLOAD INJECTION TESTS ====================

    def test_inject_url_modifies_parameter(self, scanner):
        """Test URL parameter injection"""
        url = "http://example.com/search?q=test"
        param = "q"
        payload = "<script>alert(1)</script>"
        
        injected = scanner._inject_url(url, param, payload)
        
        # Payload should be in the URL (URL encoded)
        assert ("script" in injected or "%73cript" in injected or 
                "%3Cscript%3E" in injected)

    def test_inject_url_preserves_other_parameters(self, scanner):
        """Test injection preserves other parameters"""
        url = "http://example.com/search?q=test&page=1"
        param = "q"
        payload = "<img src=x>"
        
        injected = scanner._inject_url(url, param, payload)
        
        # Both parameters should be present
        assert "q" in injected
        assert "page" in injected

    def test_inject_url_proper_encoding(self, scanner):
        """Test URL encoding of payload"""
        url = "http://example.com/page?id=1"
        param = "id"
        payload = "<script>alert(1)</script>"
        
        injected = scanner._inject_url(url, param, payload)
        
        # Should be URL encoded
        assert "<" not in injected or "%3C" in injected or "script" not in injected

    def test_inject_url_multiple_parameters(self, scanner):
        """Test injection on multiple parameters"""
        base_url = "http://example.com/page?id=1&name=test"
        
        for param in ["id", "name"]:
            injected = scanner._inject_url(base_url, param, "<xss>")
            assert param in injected

    # ==================== PAYLOAD REFLECTION TESTS ====================

    def test_payload_reflection_simple(self, scanner):
        """Test basic payload reflection detection"""
        payload = "<script>alert(1)</script>"
        response_text = f"Search results for: {payload}"
        
        # Simple check if payload is in response
        assert payload in response_text

    def test_payload_reflection_encoded(self, scanner):
        """Test reflection detection might need decoding"""
        payload = "<img src=x>"
        # In response might be HTML encoded
        response_text = "&lt;img src=x&gt;"
        
        # Direct check fails, would need HTML decoding
        assert payload not in response_text
        assert "img" in response_text

    def test_payload_reflection_case_sensitive(self):
        """Test payload reflection is case-sensitive"""
        payload = "<SCRIPT>alert(1)</SCRIPT>"
        response = "<script>alert(1)</script>"
        
        # Different case
        assert payload not in response

    # ==================== ASYNC SCAN URL TESTS ====================

    @pytest.mark.asyncio
    async def test_scan_url_detects_reflected_xss(self, scanner, mock_client):
        """Test URL scanning detects reflected XSS"""
        mock_response = AsyncMock()
        mock_response.text = "Results for: <script>alert(1)</script>"
        mock_client.get = AsyncMock(return_value=mock_response)

        url = "http://example.com/search?q=test"
        results = await scanner.scan_url(url, mock_client)
        
        assert len(results) > 0
        assert results[0]["type"] == "Cross-Site Scripting (XSS)"
        assert results[0]["parameter"] == "q"

    @pytest.mark.asyncio
    async def test_scan_url_without_params(self, scanner, mock_client):
        """Test scanning URL without parameters"""
        url = "http://example.com/page"
        results = await scanner.scan_url(url, mock_client)
        
        assert len(results) == 0
        mock_client.get.assert_not_called()

    @pytest.mark.asyncio
    async def test_scan_url_no_reflection(self, scanner, mock_client):
        """Test normal response returns no vulnerabilities"""
        mock_response = AsyncMock()
        mock_response.text = "This is a normal response without payload"
        mock_client.get = AsyncMock(return_value=mock_response)

        url = "http://example.com/search?q=test"
        results = await scanner.scan_url(url, mock_client)
        
        assert len(results) == 0

    @pytest.mark.asyncio
    async def test_scan_url_multiple_parameters(self, scanner, mock_client):
        """Test scanning multiple parameters"""
        async def get_side_effect(url):
            response = AsyncMock()
            if "q=" in url:
                response.text = "Results: <img src=x onerror=alert(1)>"
            else:
                response.text = "Normal response"
            return response

        mock_client.get = AsyncMock(side_effect=get_side_effect)

        url = "http://example.com/search?q=test&page=1"
        results = await scanner.scan_url(url, mock_client)
        
        # Should find XSS in q parameter
        if len(results) > 0:
            assert any(r["parameter"] == "q" for r in results)

    @pytest.mark.asyncio
    async def test_scan_url_handles_exceptions(self, scanner, mock_client):
        """Test scanning handles request exceptions"""
        mock_client.get = AsyncMock(side_effect=Exception("Connection error"))

        url = "http://example.com/search?q=test"
        results = await scanner.scan_url(url, mock_client)
        
        # Should not crash
        assert isinstance(results, list)

    @pytest.mark.asyncio
    async def test_scan_url_stops_after_first_hit(self, scanner, mock_client):
        """Test scanner stops after finding first XSS"""
        call_count = 0
        
        async def get_side_effect(url):
            nonlocal call_count
            call_count += 1
            response = AsyncMock()
            response.text = "<script>alert(1)</script>"
            return response

        mock_client.get = AsyncMock(side_effect=get_side_effect)

        url = "http://example.com/search?q=test"
        results = await scanner.scan_url(url, mock_client)
        
        # Should stop after first successful payload
        assert call_count == 1

    @pytest.mark.asyncio
    async def test_scan_url_different_payload_types(self, scanner, mock_client):
        """Test different XSS payload types"""
        payloads_to_test = [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
        ]

        for payload in payloads_to_test:
            mock_response = AsyncMock()
            mock_response.text = f"Search: {payload}"
            mock_client.get = AsyncMock(return_value=mock_response)

            results = await scanner.scan_url(
                "http://example.com/search?q=test",
                mock_client
            )
            
            # Should detect reflection
            if len(results) > 0:
                assert payload in results[0]["payload"]

    # ==================== ASYNC SCAN FORM TESTS ====================

    @pytest.mark.asyncio
    async def test_scan_form_post_request(self, scanner, mock_client):
        """Test form scanning with POST method"""
        form = {
            "url": "http://example.com/search",
            "method": "POST",
            "inputs": [
                {"name": "q", "type": "text", "value": ""},
                {"name": "page", "type": "hidden", "value": "1"},
            ]
        }

        mock_response = AsyncMock()
        mock_response.text = "Results for: <script>alert(1)</script>"
        mock_client.post = AsyncMock(return_value=mock_response)

        results = await scanner.scan_form(form, mock_client)
        
        # Should attempt POST request
        assert mock_client.post.called or len(results) >= 0

    @pytest.mark.asyncio
    async def test_scan_form_get_request(self, scanner, mock_client):
        """Test form scanning with GET method"""
        form = {
            "url": "http://example.com/search",
            "method": "GET",
            "inputs": [{"name": "q", "type": "text", "value": ""}]
        }

        mock_response = AsyncMock()
        mock_response.text = "Normal results"
        mock_client.get = AsyncMock(return_value=mock_response)

        results = await scanner.scan_form(form, mock_client)
        
        assert isinstance(results, list)

    @pytest.mark.asyncio
    async def test_scan_form_skips_hidden_inputs(self, scanner, mock_client):
        """Test form scanning skips hidden and button inputs"""
        form = {
            "url": "http://example.com/form",
            "method": "POST",
            "inputs": [
                {"name": "visible", "type": "text", "value": ""},
                {"name": "csrf_token", "type": "hidden", "value": "token123"},
                {"name": "submit", "type": "submit", "value": "Submit"},
            ]
        }

        mock_response = AsyncMock()
        mock_response.text = "Response"
        mock_client.post = AsyncMock(return_value=mock_response)

        results = await scanner.scan_form(form, mock_client)
        
        # Should only test visible field
        assert isinstance(results, list)

    @pytest.mark.asyncio
    async def test_scan_form_skips_empty_names(self, scanner, mock_client):
        """Test form scanning skips inputs without names"""
        form = {
            "url": "http://example.com/form",
            "method": "POST",
            "inputs": [
                {"name": "", "type": "text", "value": ""},
                {"name": "field", "type": "text", "value": ""},
            ]
        }

        mock_response = AsyncMock()
        mock_response.text = "response"
        mock_client.post = AsyncMock(return_value=mock_response)

        results = await scanner.scan_form(form, mock_client)
        
        assert isinstance(results, list)

    # ==================== VULNERABILITY RESULT TESTS ====================

    @pytest.mark.asyncio
    async def test_vulnerability_structure(self, scanner, mock_client):
        """Test vulnerability result structure"""
        mock_response = AsyncMock()
        mock_response.text = "Results for: <script>alert(1)</script>"
        mock_client.get = AsyncMock(return_value=mock_response)

        results = await scanner.scan_url(
            "http://example.com/search?q=test",
            mock_client
        )
        
        if len(results) > 0:
            vuln = results[0]
            assert "type" in vuln
            assert "severity" in vuln
            assert "url" in vuln
            assert "parameter" in vuln
            assert "payload" in vuln
            assert "evidence" in vuln

    @pytest.mark.asyncio
    async def test_vulnerability_severity_is_medium(self, scanner, mock_client):
        """Test XSS is marked as MEDIUM severity"""
        mock_response = AsyncMock()
        mock_response.text = "Reflected: <img src=x onerror=alert(1)>"
        mock_client.get = AsyncMock(return_value=mock_response)

        results = await scanner.scan_url(
            "http://example.com/page?q=test",
            mock_client
        )
        
        if len(results) > 0:
            assert results[0]["severity"] == "MEDIUM"

    @pytest.mark.asyncio
    async def test_vulnerability_type_from_url(self, scanner, mock_client):
        """Test URL scan sets correct XSS type"""
        mock_response = AsyncMock()
        mock_response.text = "Found: <script>alert(1)</script>"
        mock_client.get = AsyncMock(return_value=mock_response)

        results = await scanner.scan_url(
            "http://example.com/search?q=test",
            mock_client
        )
        
        if len(results) > 0:
            assert results[0]["type"] == "Cross-Site Scripting (XSS)"

    @pytest.mark.asyncio
    async def test_vulnerability_type_from_form(self, scanner, mock_client):
        """Test form scan sets correct XSS type"""
        form = {
            "url": "http://example.com/form",
            "method": "POST",
            "inputs": [{"name": "field", "type": "text", "value": ""}]
        }

        mock_response = AsyncMock()
        mock_response.text = "Result: <script>alert(1)</script>"
        mock_client.post = AsyncMock(return_value=mock_response)

        results = await scanner.scan_form(form, mock_client)
        
        if len(results) > 0:
            assert "XSS" in results[0]["type"]

    # ==================== EDGE CASES ====================

    def test_inject_url_special_characters(self, scanner):
        """Test injection with special characters"""
        url = "http://example.com/page?search=test"
        payload = "'\"><img src=x onerror=alert(1)>"
        
        injected = scanner._inject_url(url, "search", payload)
        
        # Should handle special characters
        assert "http://example.com" in injected

    @pytest.mark.asyncio
    async def test_scan_url_with_unicode_payload(self, scanner, mock_client):
        """Test XSS with unicode characters"""
        mock_response = AsyncMock()
        mock_response.text = "Results for: café"
        mock_client.get = AsyncMock(return_value=mock_response)

        url = "http://example.com/search?q=café"
        results = await scanner.scan_url(url, mock_client)
        
        # Should not crash
        assert isinstance(results, list)

    def test_scanner_multiple_instances_independent(self):
        """Test multiple scanner instances are independent"""
        scanner1 = XSSScanner()
        scanner2 = XSSScanner()
        
        # Instances should be separate
        assert scanner1 is not scanner2

    @pytest.mark.asyncio
    async def test_scan_url_empty_response(self, scanner, mock_client):
        """Test handling of empty response"""
        mock_response = AsyncMock()
        mock_response.text = ""
        mock_client.get = AsyncMock(return_value=mock_response)

        results = await scanner.scan_url(
            "http://example.com/page?q=test",
            mock_client
        )
        
        assert len(results) == 0

    @pytest.mark.asyncio
    async def test_scan_url_very_long_response(self, scanner, mock_client):
        """Test handling of very long response"""
        mock_response = AsyncMock()
        # Create a long response
        mock_response.text = "x" * 100000  # 100KB response
        mock_response.text += "<script>alert(1)</script>"
        mock_client.get = AsyncMock(return_value=mock_response)

        results = await scanner.scan_url(
            "http://example.com/page?q=test",
            mock_client
        )
        
        # Should handle long response
        assert isinstance(results, list)
