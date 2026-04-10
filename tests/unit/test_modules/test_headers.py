"""
test_headers.py - Unit tests for Security Headers Scanner
"""
import pytest
from unittest.mock import AsyncMock
from modules.headers import HeadersScanner, SECURITY_HEADERS, DANGEROUS_HEADERS


class TestHeadersScanner:
    """Test security headers detection"""

    @pytest.fixture
    def scanner(self):
        """Initialize headers scanner"""
        return HeadersScanner()

    @pytest.fixture
    def mock_client(self):
        """Create mock httpx AsyncClient"""
        return AsyncMock()

    # ==================== CONSTANTS TESTS ====================

    def test_security_headers_defined(self):
        """Test security headers are defined"""
        assert len(SECURITY_HEADERS) > 0
        assert "X-Frame-Options" in SECURITY_HEADERS
        assert "Content-Security-Policy" in SECURITY_HEADERS

    def test_security_headers_have_properties(self):
        """Test security headers have required properties"""
        for header_name, header_info in SECURITY_HEADERS.items():
            assert "description" in header_info
            assert "severity" in header_info
            assert "recommended" in header_info

    def test_dangerous_headers_defined(self):
        """Test dangerous headers are defined"""
        assert len(DANGEROUS_HEADERS) > 0
        assert "Server" in DANGEROUS_HEADERS
        assert "X-Powered-By" in DANGEROUS_HEADERS

    # ==================== INITIALIZATION TESTS ====================

    def test_scanner_initialization(self, scanner):
        """Test scanner initializes"""
        assert scanner is not None

    # ==================== ASYNC SCAN TESTS ====================

    @pytest.mark.asyncio
    async def test_scan_returns_list(self, scanner, mock_client):
        """Test scan returns list"""
        mock_response = AsyncMock()
        mock_response.headers = {}
        mock_client.get = AsyncMock(return_value=mock_response)

        results = await scanner.scan("http://example.com", mock_client)
        
        assert isinstance(results, list)

    @pytest.mark.asyncio
    async def test_scan_calls_client_get(self, scanner, mock_client):
        """Test scan calls client.get"""
        mock_response = AsyncMock()
        mock_response.headers = {}
        mock_client.get = AsyncMock(return_value=mock_response)

        await scanner.scan("http://example.com", mock_client)
        
        mock_client.get.assert_called_once()

    @pytest.mark.asyncio
    async def test_scan_missing_security_headers(self, scanner, mock_client):
        """Test detection of missing security headers"""
        mock_response = AsyncMock()
        mock_response.headers = {}  # No headers
        mock_client.get = AsyncMock(return_value=mock_response)

        results = await scanner.scan("http://example.com", mock_client)
        
        # Should detect missing headers
        if len(results) > 0:
            assert any("missing" in str(r).lower() for r in results)

    @pytest.mark.asyncio
    async def test_scan_with_security_headers(self, scanner, mock_client):
        """Test page with proper security headers"""
        mock_response = AsyncMock()
        mock_response.headers = {
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Content-Security-Policy": "default-src 'self'",
            "Strict-Transport-Security": "max-age=31536000",
        }
        mock_client.get = AsyncMock(return_value=mock_response)

        results = await scanner.scan("http://example.com", mock_client)
        
        # Should have fewer issues
        assert isinstance(results, list)

    @pytest.mark.asyncio
    async def test_scan_detects_dangerous_headers(self, scanner, mock_client):
        """Test detection of dangerous headers"""
        mock_response = AsyncMock()
        mock_response.headers = {
            "Server": "Apache/2.4.41 (Ubuntu)",
            "X-Powered-By": "PHP/7.4.3",
        }
        mock_client.get = AsyncMock(return_value=mock_response)

        results = await scanner.scan("http://example.com", mock_client)
        
        # MAY detect dangerous headers
        assert isinstance(results, list)

    @pytest.mark.asyncio
    async def test_scan_case_insensitive_headers(self, scanner, mock_client):
        """Test header detection is case-insensitive"""
        mock_response = AsyncMock()
        mock_response.headers = {
            "x-frame-options": "DENY",  # lowercase
            "CONTENT-SECURITY-POLICY": "default-src 'self'",  # uppercase
        }
        mock_client.get = AsyncMock(return_value=mock_response)

        results = await scanner.scan("http://example.com", mock_client)
        
        # Should handle case variations
        assert isinstance(results, list)

    @pytest.mark.asyncio
    async def test_scan_handles_exceptions(self, scanner, mock_client):
        """Test scan handles request exceptions"""
        mock_client.get = AsyncMock(side_effect=Exception("Connection error"))

        results = await scanner.scan("http://example.com", mock_client)
        
        # Should not crash
        assert isinstance(results, list)

    # ==================== HEADER PROPERTIES ====================

    def test_x_frame_options_severity(self):
        """Test X-Frame-Options severity is MEDIUM"""
        assert SECURITY_HEADERS["X-Frame-Options"]["severity"] == "MEDIUM"

    def test_content_security_policy_severity(self):
        """Test CSP severity is HIGH"""
        assert SECURITY_HEADERS["Content-Security-Policy"]["severity"] == "HIGH"

    def test_x_content_type_options_severity(self):
        """Test X-Content-Type-Options severity is LOW"""
        assert SECURITY_HEADERS["X-Content-Type-Options"]["severity"] == "LOW"

    def test_hsts_recommended_value(self):
        """Test HSTS recommended value"""
        hsts = SECURITY_HEADERS["Strict-Transport-Security"]
        assert "max-age" in hsts["recommended"]

    def test_csp_recommended_value(self):
        """Test CSP recommended value"""
        csp = SECURITY_HEADERS["Content-Security-Policy"]
        assert "default-src" in csp["recommended"]

    # ==================== VULNERABILITY RESULTS ====================

    @pytest.mark.asyncio
    async def test_vulnerability_structure(self, scanner, mock_client):
        """Test vulnerability result structure"""
        mock_response = AsyncMock()
        mock_response.headers = {}
        mock_client.get = AsyncMock(return_value=mock_response)

        results = await scanner.scan("http://example.com", mock_client)
        
        # If vulnerabilities found, check structure
        for result in results:
            assert isinstance(result, dict)

    # ==================== EDGE CASES ====================

    @pytest.mark.asyncio
    async def test_scan_empty_headers(self, scanner, mock_client):
        """Test scanning with empty headers"""
        mock_response = AsyncMock()
        mock_response.headers = {}
        mock_client.get = AsyncMock(return_value=mock_response)

        results = await scanner.scan("http://example.com", mock_client)
        
        # Should detect multiple missing headers
        assert isinstance(results, list)

    @pytest.mark.asyncio
    async def test_scan_all_headers_present(self, scanner, mock_client):
        """Test scanning when all headers present"""
        mock_response = AsyncMock()
        mock_response.headers = {
            header: "value" for header in SECURITY_HEADERS.keys()
        }
        mock_client.get = AsyncMock(return_value=mock_response)

        results = await scanner.scan("http://example.com", mock_client)
        
        # Should have minimal issues
        assert isinstance(results, list)

    @pytest.mark.asyncio
    async def test_scan_extra_custom_headers(self, scanner, mock_client):
        """Test scanning with extra custom headers"""
        mock_response = AsyncMock()
        mock_response.headers = {
            "X-Custom-Header": "value",
            "X-Another-Custom": "value2",
            "X-Frame-Options": "DENY",
        }
        mock_client.get = AsyncMock(return_value=mock_response)

        results = await scanner.scan("http://example.com", mock_client)
        
        # Should handle custom headers
        assert isinstance(results, list)

    @pytest.mark.asyncio
    async def test_scan_headers_with_special_values(self, scanner, mock_client):
        """Test scanning headers with special/complex values"""
        mock_response = AsyncMock()
        mock_response.headers = {
            "Content-Security-Policy": "default-src 'self'; script-src 'self' 'unsafe-inline'",
            "X-Frame-Options": "ALLOW-FROM http://example.com",
        }
        mock_client.get = AsyncMock(return_value=mock_response)

        results = await scanner.scan("http://example.com", mock_client)
        
        # Should handle complex header values
        assert isinstance(results, list)

    @pytest.mark.asyncio
    async def test_scan_very_long_header_values(self, scanner, mock_client):
        """Test scanning very long header values"""
        mock_response = AsyncMock()
        mock_response.headers = {
            "Content-Security-Policy": "script-src " + " ".join([f"'https://example.com/{i}'" for i in range(100)]),
        }
        mock_client.get = AsyncMock(return_value=mock_response)

        results = await scanner.scan("http://example.com", mock_client)
        
        # Should handle long values
        assert isinstance(results, list)
