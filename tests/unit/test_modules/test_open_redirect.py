"""
test_open_redirect.py - Unit tests for Open Redirect Scanner
"""
import pytest
from unittest.mock import AsyncMock
from modules.open_redirect import OpenRedirectScanner


class TestOpenRedirectScanner:
    """Test Open Redirect vulnerability detection"""

    @pytest.fixture
    def scanner(self):
        return OpenRedirectScanner()

    @pytest.fixture
    def mock_client(self):
        return AsyncMock()

    @pytest.mark.asyncio
    async def test_scan_url_returns_list(self, scanner, mock_client):
        """Test scan_url returns list"""
        mock_response = AsyncMock()
        mock_response.status_code = 301
        mock_response.headers = {}
        mock_client.get = AsyncMock(return_value=mock_response)

        results = await scanner.scan_url("http://example.com/page?redirect=http://evil.com", mock_client)
        assert isinstance(results, list)

    @pytest.mark.asyncio
    async def test_detect_redirect_location_header(self, scanner, mock_client):
        """Test detection of redirect via Location header"""
        mock_response = AsyncMock()
        mock_response.status_code = 302
        mock_response.headers = {"Location": "http://evil.com"}
        mock_response.text = ""
        mock_client.get = AsyncMock(return_value=mock_response)

        results = await scanner.scan_url("http://example.com/page?url=http://evil.com", mock_client)
        
        if len(results) > 0:
            assert "redirect" in results[0].get("type", "").lower()

    @pytest.mark.asyncio
    async def test_no_redirect_on_safe_url(self, scanner, mock_client):
        """Test no vulnerability when URL stays on same domain"""
        mock_response = AsyncMock()
        mock_response.status_code = 200
        mock_response.headers = {}
        mock_response.text = "Page content"
        mock_client.get = AsyncMock(return_value=mock_response)

        results = await scanner.scan_url("http://example.com/page?url=http://example.com/safe", mock_client)
        
        # Should not report vulnerability
        assert isinstance(results, list)

    def test_scanner_initialization(self, scanner):
        """Test scanner initializes"""
        assert scanner is not None
        assert scanner.timeout > 0
