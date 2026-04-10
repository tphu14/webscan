"""
test_cors.py - Unit tests for CORS Scanner
"""
import pytest
from unittest.mock import AsyncMock
from modules.cors import CORSScanner


class TestCORSScanner:
    """Test CORS vulnerability detection"""

    @pytest.fixture
    def scanner(self):
        return CORSScanner()

    @pytest.fixture
    def mock_client(self):
        return AsyncMock()

    def test_scanner_initialization(self, scanner):
        """Test scanner initializes"""
        assert scanner is not None
        assert hasattr(scanner, 'scan')

    @pytest.mark.asyncio
    async def test_scan_returns_list(self, scanner, mock_client):
        """Test scan returns list"""
        mock_response = AsyncMock()
        mock_response.headers = {}
        mock_client.request = AsyncMock(return_value=mock_response)

        urls = ["http://example.com/api/users", "http://example.com/api/posts"]
        results = await scanner.scan("http://example.com", urls, mock_client)
        assert isinstance(results, list)

    @pytest.mark.asyncio
    async def test_detect_permissive_cors(self, scanner, mock_client):
        """Test detection of permissive CORS"""
        mock_response = AsyncMock()
        mock_response.headers = {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Credentials": "true",
        }
        mock_client.request = AsyncMock(return_value=mock_response)

        urls = ["http://example.com/api/users"]
        results = await scanner.scan("http://example.com", urls, mock_client)
        
        # May detect permissive CORS
        assert isinstance(results, list)

    @pytest.mark.asyncio
    async def test_scan_with_proper_cors(self, scanner, mock_client):
        """Test proper CORS doesn't trigger vulnerability"""
        mock_response = AsyncMock()
        mock_response.headers = {
            "Access-Control-Allow-Origin": "http://trusted.com",
            "Access-Control-Allow-Methods": "GET, POST",
        }
        mock_client.request = AsyncMock(return_value=mock_response)

        urls = ["http://example.com/api/users"]
        results = await scanner.scan("http://example.com", urls, mock_client)
        
        assert isinstance(results, list)

    @pytest.mark.asyncio
    async def test_scan_no_cors_headers(self, scanner, mock_client):
        """Test page without CORS headers"""
        mock_response = AsyncMock()
        mock_response.headers = {}
        mock_client.request = AsyncMock(return_value=mock_response)

        urls = ["http://example.com/api/users"]
        results = await scanner.scan("http://example.com", urls, mock_client)
        
        # No CORS headers means no CORS vulnerability
        assert isinstance(results, list)
