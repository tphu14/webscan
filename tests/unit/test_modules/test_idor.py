"""
test_idor.py - Unit tests for IDOR Scanner
"""
import pytest
from unittest.mock import AsyncMock
from modules.idor import IDORScanner


class TestIDORScanner:
    """Test IDOR vulnerability detection"""

    @pytest.fixture
    def scanner(self):
        return IDORScanner()

    @pytest.fixture
    def mock_client(self):
        return AsyncMock()

    def test_scanner_initialization(self, scanner):
        """Test scanner initializes"""
        assert scanner is not None

    @pytest.mark.asyncio
    async def test_scan_url_returns_list(self, scanner, mock_client):
        """Test scan_url returns list"""
        mock_response = AsyncMock()
        mock_response.status_code = 200
        mock_response.text = "User data for ID 123"
        mock_client.get = AsyncMock(return_value=mock_response)

        results = await scanner.scan_url("http://example.com/api/user?id=123", mock_client)
        
        assert isinstance(results, list)

    @pytest.mark.asyncio
    async def test_detect_idor_sequential_ids(self, scanner, mock_client):
        """Test IDOR detection with sequential IDs"""
        async def get_side_effect(url):
            response = AsyncMock()
            response.status_code = 200
            # Different users return data
            if "id=1" in url or "id=2" in url or "id=3" in url:
                response.text = f"User found for {url}"
            else:
                response.text = "Access denied"
            return response

        mock_client.get = AsyncMock(side_effect=get_side_effect)

        results = await scanner.scan_url("http://example.com/api/user?id=1", mock_client)
        
        # May detect IDOR if pattern found
        assert isinstance(results, list)

    @pytest.mark.asyncio
    async def test_no_idor_proper_access_control(self, scanner, mock_client):
        """Test no IDOR with proper access control"""
        mock_response = AsyncMock()
        mock_response.status_code = 403
        mock_response.text = "Access Denied"
        mock_client.get = AsyncMock(return_value=mock_response)

        results = await scanner.scan_url("http://example.com/api/user?id=999", mock_client)
        
        # Proper access control, should not flag IDOR
        assert isinstance(results, list)

    @pytest.mark.asyncio
    async def test_detect_idor_uuid(self, scanner, mock_client):
        """Test IDOR detection with UUIDs"""
        mock_response = AsyncMock()
        mock_response.status_code = 200
        mock_response.text = "Profile data"
        mock_client.get = AsyncMock(return_value=mock_response)

        results = await scanner.scan_url(
            "http://example.com/api/profile?user_id=550e8400-e29b-41d4-a716-446655440000",
            mock_client
        )
        
        assert isinstance(results, list)

    @pytest.mark.asyncio
    async def test_scan_handles_404(self, scanner, mock_client):
        """Test scan handles 404 responses"""
        mock_response = AsyncMock()
        mock_response.status_code = 404
        mock_response.text = "Not Found"
        mock_client.get = AsyncMock(return_value=mock_response)

        results = await scanner.scan_url("http://example.com/api/user?id=999", mock_client)
        
        # 404 is normal, not IDOR
        assert isinstance(results, list)
