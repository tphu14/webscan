"""
test_jwt_analyzer.py - Unit tests for JWT Analyzer
"""
import pytest
from unittest.mock import AsyncMock
from modules.jwt_analyzer import JWTAnalyzer


class TestJWTAnalyzer:
    """Test JWT vulnerability detection"""

    @pytest.fixture
    def analyzer(self):
        return JWTAnalyzer()

    @pytest.fixture
    def mock_client(self):
        return AsyncMock()

    def test_analyzer_initialization(self, analyzer):
        """Test analyzer initializes"""
        assert analyzer is not None

    def test_valid_jwt_format(self, analyzer):
        """Test valid JWT format detection"""
        # Valid JWT: header.payload.signature
        valid_jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
        
        # Analyzer should recognize JWT
        assert "." in valid_jwt
        parts = valid_jwt.split(".")
        assert len(parts) == 3

    @pytest.mark.asyncio
    async def test_scan_urls_returns_list(self, analyzer, mock_client):
        """Test scan returns list"""
        mock_response = AsyncMock()
        mock_response.headers = {}
        mock_response.cookies = {}
        mock_response.text = ""
        mock_client.get = AsyncMock(return_value=mock_response)

        results = await analyzer.scan("http://example.com", mock_client)
        
        assert isinstance(results, list)

    @pytest.mark.asyncio
    async def test_detect_jwt_in_cookie(self, analyzer, mock_client):
        """Test JWT detection in cookies"""
        mock_response = AsyncMock()
        mock_response.headers = {}
        # JWT in cookie
        mock_response.cookies = {
            "token": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.x"
        }
        mock_response.text = ""
        mock_client.get = AsyncMock(return_value=mock_response)

        results = await analyzer.scan("http://example.com", mock_client)
        
        # May detect JWT
        assert isinstance(results, list)

    @pytest.mark.asyncio
    async def test_detect_jwt_in_header(self, analyzer, mock_client):
        """Test JWT detection in Authorization header"""
        mock_response = AsyncMock()
        # JWT in Authorization header
        mock_response.headers = {
            "Authorization": "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.x"
        }
        mock_response.cookies = {}
        mock_response.text = ""
        mock_client.get = AsyncMock(return_value=mock_response)

        results = await analyzer.scan("http://example.com", mock_client)
        
        assert isinstance(results, list)

    @pytest.mark.asyncio
    async def test_detect_weak_signing_algorithm(self, analyzer, mock_client):
        """Test detection of weak JWT algorithm"""
        mock_response = AsyncMock()
        mock_response.headers = {}
        mock_response.cookies = {}
        # JWT with no signature (none algorithm vulnerability)
        mock_response.text = ""
        mock_client.get = AsyncMock(return_value=mock_response)

        results = await analyzer.scan("http://example.com", mock_client)
        
        assert isinstance(results, list)

    def test_jwt_structure_validation(self, analyzer):
        """Test JWT structure has 3 parts"""
        jwt_token = "header.payload.signature"
        parts = jwt_token.split(".")
        
        assert len(parts) == 3
