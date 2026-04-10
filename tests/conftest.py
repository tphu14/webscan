"""
conftest.py - Shared pytest fixtures for WebVulnScanner tests
"""
import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch
from io import StringIO
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))


# ==================== ASYNC FIXTURES ====================

@pytest.fixture
def event_loop():
    """Create an event loop for async tests"""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture
async def mock_httpx_client():
    """Mock httpx AsyncClient for testing"""
    client = AsyncMock()
    
    # Setup default mock responses
    mock_response = AsyncMock()
    mock_response.status_code = 200
    mock_response.text = "<html><body><a href='/page1'>Link</a></body></html>"
    mock_response.headers = {"Content-Type": "text/html"}
    
    client.get = AsyncMock(return_value=mock_response)
    client.post = AsyncMock(return_value=mock_response)
    client.put = AsyncMock(return_value=mock_response)
    client.delete = AsyncMock(return_value=mock_response)
    
    return client


# ==================== CONFIG FIXTURES ====================

@pytest.fixture
def default_config():
    """Default scanner configuration"""
    return {
        "scanner": {
            "max_depth": 3,
            "max_pages": 50,
            "timeout": 10,
            "concurrency": 8,
            "rate_limit": 8.0,
            "burst": 15,
            "user_agent": "WebVulnScanner/3.0 (Testing)",
            "verify_ssl": False,
            "follow_redirects": True,
        },
        "modules": {
            "sqli": True,
            "xss": True,
            "sensitive_files": True,
            "open_redirect": True,
            "headers": True,
            "waf_detect": True,
            "time_sqli": True,
            "ssrf": True,
            "csrf": True,
            "idor": True,
            "jwt": True,
            "cors": True,
            "graphql": True,
            "api_fuzzer": True,
            "ssti": True,
            "lfi": True,
            "xxe": True,
            "subdomain_takeover": True,
        },
        "detection": {
            "confidence_threshold": 0.65,
            "differ_threshold": 0.93,
            "deduplication": True,
        },
        "reporting": {
            "cvss_scoring": True,
            "include_waf_info": True,
        },
        "logging": {
            "level": "WARNING",
            "log_file": None,
        },
    }


@pytest.fixture
def crawler_config(default_config):
    """Configuration for Crawler tests"""
    return default_config["scanner"]


# ==================== HTML FIXTURES ====================

@pytest.fixture
def sample_html_simple():
    """Simple HTML page with basic structure"""
    return """
    <html>
        <head><title>Test Page</title></head>
        <body>
            <a href="/page1">Link 1</a>
            <a href="/page2">Link 2</a>
            <form action="/search" method="GET">
                <input type="text" name="q" />
                <input type="submit" value="Search" />
            </form>
        </body>
    </html>
    """


@pytest.fixture
def sample_html_forms():
    """HTML page with various forms"""
    return """
    <html>
        <body>
            <form id="login" action="/login" method="POST">
                <input type="text" name="username" />
                <input type="password" name="password" />
                <input type="submit" value="Login" />
            </form>
            <form id="search" action="/api/search" method="GET">
                <input type="text" name="query" />
                <textarea name="description"></textarea>
                <select name="category">
                    <option>Cat1</option>
                    <option>Cat2</option>
                </select>
            </form>
        </body>
    </html>
    """


@pytest.fixture
def sample_html_with_links():
    """HTML with various link types"""
    return """
    <html>
        <body>
            <a href="/relative">Relative link</a>
            <a href="/page/subpage">Nested link</a>
            <a href="./same-dir">Same dir link</a>
            <a href="https://external.com">External link</a>
            <a href="javascript:void(0)">JS link</a>
            <a href="#">Anchor link</a>
        </body>
    </html>
    """


# ==================== RESPONSE FIXTURES ====================

@pytest.fixture
def response_sqli_error():
    """Mock response with SQL error"""
    return """
    <html>
        <body>
            <h1>Database Error</h1>
            <p>You have an error in your SQL syntax; check the manual that corresponds 
            to your MySQL server version for the right syntax to use near ''&quot;' at line 1</p>
        </body>
    </html>
    """


@pytest.fixture
def response_xss_reflected():
    """Mock response with reflected XSS"""
    return """
    <html>
        <body>
            <h1>Search Results</h1>
            <p>You searched for: <script>alert('XSS')</script></p>
        </body>
    </html>
    """


@pytest.fixture
def response_normal():
    """Mock normal HTTP response"""
    return """
    <html>
        <head><title>Normal Page</title></head>
        <body>
            <h1>Welcome</h1>
            <p>This is a normal page with no vulnerabilities.</p>
        </body>
    </html>
    """


@pytest.fixture
def response_with_headers():
    """Mock response headers"""
    return {
        "Content-Type": "text/html; charset=utf-8",
        "Server": "Apache/2.4.41",
        "X-Powered-By": "PHP/7.4.3",
        "X-Frame-Options": "SAMEORIGIN",
        "X-Content-Type-Options": "nosniff",
        "Strict-Transport-Security": "max-age=31536000",
        "Content-Security-Policy": "default-src 'self'",
        "Set-Cookie": "PHPSESSID=abc123def456ghi789; Path=/; HttpOnly",
    }


@pytest.fixture
def response_missing_headers():
    """Mock response with missing security headers"""
    return {
        "Content-Type": "text/html",
        "Server": "nginx",
        # Missing: X-Frame-Options, X-Content-Type-Options, CSP, etc.
    }


@pytest.fixture
def response_waf_blocked():
    """Mock WAF blocking response"""
    return """
    <html>
        <head><title>403 Forbidden</title></head>
        <body>
            <h1>Access Denied</h1>
            <p>Your request was blocked by our security system.</p>
            <!-- ModSecurity powered by OWASP -->
        </body>
    </html>
    """


# ==================== PAYLOAD FIXTURES ====================

@pytest.fixture
def sqli_payloads():
    """Common SQL injection payloads"""
    return [
        "'",
        "''",
        "' OR '1'='1",
        "' OR 1=1--",
        "'; DROP TABLE users--",
        "1' ORDER BY 1--",
        "1' UNION SELECT NULL--",
    ]


@pytest.fixture
def xss_payloads():
    """Common XSS payloads"""
    return [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "<svg onload=alert('XSS')>",
        "';alert('XSS');//",
        "\"><script>alert('XSS')</script>",
        "<iframe src=x onload=alert('XSS')>",
    ]


@pytest.fixture
def lfi_payloads():
    """Common LFI payloads"""
    return [
        "../../../etc/passwd",
        "..\\..\\..\\windows\\win.ini",
        "./../.../../etc/passwd",
        "....//....//....//etc/passwd",
        "%2e%2e%2fetc%2fpasswd",
    ]


@pytest.fixture
def ssrf_payloads():
    """Common SSRF payloads"""
    return [
        "http://localhost",
        "http://127.0.0.1",
        "http://192.168.1.1",
        "http://169.254.169.254",
        "file:///etc/passwd",
        "gopher://localhost",
    ]


# ==================== MOCK OBJECTS ====================

@pytest.fixture
def mock_vulnerability():
    """Mock vulnerability object"""
    return {
        "type": "SQL Injection",
        "severity": "HIGH",
        "confidence": 0.95,
        "url": "http://target.com/page?id=1",
        "parameter": "id",
        "payload": "' OR '1'='1",
        "response": "SQL error message",
        "cvss_score": 7.5,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    }


@pytest.fixture
def mock_crawler_result():
    """Mock crawler discovery result"""
    return {
        "urls": [
            "http://target.com/",
            "http://target.com/page1",
            "http://target.com/page2",
            "http://target.com/admin",
        ],
        "forms": [
            {
                "url": "http://target.com/search",
                "method": "GET",
                "inputs": [
                    {"name": "q", "type": "text"},
                    {"name": "submit", "type": "submit"}
                ]
            },
            {
                "url": "http://target.com/login",
                "method": "POST",
                "inputs": [
                    {"name": "username", "type": "text"},
                    {"name": "password", "type": "password"}
                ]
            }
        ]
    }


# ==================== CONTEXT MANAGERS ====================

@pytest.fixture
def capture_stdout():
    """Capture stdout for testing print statements"""
    old_stdout = sys.stdout
    sys.stdout = StringIO()
    yield sys.stdout
    sys.stdout = old_stdout


# ==================== MARKERS ====================

def pytest_configure(config):
    """Register custom markers"""
    config.addinivalue_line("markers", "unit: unit tests")
    config.addinivalue_line("markers", "integration: integration tests")
    config.addinivalue_line("markers", "slow: slow tests")
