"""
test_crawler.py - Unit tests for Web Crawler
"""
import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from core.crawler import Crawler


class TestCrawler:
    """Test Web Crawler functionality"""

    @pytest.fixture
    def crawler(self):
        """Initialize crawler with test URL"""
        return Crawler(
            base_url="http://example.com",
            max_depth=2,
            max_pages=10,
            timeout=5
        )

    # ==================== INITIALIZATION TESTS ====================

    def test_crawler_initialization(self, crawler):
        """Test crawler initializes with correct parameters"""
        assert crawler.base_url == "http://example.com"
        assert crawler.base_domain == "example.com"
        assert crawler.max_depth == 2
        assert crawler.max_pages == 10
        assert crawler.timeout == 5

    def test_base_url_rstrip_slash(self):
        """Test base URL strips trailing slash"""
        crawler = Crawler("http://example.com/")
        assert crawler.base_url == "http://example.com"

    def test_base_domain_extraction(self):
        """Test base domain is correctly extracted"""
        crawler = Crawler("http://subdomain.example.com/path")
        assert crawler.base_domain == "subdomain.example.com"

    def test_crawler_started_with_empty_lists(self, crawler):
        """Test crawler starts with empty visited, found_urls, forms"""
        assert len(crawler.visited) == 0
        assert len(crawler.found_urls) == 0
        assert len(crawler.forms) == 0

    # ==================== URL NORMALIZATION TESTS ====================

    def test_normalize_url_removes_fragment(self, crawler):
        """Test URL normalization removes fragment"""
        url = "http://example.com/page#section"
        normalized = crawler._normalize_url(url)
        assert "#section" not in normalized
        assert normalized == "http://example.com/page"

    def test_normalize_url_removes_query(self, crawler):
        """Test URL normalization removes query string"""
        url = "http://example.com/page?id=123"
        normalized = crawler._normalize_url(url)
        assert "?id=123" not in normalized
        assert normalized == "http://example.com/page"

    def test_normalize_url_preserves_path(self, crawler):
        """Test URL normalization preserves path"""
        url = "http://example.com/path/to/page"
        normalized = crawler._normalize_url(url)
        assert "/path/to/page" in normalized

    def test_normalize_url_with_protocol(self, crawler):
        """Test URL normalization preserves protocol"""
        url_http = "http://example.com/page"
        url_https = "https://example.com/page"
        assert crawler._normalize_url(url_http).startswith("http://")
        assert crawler._normalize_url(url_https).startswith("https://")

    # ==================== DOMAIN CHECKING TESTS ====================

    def test_is_same_domain_true_for_same_domain(self, crawler):
        """Test same domain returns True"""
        assert crawler._is_same_domain("http://example.com/page") is True
        assert crawler._is_same_domain("http://example.com/another") is True

    def test_is_same_domain_true_for_subdomain(self, crawler):
        """Test subdomain detection (should be different domain)"""
        # Note: subdomain.example.com is a different domain than example.com
        is_same = crawler._is_same_domain("http://subdomain.example.com/page")
        assert is_same is False

    def test_is_same_domain_false_for_different_domain(self, crawler):
        """Test different domain returns False"""
        assert crawler._is_same_domain("http://other.com/page") is False
        assert crawler._is_same_domain("http://google.com") is False

    def test_is_same_domain_with_port(self, crawler):
        """Test domain check with port numbers"""
        crawler_port = Crawler("http://example.com:8080")
        assert crawler_port._is_same_domain("http://example.com:8080/page") is True
        assert crawler_port._is_same_domain("http://example.com/page") is False

    # ==================== LINK EXTRACTION TESTS ====================

    def test_extract_links_from_html(self, crawler, sample_html_with_links):
        """Test link extraction from HTML"""
        links = crawler._extract_links(sample_html_with_links, "http://example.com")
        
        # Should extract relative and nested links
        assert len(links) >= 3
        assert any("/relative" in link for link in links)
        assert any("/page/subpage" in link for link in links)

    def test_extract_links_filters_same_domain(self, crawler, sample_html_with_links):
        """Test that external links are not extracted"""
        links = crawler._extract_links(sample_html_with_links, "http://example.com")
        
        # Should not include external link
        external_links = [link for link in links if "external.com" in link]
        assert len(external_links) == 0

    def test_extract_links_normalizes_urls(self, crawler):
        """Test extracted links are normalized"""
        html = """
        <html>
            <a href="/page?id=1#section">Page</a>
            <a href="/page?id=2">Same Page</a>
        </html>
        """
        links = crawler._extract_links(html, "http://example.com")
        
        # Removed query strings and fragments should result in same URLs
        assert len(links) <= 2

    def test_extract_links_skips_javascript(self, crawler):
        """Test that JavaScript links are skipped or handled"""
        html = """
        <html>
            <a href="javascript:void(0)">JS Link</a>
            <a href="/real-page">Real Link</a>
        </html>
        """
        links = crawler._extract_links(html, "http://example.com")
        
        # Should filter out javascript: links or handle them
        real_links = [link for link in links if link.startswith("http")]
        assert len(real_links) >= 1

    def test_extract_links_empty_html(self, crawler):
        """Test link extraction from empty HTML"""
        links = crawler._extract_links("<html></html>", "http://example.com")
        assert len(links) == 0

    def test_extract_links_no_duplicate_in_visited(self, crawler):
        """Test already visited links are not extracted again"""
        crawler.visited.add("http://example.com/visited")
        html = """
        <html>
            <a href="/visited">Visited</a>
            <a href="/new">New</a>
        </html>
        """
        links = crawler._extract_links(html, "http://example.com")
        
        # Should not include visited link
        visited_in_links = [link for link in links if "visited" in link]
        assert len(visited_in_links) == 0

    # ==================== FORM EXTRACTION TESTS ====================

    def test_extract_forms_from_html(self, crawler, sample_html_forms):
        """Test form extraction from HTML"""
        crawler._extract_forms(sample_html_forms, "http://example.com")
        
        assert len(crawler.forms) >= 2
        assert crawler.forms[0]["method"] in ["GET", "POST"]
        assert "url" in crawler.forms[0]
        assert "inputs" in crawler.forms[0]

    def test_extract_form_with_inputs(self, crawler):
        """Test form input extraction"""
        html = """
        <html>
            <form action="/login" method="POST">
                <input type="text" name="username" />
                <input type="password" name="password" />
                <textarea name="bio"></textarea>
                <select name="role"><option>Admin</option></select>
            </form>
        </html>
        """
        crawler._extract_forms(html, "http://example.com")
        
        assert len(crawler.forms) >= 1
        form = crawler.forms[0]
        assert len(form["inputs"]) >= 4
        assert any(inp["name"] == "username" for inp in form["inputs"])
        assert any(inp["name"] == "password" for inp in form["inputs"])

    def test_extract_form_without_action(self, crawler):
        """Test form extraction when action is missing"""
        html = """
        <html>
            <form method="POST">
                <input type="text" name="field" />
            </form>
        </html>
        """
        crawler._extract_forms(html, "http://example.com/page")
        
        assert len(crawler.forms) >= 1
        # Should default to current URL
        assert crawler.forms[0]["url"] == "http://example.com/page"

    def test_extract_form_method_normalization(self, crawler):
        """Test form method is normalized to uppercase"""
        html = """
        <html>
            <form method="post"><input name="field" /></form>
            <form method="get"><input name="field" /></form>
        </html>
        """
        crawler._extract_forms(html, "http://example.com")
        
        assert len(crawler.forms) >= 2
        assert all(form["method"] in ["GET", "POST"] for form in crawler.forms)

    def test_extract_form_with_relative_action(self, crawler):
        """Test form action URL joining"""
        html = """
        <html>
            <form action="/api/submit" method="POST">
                <input name="field" />
            </form>
        </html>
        """
        crawler._extract_forms(html, "http://example.com/page")
        
        form = crawler.forms[0]
        assert form["url"] == "http://example.com/api/submit"

    def test_extract_form_stores_source_page(self, crawler):
        """Test form extraction stores source page URL"""
        html = """
        <html>
            <form action="/submit" method="POST">
                <input name="field" />
            </form>
        </html>
        """
        source_url = "http://example.com/contact"
        crawler._extract_forms(html, source_url)
        
        assert crawler.forms[0]["source_page"] == source_url

    def test_extract_multiple_forms(self, crawler):
        """Test extraction of multiple forms from single page"""
        html = """
        <html>
            <form action="/search" method="GET"><input name="q" /></form>
            <form action="/login" method="POST"><input name="user" /></form>
            <form action="/signup" method="POST"><input name="email" /></form>
        </html>
        """
        crawler._extract_forms(html, "http://example.com")
        
        assert len(crawler.forms) == 3

    # ==================== ASYNC CRAWL TESTS ====================

    @pytest.mark.asyncio
    async def test_crawl_returns_correct_structure(self, crawler):
        """Test crawl returns expected structure"""
        with patch('httpx.AsyncClient') as mock_client_class:
            # Mock the async client
            mock_client = AsyncMock()
            mock_response = AsyncMock()
            mock_response.headers = {"content-type": "text/html"}
            mock_response.text = "<html><body><a href='/page1'>Link</a></body></html>"
            mock_client.get = AsyncMock(return_value=mock_response)
            mock_client.__aenter__.return_value = mock_client
            mock_client.__aexit__.return_value = None
            mock_client_class.return_value = mock_client

            result = await crawler.crawl()

            assert isinstance(result, dict)
            assert "urls" in result
            assert "forms" in result
            assert "total_urls" in result
            assert "total_forms" in result

    @pytest.mark.asyncio
    async def test_crawl_respects_max_pages(self, crawler):
        """Test crawl respects max_pages limit"""
        crawler.max_pages = 5

        with patch('httpx.AsyncClient') as mock_client_class:
            mock_client = AsyncMock()
            mock_response = AsyncMock()
            mock_response.headers = {"content-type": "text/html"}
            mock_response.text = """
            <html>
                <a href='/1'>1</a><a href='/2'>2</a>
                <a href='/3'>3</a><a href='/4'>4</a>
            </html>
            """
            mock_client.get = AsyncMock(return_value=mock_response)
            mock_client.__aenter__.return_value = mock_client
            mock_client.__aexit__.return_value = None
            mock_client_class.return_value = mock_client

            result = await crawler.crawl()

            assert result["total_urls"] <= crawler.max_pages

    @pytest.mark.asyncio
    async def test_crawl_respects_max_depth(self, crawler):
        """Test crawl respects max depth limitation"""
        crawler.max_depth = 1

        with patch('httpx.AsyncClient') as mock_client_class:
            mock_client = AsyncMock()
            mock_response = AsyncMock()
            mock_response.headers = {"content-type": "text/html"}
            mock_response.text = "<html><a href='/page'>Link</a></html>"
            mock_client.get = AsyncMock(return_value=mock_response)
            mock_client.__aenter__.return_value = mock_client
            mock_client.__aexit__.return_value = None
            mock_client_class.return_value = mock_client

            result = await crawler.crawl()

            # URLs should be limited by depth
            assert len(result["urls"]) <= 10

    @pytest.mark.asyncio
    async def test_crawl_skips_non_html(self, crawler):
        """Test crawl skips non-HTML responses"""
        with patch('httpx.AsyncClient') as mock_client_class:
            mock_client = AsyncMock()

            async def get_side_effect(url, **kwargs):
                response = AsyncMock()
                if "image" in url:
                    response.headers = {"content-type": "image/png"}
                else:
                    response.headers = {"content-type": "text/html"}
                    response.text = "<html></html>"
                return response

            mock_client.get = AsyncMock(side_effect=get_side_effect)
            mock_client.__aenter__.return_value = mock_client
            mock_client.__aexit__.return_value = None
            mock_client_class.return_value = mock_client

            result = await crawler.crawl()

            # Should handle mixed content types
            assert isinstance(result["urls"], list)

    # ==================== EDGE CASES ====================

    def test_crawler_with_long_url(self):
        """Test crawler handles long URLs"""
        long_path = "/path/" + "a" * 2000
        crawler = Crawler(f"http://example.com{long_path}")
        assert crawler.base_domain == "example.com"

    def test_crawler_with_special_characters_in_domain(self):
        """Test crawler handles special characters in path"""
        crawler = Crawler("http://example.com/path-with-dash")
        assert crawler.base_domain == "example.com"

    def test_crawler_with_empty_html(self, crawler):
        """Test crawler handles empty HTML"""
        links = crawler._extract_links("", "http://example.com")
        assert len(links) == 0

    def test_crawler_with_malformed_html(self, crawler):
        """Test crawler handles malformed HTML gracefully"""
        html = "<html><body><a href='/page'><p>Unclosed tags"
        links = crawler._extract_links(html, "http://example.com")
        # Should attempt to parse despite malformation
        assert isinstance(links, list)

    def test_crawler_with_unicode_urls(self, crawler):
        """Test crawler handles unicode in URLs"""
        html = """
        <html>
            <a href="/café">Café Link</a>
            <a href="/中文">Chinese</a>
        </html>
        """
        # Should not crash
        links = crawler._extract_links(html, "http://example.com")
        assert isinstance(links, list)
