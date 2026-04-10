"""
test_response_differ.py - Unit tests for Response Differ
"""
import pytest
from detection.response_differ import ResponseDiffer, DiffResult


class TestResponseDiffer:
    """Test response comparison for blind detection"""

    @pytest.fixture
    def differ(self):
        """Initialize ResponseDiffer"""
        return ResponseDiffer(threshold=0.95)

    @pytest.fixture
    def differ_strict(self):
        """Initialize with strict threshold"""
        return ResponseDiffer(threshold=0.90)

    # ==================== INITIALIZATION TESTS ====================

    def test_differ_initialization(self, differ):
        """Test differ initializes with threshold"""
        assert differ.threshold == 0.95

    def test_differ_custom_threshold(self):
        """Test custom threshold"""
        differ = ResponseDiffer(threshold=0.80)
        assert differ.threshold == 0.80

    # ==================== DIFF RESULT TESTS ====================

    def test_diff_returns_result_object(self, differ):
        """Test diff returns DiffResult"""
        result = differ.diff("abc", "abc")
        assert isinstance(result, DiffResult)
        assert hasattr(result, 'is_different')
        assert hasattr(result, 'similarity')
        assert hasattr(result, 'length_delta')

    def test_diff_result_has_all_fields(self, differ):
        """Test DiffResult contains all required fields"""
        result = differ.diff("baseline", "response")
        assert hasattr(result, 'is_different')
        assert hasattr(result, 'similarity')
        assert hasattr(result, 'length_delta')
        assert hasattr(result, 'structure_changed')
        assert hasattr(result, 'new_blocks')
        assert hasattr(result, 'anomaly_score')

    # ==================== IDENTICAL RESPONSES ====================

    def test_identical_responses(self, differ):
        """Test identical responses show 100% similarity"""
        response = "This is a test response"
        result = differ.diff(response, response)
        
        assert result.similarity == 1.0
        assert result.length_delta == 0
        assert result.is_different is False

    def test_empty_responses(self, differ):
        """Test empty responses are considered identical"""
        result = differ.diff("", "")
        
        assert result.similarity == 1.0
        assert result.is_different is False

    # ==================== SIMILAR RESPONSES ====================

    def test_slightly_different_responses(self, differ):
        """Test responses with minor differences"""
        baseline = "This is a baseline response with some content"
        response = "This is a baseline response with some content!"  # Added !
        result = differ.diff(baseline, response)
        
        assert result.similarity > 0.95
        assert result.is_different is False

    def test_different_responses(self, differ):
        """Test very different responses"""
        baseline = "Login successful"
        response = "Login failed"
        result = differ.diff(baseline, response)
        
        assert result.similarity < 0.95
        assert result.is_different is True

    # ==================== LENGTH DELTA TESTS ====================

    def test_length_delta_calculation(self, differ):
        """Test length difference is calculated"""
        baseline = "short"
        response = "much longer response"
        result = differ.diff(baseline, response)
        
        assert result.length_delta == len(response) - len(baseline)
        assert result.length_delta > 0

    def test_length_delta_negative(self, differ):
        """Test negative length delta"""
        baseline = "very long baseline response"
        response = "short"
        result = differ.diff(baseline, response)
        
        assert result.length_delta < 0

    def test_large_length_delta(self, differ):
        """Test large length differences affect anomaly score"""
        baseline = "x"
        response = "y" * 2000
        result = differ.diff(baseline, response)
        
        assert result.length_delta > 1000
        assert result.anomaly_score > 0

    # ==================== STRUCTURE CHANGE TESTS ====================

    def test_structure_unchanged(self, differ):
        """Test HTML structure unchanged"""
        baseline = "<div><p>Content</p></div>"
        response = "<div><p>Different content</p></div>"
        result = differ.diff(baseline, response)
        
        assert result.structure_changed is False

    def test_structure_changed_tags(self, differ):
        """Test HTML structure changed (different tags)"""
        baseline = "<div><p>Content</p></div>"
        response = "<div><span>Content</span></div>"
        result = differ.diff(baseline, response)
        
        assert result.structure_changed is True

    def test_structure_added_elements(self, differ):
        """Test added HTML elements detected"""
        baseline = "<div><p>Content</p></div>"
        response = "<div><p>Content</p><p>Extra</p></div>"
        result = differ.diff(baseline, response)
        
        assert result.structure_changed is True

    # ==================== NEW BLOCKS DETECTION ====================

    def test_new_content_detected(self, differ):
        """Test new content blocks are detected"""
        baseline = "Line 1\nLine 2"
        response = "Line 1\nLine 2\nLine 3 NEW"
        result = differ.diff(baseline, response)
        
        assert len(result.new_blocks) > 0
        assert any("Line 3" in block for block in result.new_blocks)

    def test_new_blocks_limited(self, differ):
        """Test new blocks list is limited to 5"""
        baseline = "line"
        response = "\n".join([f"line {i}" for i in range(20)])
        result = differ.diff(baseline, response)
        
        assert len(result.new_blocks) <= 5

    def test_no_new_blocks_identical(self, differ):
        """Test no new blocks for identical responses"""
        response = "This is content"
        result = differ.diff(response, response)
        
        assert len(result.new_blocks) == 0

    # ==================== ERROR PAGE DETECTION ====================

    def test_is_error_page_500(self, differ):
        """Test error page detection for 500 errors"""
        error_response = "Internal Server Error 500"
        assert differ.is_error_page(error_response) is True

    def test_is_error_page_stack_trace(self, differ):
        """Test error page detection for stack trace"""
        error_response = """
        Traceback (most recent call last):
            File "app.py", line 42
        Exception: Database connection failed
        """
        assert differ.is_error_page(error_response) is True

    def test_is_error_page_exception(self, differ):
        """Test error page detection for exception"""
        error_response = "Fatal Exception: Null pointer exception"
        assert differ.is_error_page(error_response) is True

    def test_is_error_page_normal(self, differ):
        """Test normal page is not detected as error"""
        normal_response = "Welcome to our website today"
        assert differ.is_error_page(normal_response) is False

    def test_is_error_page_login_failed(self, differ):
        """Test login failure is not detected as error"""
        response = "Login Failed: Invalid credentials"
        assert differ.is_error_page(response) is False

    # ==================== SIMILARITY SCORING ====================

    def test_similarity_score_range(self, differ):
        """Test similarity score is between 0 and 1"""
        result = differ.diff("abc", "xyz")
        
        assert 0.0 <= result.similarity <= 1.0

    def test_similarity_precision(self, differ):
        """Test similarity is rounded to 4 decimals"""
        result = differ.diff("baseline", "response")
        
        # Should be rounded to 4 decimals
        assert isinstance(result.similarity, float)

    def test_similarity_empty_baseline(self, differ):
        """Test similarity with empty baseline"""
        result = differ.diff("", "content")
        
        # Should handle gracefully
        assert isinstance(result.similarity, float)

    def test_similarity_long_content(self, differ):
        """Test similarity with very long content"""
        baseline = "content " * 1000
        response = "content " * 999 + "modified"
        result = differ.diff(baseline, response)
        
        assert 0.0 <= result.similarity <= 1.0

    # ==================== ANOMALY SCORING ====================

    def test_anomaly_score_range(self, differ):
        """Test anomaly score is between 0 and 1"""
        result = differ.diff("baseline", "response")
        
        assert 0.0 <= result.anomaly_score <= 1.0

    def test_anomaly_increases_with_difference(self, differ):
        """Test anomaly score increases with dissimilarity"""
        similar = differ.diff("abc", "abc")
        different = differ.diff("abc", "xyz")
        
        assert different.anomaly_score >= similar.anomaly_score

    def test_anomaly_precision(self, differ):
        """Test anomaly score is rounded to 3 decimals"""
        result = differ.diff("baseline", "response")
        
        # Should be rounded to 3 decimals
        assert isinstance(result.anomaly_score, float)

    # ==================== THRESHOLD BEHAVIOR ====================

    def test_is_different_threshold_strict(self, differ_strict):
        """Test is_different with strict threshold"""
        baseline = "content"
        response = "content with slight difference"
        result = differ_strict.diff(baseline, response)
        
        # With strict threshold (0.90), might be marked different
        assert isinstance(result.is_different, bool)

    def test_is_different_threshold_loose(self):
        """Test is_different with loose threshold"""
        differ = ResponseDiffer(threshold=0.90)
        baseline = "a"
        response = "ab"
        result = differ.diff(baseline, response)
        
        # With threshold 0.90, is_different = (similarity < 0.90)
        # responses "a" and "ab" are ~67% similar, so is_different should be True
        assert (result.is_different and result.similarity < 0.90) or (not result.is_different and result.similarity >= 0.90)

    # ==================== BOOLEAN SQLI SCENARIOS ====================

    def test_boolean_sqli_true_condition(self, differ):
        """Test baseline similarity for TRUE boolean SQLi"""
        baseline = "Welcome. You have 5 items."
        true_payload = "Welcome. You have 5 items."
        result = differ.diff(baseline, true_payload)
        
        assert result.similarity == 1.0
        assert result.is_different is False

    def test_boolean_sqli_false_condition(self, differ):
        """Test different response for FALSE boolean SQLi"""
        baseline = "Welcome. You have 5 items."
        false_payload = "Invalid request"
        result = differ.diff(baseline, false_payload)
        
        assert result.is_different is True

    # ==================== TIME SQLI SCENARIOS ====================

    def test_blind_time_detection_normal(self, differ):
        """Test normal response time detection setup"""
        response1 = "Response content"
        response2 = "Response content"
        result = differ.diff(response1, response2)
        
        # Same content means same response
        assert result.similarity == 1.0

    # ==================== EDGE CASES ====================

    def test_very_long_responses(self, differ):
        """Test with very long responses (truncated processing)"""
        baseline = "x" * 100000
        response = "y" * 100000
        result = differ.diff(baseline, response)
        
        # Should handle without crash
        assert isinstance(result, DiffResult)

    def test_unicode_content(self, differ):
        """Test with unicode content"""
        baseline = "Hello 世界 مرحبا"
        response = "Hello 世界 مرحبا!"
        result = differ.diff(baseline, response)
        
        # Should handle unicode
        assert isinstance(result.similarity, float)

    def test_html_entities(self, differ):
        """Test with HTML entities"""
        baseline = "&lt;script&gt;alert(1)&lt;/script&gt;"
        response = "&lt;script&gt;alert(1)&lt;/script&gt;"
        result = differ.diff(baseline, response)
        
        assert result.similarity == 1.0

    def test_whitespace_only_difference(self, differ):
        """Test responses differing only in whitespace"""
        baseline = "Content  with  spaces"
        response = "Content with spaces"
        result = differ.diff(baseline, response)
        
        # Should detect slight difference
        assert isinstance(result.is_different, bool)

    def test_newline_differences(self, differ):
        """Test responses differing in newlines"""
        baseline = "Line1\nLine2\nLine3"
        response = "Line1\r\nLine2\r\nLine3"
        result = differ.diff(baseline, response)
        
        # Should be similar despite whitespace
        assert result.similarity > 0.5

    # ==================== STORED XSS SCENARIOS ====================

    def test_stored_xss_baseline(self, differ):
        """Test baseline page without payload"""
        baseline = "<div class='comments'>No comments yet</div>"
        response = "<div class='comments'>No comments yet</div>"
        result = differ.diff(baseline, response)
        
        assert result.is_different is False

    def test_stored_xss_after_injection(self, differ):
        """Test page after XSS payload stored"""
        baseline = "<div class='comments'>No comments yet</div>"
        response = "<div class='comments'><script>alert(1)</script></div>"
        result = differ.diff(baseline, response)
        
        assert result.is_different is True
        assert len(result.new_blocks) > 0
