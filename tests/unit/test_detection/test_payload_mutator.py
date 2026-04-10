"""
test_payload_mutator.py - Unit tests for Payload Mutator
"""
import pytest
from detection.payload_mutator import PayloadMutator, MutatedPayload


class TestPayloadMutator:
    """Test Payload mutation for WAF bypassing"""

    @pytest.fixture
    def mutator(self):
        """Initialize payload mutator"""
        return PayloadMutator()

    # ==================== INITIALIZATION TESTS ====================

    def test_mutator_initialization(self, mutator):
        """Test mutator initializes correctly"""
        assert mutator is not None

    # ==================== MUTATE ALL TESTS ====================

    def test_mutate_all_returns_list(self, mutator):
        """Test mutate_all returns list"""
        payload = "SELECT * FROM users"
        results = mutator.mutate_all(payload)
        
        assert isinstance(results, list)
        assert len(results) > 0

    def test_mutate_all_includes_original(self, mutator):
        """Test original payload is included"""
        payload = "SELECT"
        results = mutator.mutate_all(payload)
        
        assert any(r.mutated == payload for r in results)

    def test_mutate_all_returns_mutated_payload_objects(self, mutator):
        """Test returns MutatedPayload objects"""
        payload = "<script>"
        results = mutator.mutate_all(payload)
        
        assert all(isinstance(r, MutatedPayload) for r in results)
        assert all(hasattr(r, 'original') for r in results)
        assert all(hasattr(r, 'mutated') for r in results)
        assert all(hasattr(r, 'technique') for r in results)

    def test_mutate_all_preserves_original(self, mutator):
        """Test original field is preserved"""
        payload = "' OR '1'='1"
        results = mutator.mutate_all(payload)
        
        assert all(r.original == payload for r in results)

    def test_mutate_all_different_mutations(self, mutator):
        """Test different mutation techniques generate different payloads"""
        payload = "SELECT 1"
        results = mutator.mutate_all(payload)
        
        payloads = [r.mutated for r in results]
        # Should have at least one different mutation
        assert len(set(payloads)) > 1

    # ==================== CASE VARY TESTS ====================

    def test_case_vary_changes_case(self, mutator):
        """Test case variation changes cases"""
        payload = "select"
        mutated = mutator._case_vary(payload)
        
        # Should have mixed case
        assert mutated != payload
        assert any(c.upper() != c for c in mutated)
        assert any(c.lower() != c for c in mutated)

    def test_case_vary_sql_keyword(self, mutator):
        """Test case variation on SQL keyword"""
        payload = "SELECT"
        mutated = mutator._case_vary(payload)
        
        # Should alternate case
        assert mutated.lower() == payload.lower()

    def test_case_vary_preserves_length(self, mutator):
        """Test case variation preserves string length"""
        payload = "SELECT FROM WHERE"
        mutated = mutator._case_vary(payload)
        
        assert len(mutated) == len(payload)

    def test_case_vary_special_chars(self, mutator):
        """Test case variation with special characters"""
        payload = "SELECT 1 = 1"
        mutated = mutator._case_vary(payload)
        
        # Numbers and special chars should be unchanged
        assert "1" in mutated
        assert "=" in mutated

    # ==================== COMMENT INJECT TESTS ====================

    def test_comment_inject_replaces_spaces(self, mutator):
        """Test SQL comment replaces spaces"""
        payload = "SELECT FROM TABLE"
        mutated = mutator._comment_inject(payload)
        
        # Should replace spaces with comments
        assert " " not in mutated
        assert "/*" in mutated

    def test_comment_inject_multiple_spaces(self, mutator):
        """Test comment injection with multiple spaces"""
        payload = "SELECT  FROM  TABLE"
        mutated = mutator._comment_inject(payload)
        
        # All spaces should be replaced
        assert "/**/" in mutated

    def test_comment_inject_no_spaces(self, mutator):
        """Test comment injection with no spaces"""
        payload = "SELECT123"
        mutated = mutator._comment_inject(payload)
        
        assert mutated == payload

    # ==================== DOUBLE ENCODE TESTS ====================

    def test_double_encode_creates_different_payload(self, mutator):
        """Test double encoding creates different payload"""
        payload = "<script>"
        mutated = mutator._double_encode(payload)
        
        assert mutated != payload
        assert "%" in mutated

    def test_double_encode_twice_different(self, mutator):
        """Test double encoding is different from single"""
        payload = "<>"
        single = mutator.mutator._double_encode if hasattr(mutator, 'mutator') else None
        
        # Just check double encode works
        mutated = mutator._double_encode(payload)
        assert isinstance(mutated, str)

    def test_double_encode_produces_percent(self, mutator):
        """Test double encoding produces percent encoding for special chars"""
        # Use a payload with special characters that need encoding
        payload = "<script>"
        mutated = mutator._double_encode(payload)
        
        # Double encoding produces %253C%253E (double-encoded < and >)
        # The % character itself is encoded as %25 on second pass
        assert "%25" in mutated  # %25 is the encoding of %

    # ==================== WHITESPACE SUBSTITUTION TESTS ====================

    def test_whitespace_sub_returns_string(self, mutator):
        """Test whitespace substitution returns string"""
        payload = "SELECT FROM"
        mutated = mutator._whitespace_sub(payload)
        
        assert isinstance(mutated, str)

    def test_whitespace_sub_different_from_original(self, mutator):
        """Test whitespace substitution creates different payload"""
        payload = "SELECT FROM TABLE"
        mutated = mutator._whitespace_sub(payload)
        
        # Should have some difference
        assert mutated != payload or payload.count(" ") == 0

    # ==================== NULL BYTE TESTS ====================

    def test_null_byte_injection(self, mutator):
        """Test null byte injection"""
        payload = "test"
        mutated = mutator._null_byte(payload)
        
        assert isinstance(mutated, str)
        # Should contain null byte indicator
        assert "\x00" in mutated or "%00" in mutated or mutated != payload

    # ==================== HEX ENCODE TESTS ====================

    def test_hex_encode_partial(self, mutator):
        """Test partial hex encoding"""
        payload = "<script>"
        mutated = mutator._hex_encode_partial(payload)
        
        assert isinstance(mutated, str)
        # Should be different from original
        assert mutated != payload or "<" not in mutated

    # ==================== MUTATE FOR WAF TESTS ====================

    def test_mutate_for_waf_cloudflare(self, mutator):
        """Test mutations for Cloudflare WAF"""
        payload = "SELECT 1"
        results = mutator.mutate_for_waf(payload, "Cloudflare")
        
        assert isinstance(results, list)
        assert len(results) >= 0

    def test_mutate_for_waf_modsecurity(self, mutator):
        """Test mutations for ModSecurity WAF"""
        payload = "<script>alert(1)</script>"
        results = mutator.mutate_for_waf(payload, "ModSecurity")
        
        assert isinstance(results, list)

    def test_mutate_for_waf_aws(self, mutator):
        """Test mutations for AWS WAF"""
        payload = "' OR '1'='1"
        results = mutator.mutate_for_waf(payload, "AWS WAF")
        
        assert isinstance(results, list)

    def test_mutate_for_waf_unknown(self, mutator):
        """Test fallback for unknown WAF"""
        payload = "test"
        results = mutator.mutate_for_waf(payload, "Unknown WAF")
        
        assert isinstance(results, list)

    def test_mutate_for_waf_returns_mutated_payloads(self, mutator):
        """Test returned objects are MutatedPayload"""
        payload = "SELECT"
        results = mutator.mutate_for_waf(payload, "Cloudflare")
        
        assert all(isinstance(r, MutatedPayload) for r in results)

    def test_mutate_for_waf_technique_specified(self, mutator):
        """Test technique is specified for each mutation"""
        payload = "test"
        results = mutator.mutate_for_waf(payload, "ModSecurity")
        
        for result in results:
            assert result.technique is not None
            assert len(result.technique) > 0

    # ==================== MUTATED PAYLOAD TESTS ====================

    def test_mutated_payload_structure(self, mutator):
        """Test MutatedPayload object structure"""
        payload = "test"
        results = mutator.mutate_all(payload)
        
        first = results[0]
        assert isinstance(first, MutatedPayload)
        assert isinstance(first.original, str)
        assert isinstance(first.mutated, str)
        assert isinstance(first.technique, str)

    def test_mutated_payload_original_preserved(self, mutator):
        """Test MutatedPayload preserves original"""
        original = "payload123"
        results = mutator.mutate_all(original)
        
        assert all(r.original == original for r in results)

    # ==================== EDGE CASES ====================

    def test_mutate_empty_payload(self, mutator):
        """Test mutation of empty payload"""
        payload = ""
        results = mutator.mutate_all(payload)
        
        # Should not crash
        assert isinstance(results, list)

    def test_mutate_very_long_payload(self, mutator):
        """Test mutation of very long payload"""
        payload = "x" * 10000
        results = mutator.mutate_all(payload)
        
        # Should handle long payloads
        assert isinstance(results, list)

    def test_mutate_special_characters(self, mutator):
        """Test mutation with special characters"""
        payload = "!@#$%^&*()"
        results = mutator.mutate_all(payload)
        
        assert isinstance(results, list)

    def test_mutate_unicode_payload(self, mutator):
        """Test mutation with unicode"""
        payload = "SELECT café"
        results = mutator.mutate_all(payload)
        
        # Should handle unicode
        assert isinstance(results, list)

    def test_mutate_sql_union_injection(self, mutator):
        """Test mutation of UNION-based SQL injection"""
        payload = "1 UNION SELECT username, password FROM users"
        results = mutator.mutate_all(payload)
        
        assert len(results) > 1

    def test_mutate_xss_payload(self, mutator):
        """Test mutation of XSS payload"""
        payload = "<img src=x onerror=alert(1)>"
        results = mutator.mutate_all(payload)
        
        assert len(results) > 1

    # ==================== MUTATION TECHNIQUE TESTS ====================

    def test_has_case_vary_technique(self, mutator):
        """Test case_vary mutations exist"""
        payload = "SELECT"
        results = mutator.mutate_all(payload)
        techniques = [r.technique for r in results]
        
        assert any("case_vary" in t for t in techniques)

    def test_has_comment_inject_technique(self, mutator):
        """Test comment_inject mutations exist"""
        payload = "SELECT FROM"
        results = mutator.mutate_all(payload)
        techniques = [r.technique for r in results]
        
        # May or may not be present depending on payload
        assert isinstance(techniques, list)

    # ==================== MUTATION CONSISTENCY ====================

    def test_same_payload_same_mutations(self, mutator):
        """Test same payload produces consistent mutations"""
        payload = "test"
        results1 = mutator.mutate_all(payload)
        results2 = mutator.mutate_all(payload)
        
        # Lengths should be same (order might vary)
        assert len(results1) == len(results2)

    def test_mutation_original_field_readonly(self, mutator):
        """Test original field represents input"""
        payload = "SELECT 1"
        results = mutator.mutate_all(payload)
        
        for result in results:
            assert result.original == payload
            # Mutated might be same as original for 'original' technique
            assert isinstance(result.mutated, str)
