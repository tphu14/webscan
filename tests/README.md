# WebVulnScanner Unit Tests

Complete test suite for WebVulnScanner v3.0 vulnerability scanner.

## Test Structure

```
tests/
├── conftest.py                           # Shared fixtures
├── pytest.ini                            # Pytest configuration
├── unit/
│   ├── test_crawler.py                   # Crawler tests (TIER 1)
│   ├── test_modules/
│   │   ├── test_sqli.py                  # SQL Injection tests (TIER 1)
│   │   ├── test_xss.py                   # XSS tests (TIER 1)
│   │   ├── test_headers.py               # Security Headers tests (TIER 2)
│   │   ├── test_open_redirect.py         # Open Redirect tests (TIER 2)
│   │   ├── test_cors.py                  # CORS tests (TIER 2)
│   │   ├── test_csrf.py                  # CSRF tests (TIER 2)
│   │   ├── test_idor.py                  # IDOR tests (TIER 2)
│   │   └── test_jwt_analyzer.py          # JWT tests (TIER 2)
│   ├── test_detection/
│   │   ├── test_cvss_calculator.py       # CVSS Calculator tests (TIER 1)
│   │   ├── test_waf_detector.py          # WAF Detector tests (TIER 1)
│   │   ├── test_response_differ.py       # Response Differ tests
│   │   └── test_payload_mutator.py       # Payload Mutator tests
│   └── test_utils/
│       └── test_config_loader.py         # Config Loader tests
└── integration/
    └── test_scanner_integration.py       # Scanner workflow tests
```

## Running Tests

### Install Dependencies

```bash
pip install -r requirements.txt
```

### Run All Tests

```bash
pytest tests/ -v
```

### Run Specific Test File

```bash
pytest tests/unit/test_modules/test_sqli.py -v
```

### Run Specific Test Class

```bash
pytest tests/unit/test_modules/test_sqli.py::TestSQLiScanner -v
```

### Run Specific Test

```bash
pytest tests/unit/test_modules/test_sqli.py::TestSQLiScanner::test_scanner_initialization -v
```

### Generate Coverage Report

```bash
pytest tests/ --cov=modules --cov=core --cov=detection --cov=utils --cov-report=html
```

### Run Only Unit Tests

```bash
pytest tests/unit/ -v
```

### Run Only Integration Tests

```bash
pytest tests/integration/ -v
```

### Run Tests with Markers

```bash
# Run only async tests
pytest tests/ -m asyncio -v

# Run only unit tests
pytest tests/ -m unit -v
```

### Run Tests with Output

```bash
# Show print statements
pytest tests/ -v -s

# Show local variables on failure
pytest tests/ -v -l
```

## Test Coverage

| Component          | Coverage | Status |
|------------------|----------|--------|
| modules/*.py      | ~80%     | ✅ Comprehensive |
| core/crawler.py   | ~85%     | ✅ Comprehensive |
| detection/*.py    | ~75%     | ✅ Good |
| utils/*.py        | ~70%     | ✅ Good |
| scanner*.py       | ~60%     | ⚠️ Basic |

## Test Statistics

- **Total Tests**: 300+
- **Unit Tests**: 270+
- **Integration Tests**: 15+
- **Async Tests**: 80+

## Tier Breakdown

### TIER 1 (Critical - 100% Coverage)
- `crawler.py` - 45 tests
- `cvss_calculator.py` - 55 tests
- `waf_detector.py` - 40 tests
- `sqli.py` - 40 tests
- `xss.py` - 45 tests

### TIER 2 (Important - 75% Coverage)
- `response_differ.py` - 35 tests
- `payload_mutator.py` - 30 tests
- `headers.py` - 20 tests
- `open_redirect.py` - 5 tests
- `cors.py` - 8 tests
- `csrf.py` - 8 tests
- `idor.py` - 8 tests
- `jwt_analyzer.py` - 8 tests

## Fixtures Available

### Config Fixtures
- `default_config` - Default scanner configuration
- `crawler_config` - Crawler-specific configuration

### HTML Fixtures
- `sample_html_simple` - Basic HTML structure
- `sample_html_forms` - HTML with forms
- `sample_html_with_links` - HTML with various link types

### Response Fixtures
- `response_sqli_error` - SQL error response
- `response_xss_reflected` - Reflected XSS response
- `response_normal` - Normal response
- `response_with_headers` - Response with security headers
- `response_missing_headers` - Response with missing headers
- `response_waf_blocked` - WAF blocking response

### Payload Fixtures
- `sqli_payloads` - SQL injection payloads
- `xss_payloads` - XSS payloads
- `lfi_payloads` - LFI payloads
- `ssrf_payloads` - SSRF payloads

### Mock Fixtures
- `mock_httpx_client` - Mocked httpx.AsyncClient
- `mock_client` - Generic mock client
- `mock_vulnerability` - Sample vulnerability object
- `mock_crawler_result` - Sample crawler result

## Testing Best Practices

1. **Always use fixtures** - Use pytest fixtures for setup/teardown
2. **Parameterize tests** - Use `@pytest.mark.parametrize` for multiple scenarios
3. **Mock external calls** - Use `AsyncMock` for HTTP calls
4. **Test edge cases** - Include tests for empty inputs, long inputs, etc.
5. **Async tests** - Mark async tests with `@pytest.mark.asyncio`
6. **Descriptive names** - Test names should explain what is being tested

## Adding New Tests

1. Create test file in appropriate directory
2. Import required fixtures from `conftest.py`
3. Follow naming convention: `test_<module_name>.py`
4. Use descriptive test names: `test_<feature>_<scenario>`
5. Add docstrings explaining test purpose

Example:
```python
@pytest.mark.asyncio
async def test_sqli_detection_with_error(self, scanner, mock_client):
    """Test SQL injection detection with database error"""
    mock_response = AsyncMock()
    mock_response.text = "SQL syntax error"
    mock_client.get = AsyncMock(return_value=mock_response)
    
    results = await scanner.scan_url("http://example.com/page?id=1", mock_client)
    
    assert len(results) > 0
    assert results[0]["type"] == "SQL Injection"
```

## CI/CD Integration

Tests can be integrated into CI/CD pipeline:

```yaml
# .github/workflows/tests.yml
name: Tests

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - uses: actions/setup-python@v2
        with:
          python-version: "3.9"
      - run: pip install -r requirements.txt
      - run: pytest tests/ --cov=. --cov-report=xml
      - uses: codecov/codecov-action@v2
```

## Troubleshooting

### Issue: "ModuleNotFoundError: No module named 'modules'"
**Solution**: Run pytest from workspace root directory

### Issue: "INTERNALERROR> PytestUnraisableExceptionWarning"
**Solution**: Add `asyncio_mode = auto` to pytest.ini

### Issue: Tests timeout
**Solution**: Increase timeout or mock slow operations

## Contact

For issues or contributions, please refer to the main project repository.
