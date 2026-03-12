"""
graphql.py - GraphQL Security Scanner
Phát hiện: introspection enabled, injection, info disclosure qua errors.
"""
import httpx
import json
from rich.console import Console

console = Console()

# Common GraphQL endpoints
GRAPHQL_ENDPOINTS = [
    "/graphql", "/api/graphql", "/v1/graphql",
    "/query", "/gql", "/graph",
    "/graphql/v1", "/api/v1/graphql",
]

INTROSPECTION_QUERY = """
{
  __schema {
    types { name kind }
    queryType { name }
    mutationType { name }
  }
}
"""

# Injection payloads
INJECTION_PAYLOADS = [
    '{ user(id: "1 OR 1=1") { id name email } }',
    '{ users { id name email password } }',
    '{ __typename }',
]

# Error indicators
GRAPHQL_ERROR_PATTERNS = [
    '"errors"', "graphql", "syntax error", "cannot query field",
    "did you mean", "unknown type", "parse error",
    '"data":', '"__schema"',
]


class GraphQLScanner:
    def __init__(self, timeout: int = 10, config: dict | None = None):
        self.timeout = timeout
        self.config  = config or {}

    async def scan(self, base_url: str, client: httpx.AsyncClient) -> list[dict]:
        results  = []
        base     = base_url.rstrip("/")
        found_ep = None

        # Step 1: Tìm GraphQL endpoint
        for path in GRAPHQL_ENDPOINTS:
            url = base + path
            try:
                resp = await client.post(
                    url,
                    json={"query": "{ __typename }"},
                    headers={"Content-Type": "application/json"},
                )
                body = resp.text.lower()
                if any(p in body for p in GRAPHQL_ERROR_PATTERNS):
                    found_ep = url
                    console.print(f"  [cyan]→ GraphQL endpoint found:[/cyan] {url}")
                    break
            except Exception:
                pass

        if not found_ep:
            return results

        # Step 2: Test Introspection
        introspection_result = await self._test_introspection(found_ep, client)
        if introspection_result:
            results.append(introspection_result)

        # Step 3: Test Information Disclosure via Errors
        error_results = await self._test_error_disclosure(found_ep, client)
        results.extend(error_results)

        # Step 4: Test basic injection
        injection_results = await self._test_injection(found_ep, client)
        results.extend(injection_results)

        return results

    async def _test_introspection(
        self, endpoint: str, client: httpx.AsyncClient
    ) -> dict | None:
        try:
            resp = await client.post(
                endpoint,
                json={"query": INTROSPECTION_QUERY},
                headers={"Content-Type": "application/json"},
            )
            data = resp.json()

            if "__schema" in str(data) and "types" in str(data):
                # Parse schema để đếm types
                types_count = 0
                try:
                    types_count = len(data["data"]["__schema"]["types"])
                except Exception:
                    pass

                console.print(
                    f"  [red bold][GRAPHQL INTROSPECTION][/red bold] {endpoint} | "
                    f"{types_count} types exposed"
                )
                return {
                    "type":        "GraphQL Introspection Enabled",
                    "severity":    "MEDIUM",
                    "url":         endpoint,
                    "parameter":   "POST body",
                    "payload":     "__schema introspection query",
                    "evidence": (
                        f"GraphQL introspection is enabled — {types_count} types exposed. "
                        "Attackers can map entire API schema."
                    ),
                    "confidence":  0.97,
                    "cvss_score":  5.3,
                    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                    "cwe":         "CWE-200",
                }
        except Exception:
            pass
        return None

    async def _test_error_disclosure(
        self, endpoint: str, client: httpx.AsyncClient
    ) -> list[dict]:
        results = []
        # Gửi malformed query để trigger error
        malformed_queries = [
            '{ invalidField123 }',
            '{ user(id: "INVALID") }',
            '{ }',
        ]
        for q in malformed_queries:
            try:
                resp = await client.post(
                    endpoint,
                    json={"query": q},
                    headers={"Content-Type": "application/json"},
                )
                body = resp.text
                data = resp.json()

                errors = data.get("errors", [])
                if errors:
                    error_msg = str(errors[0].get("message", ""))
                    # Kiểm tra error có leak stack trace/internal info không
                    sensitive_patterns = [
                        "exception", "stack", "at line", "filepath",
                        "internal", "database", "sql", "syntax error",
                        "resolver", "Cannot read property",
                    ]
                    if any(p in error_msg.lower() for p in sensitive_patterns):
                        results.append({
                            "type":        "GraphQL Error Information Disclosure",
                            "severity":    "LOW",
                            "url":         endpoint,
                            "parameter":   "query",
                            "payload":     q,
                            "evidence": (
                                f"GraphQL error leaks internal info: "
                                f"'{error_msg[:150]}'"
                            ),
                            "confidence":  0.80,
                            "cvss_score":  4.3,
                            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                            "cwe":         "CWE-209",
                        })
                        break
            except Exception:
                pass
        return results

    async def _test_injection(
        self, endpoint: str, client: httpx.AsyncClient
    ) -> list[dict]:
        results = []
        for payload in INJECTION_PAYLOADS:
            try:
                resp = await client.post(
                    endpoint,
                    json={"query": payload},
                    headers={"Content-Type": "application/json"},
                )
                data = resp.json()
                # Nếu có "data" trả về = query thực thi được (không bị block)
                if "data" in data and data["data"] and data["data"] != {"__typename": "Query"}:
                    console.print(
                        f"  [yellow bold][GRAPHQL DATA LEAK][/yellow bold] "
                        f"{endpoint} | query returned data"
                    )
                    results.append({
                        "type":        "GraphQL Unauthorized Data Access",
                        "severity":    "HIGH",
                        "url":         endpoint,
                        "parameter":   "query",
                        "payload":     payload[:80],
                        "evidence":    "GraphQL query returned data without authentication",
                        "confidence":  0.75,
                        "cvss_score":  7.5,
                        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                        "cwe":         "CWE-284",
                    })
                    break
            except Exception:
                pass
        return results