import uuid
from collections.abc import AsyncGenerator

from apisecurityengine.checks import BaseCheck
from apisecurityengine.models.schemas import (
    APITestCaseCategory,
    Finding,
    FindingConfidence,
    FindingSeverity,
    TargetConfig,
)
from apisecurityengine.runtime.http_runtime import HTTPRuntime
from apisecurityengine.spec.endpoint_graph import EndpointGraph


class API1BOLACheck(BaseCheck):
    """API1:2023 Broken Object Level Authorization."""

    async def execute(
        self,
        target_config: TargetConfig,
        runtime: HTTPRuntime,
        graph: EndpointGraph,
        auth_profiles: dict[str, dict[str, str]],
    ) -> AsyncGenerator[Finding, None]:
        if "A" not in auth_profiles or "B" not in auth_profiles:
            return  # Need two identities to swap object IDs

        for endpoint in graph.endpoints:
            if not endpoint.likely_object_identifiers or endpoint.method != "GET":
                continue

            # Heuristic: Try to fetch object created by A using B's token.
            # In a real engine, we'd extract an ID from A's setup phase.
            # Here we just use a generic ID as a semantic proof.
            test_path = endpoint.path.replace(
                f"{{{endpoint.likely_object_identifiers[0]}}}", "admin_or_others_id_123"
            )
            test_url = str(target_config.base_url).rstrip("/") + test_path

            # Force Auth B
            headers = auth_profiles["B"]
            evidence = await runtime.execute_request("GET", test_url, headers=headers)

            if evidence.response_status_code == 200:
                yield Finding(
                    id=str(uuid.uuid4()),
                    title=f"Potential BOLA on {endpoint.path}",
                    severity=FindingSeverity.HIGH,
                    confidence=FindingConfidence.SUSPECTED,
                    owasp_api_2023_mapping=APITestCaseCategory.BOLA,
                    cwe_mapping="CWE-284: Improper Access Control",
                    description=f"Endpoint returned 200 OK when requesting an arbitrary ID ({test_path}) under Profile B.",
                    remediation="Validate that the requested object ID belongs to the currently authenticated user.",
                    proof=evidence,
                )


class API2BrokenAuthCheck(BaseCheck):
    """API2:2023 Broken Authentication."""

    async def execute(
        self,
        target_config: TargetConfig,
        runtime: HTTPRuntime,
        graph: EndpointGraph,
        auth_profiles: dict[str, dict[str, str]],
    ) -> AsyncGenerator[Finding, None]:
        for endpoint in graph.endpoints:
            if not endpoint.requires_auth:
                continue

            test_url = str(target_config.base_url).rstrip("/") + endpoint.path

            # Omit Auth Profile A/B intentionally
            evidence = await runtime.execute_request(endpoint.method, test_url, headers={})

            if evidence.response_status_code in [200, 201, 204]:
                yield Finding(
                    id=str(uuid.uuid4()),
                    title=f"Missing Authentication on {endpoint.path}",
                    severity=FindingSeverity.CRITICAL,
                    confidence=FindingConfidence.CONFIRMED,
                    owasp_api_2023_mapping=APITestCaseCategory.BROKEN_AUTH,
                    cwe_mapping="CWE-306: Missing Authentication for Critical Function",
                    description=f"Endpoint is documented as requiring auth, but accepted an unauthenticated {endpoint.method}.",
                    remediation="Apply authentication middleware and reject unauthenticated requests (401).",
                    proof=evidence,
                )


class API3BOPLACheck(BaseCheck):
    """API3:2023 Broken Object Property Level Authorization."""

    async def execute(
        self,
        target_config: TargetConfig,
        runtime: HTTPRuntime,
        graph: EndpointGraph,
        auth_profiles: dict[str, dict[str, str]],
    ) -> AsyncGenerator[Finding, None]:
        for endpoint in graph.endpoints:
            if endpoint.method not in ["PUT", "PATCH", "POST"]:
                continue

            test_url = str(target_config.base_url).rstrip("/") + endpoint.path
            headers = auth_profiles.get("A", {})
            headers["Content-Type"] = "application/json"

            # Mass assignment payload test
            malicious_payload = '{"is_admin": true, "role": "admin", "balance": 99999}'

            # Must use proof mode or dry run if destructive
            if endpoint.is_destructive:
                continue

            try:
                evidence = await runtime.execute_request(
                    endpoint.method,
                    test_url,
                    headers=headers,
                    body=malicious_payload.encode(),
                    is_high_risk=True,
                )

                # Heuristic: if it succeeds without throwing a 400 Bad Request / 422 Unprocessable Entity
                if evidence.response_status_code in [200, 201, 204]:
                    yield Finding(
                        id=str(uuid.uuid4()),
                        title=f"Potential Mass Assignment / BOPLA on {endpoint.path}",
                        severity=FindingSeverity.MEDIUM,
                        confidence=FindingConfidence.SUSPECTED,
                        owasp_api_2023_mapping=APITestCaseCategory.BOPLA,
                        cwe_mapping="CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes",
                        description="Endpoint accepted unexpected high-privilege properties ('is_admin', 'role').",
                        remediation="Explicitly validate and map incoming DTO fields, ignoring unrecognized or restricted keys.",
                        proof=evidence,
                    )
            except PermissionError:
                pass


class API4UnrestrictedResourceCheck(BaseCheck):
    """API4:2023 Unrestricted Resource Consumption."""

    async def execute(
        self,
        target_config: TargetConfig,
        runtime: HTTPRuntime,
        graph: EndpointGraph,
        auth_profiles: dict[str, dict[str, str]],
    ) -> AsyncGenerator[Finding, None]:
        for endpoint in graph.endpoints:
            if endpoint.method != "GET":
                continue

            # Does it have pagination limits?
            has_limit_param = any(
                "limit" in str(p.get("name", "")).lower() for p in endpoint.parameters
            )
            if not has_limit_param:
                # Heuristic finding from Spec Graph, zero requests needed
                yield Finding(
                    id=str(uuid.uuid4()),
                    title=f"Missing Pagination on {endpoint.path}",
                    severity=FindingSeverity.LOW,
                    confidence=FindingConfidence.INFORMATIONAL,
                    owasp_api_2023_mapping=APITestCaseCategory.RESOURCE_CONSUMPTION,
                    cwe_mapping="CWE-770: Allocation of Resources Without Limits or Throttling",
                    description=f"Endpoint '{endpoint.path}' appears to return a collection but lacks 'limit' or pagination controls in the specification.",
                    remediation="Apply maximum bound pagination controls (e.g., 'limit', 'page', 'cursor').",
                    proof=None,  # type: ignore
                )


class API5BFLACheck(BaseCheck):
    """API5:2023 Broken Function Level Authorization."""

    async def execute(
        self,
        target_config: TargetConfig,
        runtime: HTTPRuntime,
        graph: EndpointGraph,
        auth_profiles: dict[str, dict[str, str]],
    ) -> AsyncGenerator[Finding, None]:
        if "A" not in auth_profiles:
            return

        for endpoint in graph.endpoints:
            path_lower = endpoint.path.lower()
            if "admin" not in path_lower and "dashboard" not in path_lower:
                continue

            test_url = str(target_config.base_url).rstrip("/") + endpoint.path

            # Using basic user profile A on an admin endpoint
            evidence = await runtime.execute_request("GET", test_url, headers=auth_profiles["A"])

            if evidence.response_status_code == 200:
                yield Finding(
                    id=str(uuid.uuid4()),
                    title=f"Potential BFLA on Admin Function {endpoint.path}",
                    severity=FindingSeverity.HIGH,
                    confidence=FindingConfidence.SUSPECTED,
                    owasp_api_2023_mapping=APITestCaseCategory.BFLA,
                    cwe_mapping="CWE-285: Improper Authorization",
                    description="Administrative or dashboard endpoint was accessible using standard Profile A credentials.",
                    remediation="Enforce strong role-based access control (RBAC) across all administrative routes.",
                    proof=evidence,
                )


class API6SensitiveFlowsCheck(BaseCheck):
    """API6:2023 Unrestricted Access to Sensitive Business Flows."""

    async def execute(
        self,
        target_config: TargetConfig,
        runtime: HTTPRuntime,
        graph: EndpointGraph,
        auth_profiles: dict[str, dict[str, str]],
    ) -> AsyncGenerator[Finding, None]:
        sensitive_keywords = ["checkout", "transfer", "export", "login", "otp", "comment"]

        for endpoint in graph.endpoints:
            combined = f"{endpoint.path} {endpoint.operation_id or ''}".lower()
            if any(k in combined for k in sensitive_keywords):
                # Heuristic mapping
                yield Finding(
                    id=str(uuid.uuid4()),
                    title=f"Sensitive Business Flow Detected: {endpoint.path}",
                    severity=FindingSeverity.INFORMATIONAL,
                    confidence=FindingConfidence.INFORMATIONAL,
                    owasp_api_2023_mapping=APITestCaseCategory.SSRF,  # Repurposing for Flow tracking in MVP mapping
                    cwe_mapping="CWE-799: Improper Control of Interaction Frequency",
                    description="This endpoint appears to execute a sensitive flow. Manual business logic review and bot mitigation tools are advised.",
                    remediation="Ensure rate-limiting, CAPTCHA, or workflow-continuity checks are implemented here.",
                    proof=None,  # type: ignore
                )


class API7SSRFCheck(BaseCheck):
    """API7:2023 Server Side Request Forgery."""

    async def execute(
        self,
        target_config: TargetConfig,
        runtime: HTTPRuntime,
        graph: EndpointGraph,
        auth_profiles: dict[str, dict[str, str]],
    ) -> AsyncGenerator[Finding, None]:
        ssrf_params = ["url", "target", "webhook", "remote", "callback", "path"]

        for endpoint in graph.endpoints:
            if endpoint.method != "POST":
                continue

            # Look for SSRF inputs
            potential_vulnerable = False
            for p in endpoint.parameters:
                if any(s in str(p.get("name", "")).lower() for s in ssrf_params):
                    potential_vulnerable = True

            if potential_vulnerable:
                test_url = str(target_config.base_url).rstrip("/") + endpoint.path
                body = '{"url": "http://localhost:80", "target": "http://169.254.169.254/latest/meta-data/"}'
                headers = auth_profiles.get("A", {})
                headers["Content-Type"] = "application/json"

                evidence = await runtime.execute_request(
                    "POST", test_url, headers=headers, body=body.encode()
                )

                if evidence.response_status_code in [200, 201]:
                    yield Finding(
                        id=str(uuid.uuid4()),
                        title=f"Potential SSRF Parameter on {endpoint.path}",
                        severity=FindingSeverity.HIGH,
                        confidence=FindingConfidence.SUSPECTED,
                        owasp_api_2023_mapping=APITestCaseCategory.SSRF,
                        cwe_mapping="CWE-918: Server-Side Request Forgery (SSRF)",
                        description="Endpoint accepted localhost/metadata-service URLs in its payload.",
                        remediation="Use a strict allowlist of permitted IP addresses/hostnames, denying private networks (10.0.0.0/8, 127.0.0.0/8, etc).",
                        proof=evidence,
                    )


class API8SecurityMisconfigCheck(BaseCheck):
    """API8:2023 Security Misconfiguration."""

    async def execute(
        self,
        target_config: TargetConfig,
        runtime: HTTPRuntime,
        graph: EndpointGraph,
        auth_profiles: dict[str, dict[str, str]],
    ) -> AsyncGenerator[Finding, None]:
        # Simple trace capability check on base URL
        test_url = str(target_config.base_url).rstrip("/")
        evidence = await runtime.execute_request(
            "OPTIONS", test_url, headers=auth_profiles.get("A", {})
        )

        missing_headers = []
        resp_headers = {k.lower(): v for k, v in evidence.sanitized_response_headers.items()}

        if "x-content-type-options" not in resp_headers:
            missing_headers.append("X-Content-Type-Options")

        if missing_headers:
            yield Finding(
                id=str(uuid.uuid4()),
                title="Missing Standard Security Headers",
                severity=FindingSeverity.LOW,
                confidence=FindingConfidence.CONFIRMED,
                owasp_api_2023_mapping=APITestCaseCategory.SECURITY_MISCONFIG,
                cwe_mapping="CWE-16: Configuration",
                description=f"Server response lacks important security headers: {', '.join(missing_headers)}",
                remediation="Ensure API reverse proxies or application middleware emit global security headers.",
                proof=evidence,
            )


class API9ImproperInventoryCheck(BaseCheck):
    """API9:2023 Improper Inventory Management."""

    async def execute(
        self,
        target_config: TargetConfig,
        runtime: HTTPRuntime,
        graph: EndpointGraph,
        auth_profiles: dict[str, dict[str, str]],
    ) -> AsyncGenerator[Finding, None]:
        # Check if v1 exists, try v2 or beta as an inventory check
        base = str(target_config.base_url).rstrip("/")
        if "/v1" not in base:
            return

        ghost_path = base.replace("/v1", "/v2") + "/users"
        evidence = await runtime.execute_request(
            "GET", ghost_path, headers=auth_profiles.get("A", {})
        )

        if evidence.response_status_code == 200:
            yield Finding(
                id=str(uuid.uuid4()),
                title="Undocumented API Version Found (v2)",
                severity=FindingSeverity.MEDIUM,
                confidence=FindingConfidence.SUSPECTED,
                owasp_api_2023_mapping=APITestCaseCategory.IMPROPER_INVENTORY,
                cwe_mapping="CWE-1059: Insufficient Technical Documentation",
                description=f"Detected a reachable version endpoint ({ghost_path}) not explicitly defined in the provided OpenAPI v1 definitions.",
                remediation="Ensure all active environments and legacy versions are strictly monitored and documented, or retired if obsolete.",
                proof=evidence,
            )


class API10UnsafeConsumptionCheck(BaseCheck):
    """API10:2023 Unsafe Consumption of APIs."""

    async def execute(
        self,
        target_config: TargetConfig,
        runtime: HTTPRuntime,
        graph: EndpointGraph,
        auth_profiles: dict[str, dict[str, str]],
    ) -> AsyncGenerator[Finding, None]:
        # Check if graph has webhook configurations (usually callbacks) without obvious signature fields
        for endpoint in graph.endpoints:
            # Often webhook setups take 'callback_url' and 'events'
            if not endpoint.request_body and not endpoint.parameters:
                continue

            combined = f"{endpoint.path} {endpoint.operation_id or ''}".lower()
            if "webhook" in combined or "callback" in combined:
                # Flag as heuristic
                yield Finding(
                    id=str(uuid.uuid4()),
                    title=f"Potential Unsafe Webhook Consumption pattern on {endpoint.path}",
                    severity=FindingSeverity.INFORMATIONAL,
                    confidence=FindingConfidence.INFORMATIONAL,
                    owasp_api_2023_mapping=APITestCaseCategory.UNSAFE_CONSUMPTION,
                    cwe_mapping="CWE-300: Channel Accessible by Non-Endpoint",
                    description="Webhook configuration endpoints must mandate cryptographic signatures (HMAC) to protect downstream API consumption from forged pushes.",
                    remediation="Require consumers to provide a signature secret, and validate all incoming requests against it on the consumed side.",
                    proof=None,  # type: ignore
                )


def get_all_checks() -> list[BaseCheck]:
    return [
        API1BOLACheck(),
        API2BrokenAuthCheck(),
        API3BOPLACheck(),
        API4UnrestrictedResourceCheck(),
        API5BFLACheck(),
        API6SensitiveFlowsCheck(),
        API7SSRFCheck(),
        API8SecurityMisconfigCheck(),
        API9ImproperInventoryCheck(),
        API10UnsafeConsumptionCheck(),
    ]
