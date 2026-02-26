import json
from datetime import datetime
from pathlib import Path

from pydantic import HttpUrl, TypeAdapter

from apisecurityengine.models.schemas import (
    APITestCaseCategory,
    Evidence,
    Finding,
    FindingConfidence,
    FindingSeverity,
    RedactionRules,
    RunSummary,
    RunSummaryStats,
    SpecArtifact,
    TargetConfig,
)


def test_target_config() -> None:
    ta = TypeAdapter(HttpUrl)
    config = TargetConfig(base_url=ta.validate_python("https://api.example.com"))
    assert getattr(config.base_url, "scheme", None) in [
        "http",
        "https",
    ] or str(config.base_url).startswith("https")
    assert config.max_requests_per_second == 10
    config_dict = config.model_dump()
    assert str(config_dict["base_url"]) == "https://api.example.com/"


def test_redaction_rules() -> None:
    raw_header = "Authorization: Bearer my-super-secret-token"
    redacted = RedactionRules.redact(raw_header)
    assert redacted == "Authorization: [REDACTED]"

    raw_cookie = "Set-Cookie: session_id=1234abcd; Path=/;"
    redacted = RedactionRules.redact(raw_cookie)
    assert redacted == "[REDACTED] Path=/;"


def test_evidence_model() -> None:
    evt = Evidence(
        request_method="POST",
        request_url="https://api.example.com/login",
        sanitized_request_body=RedactionRules.redact("password=secretpassword"),
        response_status_code=401,
    )
    assert evt.sanitized_request_body == "[REDACTED]"
    assert evt.request_hash is not None


def test_finding_and_summary_json() -> None:
    evidence = Evidence(
        request_method="GET",
        request_url="https://api.example.com/users/999",
        sanitized_request_headers={"Authorization": "[REDACTED]"},
        response_status_code=200,
        sanitized_response_body='{"user_id": 999, "role": "admin"}',
    )

    finding = Finding(
        id="fnd-1234",
        title="BOLA on /users/{id}",
        severity=FindingSeverity.HIGH,
        confidence=FindingConfidence.CONFIRMED,
        owasp_api_2023_mapping=APITestCaseCategory.BOLA,
        cwe_mapping="CWE-284",
        description="Able to read arbitrary user profile by altering the numeric ID.",
        remediation="Implement resource-level authorization checks checking the owner.",
        proof=evidence,
    )

    stats = RunSummaryStats(total_endpoints_discovered=10, total_requests_sent=15, high_findings=1)
    summary = RunSummary(
        run_id="run-5678",
        start_time=datetime(2026, 1, 1, 10, 0, 0),
        end_time=datetime(2026, 1, 1, 10, 5, 0),
        target_url="https://api.example.com",
        stats=stats,
        findings=[finding],
        spec_artifact=SpecArtifact(
            type="openapi", version="3.0", title="Example API", total_endpoints=10
        ),
    )

    # Assert JSON Serialization
    json_data = summary.model_dump_json(indent=2)
    data = json.loads(json_data)

    assert data["run_id"] == "run-5678"
    assert data["stats"]["high_findings"] == 1
    assert data["findings"][0]["severity"] == "High"
    assert data["findings"][0]["owasp_api_2023_mapping"] == "API1:2023-BOLA"
    assert data["findings"][0]["proof"]["response_status_code"] == 200

    # Write example json to disk
    with Path("example_summary.json").open("w") as f:
        f.write(json_data)
