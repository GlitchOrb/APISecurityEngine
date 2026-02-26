import json
from datetime import UTC, datetime

from apisecurityengine.models.schemas import (
    APITestCaseCategory,
    Evidence,
    Finding,
    FindingConfidence,
    FindingSeverity,
    RunSummary,
    RunSummaryStats,
    SpecArtifact,
)
from apisecurityengine.reporting.html import HtmlReporter
from apisecurityengine.reporting.sarif import SarifReporter


def get_mock_summary() -> RunSummary:
    finding1 = Finding(
        id="f1",
        title="Test BOLA",
        severity=FindingSeverity.HIGH,
        confidence=FindingConfidence.SUSPECTED,
        owasp_api_2023_mapping=APITestCaseCategory.BOLA,
        cwe_mapping="CWE-284",
        description="BOLA triggered",
        remediation="Fix it",
        proof=Evidence(
            request_method="GET",
            request_url="https://api.example.com/users/1",
            sanitized_request_headers={},
            sanitized_request_body="",
            response_status_code=200,
            sanitized_response_headers={},
            sanitized_response_body="",
        ),
    )

    finding2 = Finding(
        id="f2",
        title="Test Missing Auth",
        severity=FindingSeverity.CRITICAL,
        confidence=FindingConfidence.CONFIRMED,
        owasp_api_2023_mapping=APITestCaseCategory.BROKEN_AUTH,
        cwe_mapping="CWE-306",
        description="Unauthenticated access",
        remediation="Require auth",
        proof=None,
    )

    return RunSummary(
        run_id="run_1",
        start_time=datetime.now(UTC),
        end_time=datetime.now(UTC),
        target_url="https://api.example.com",
        stats=RunSummaryStats(
            total_endpoints_discovered=10,
            critical_findings=1,
            high_findings=1,
        ),
        findings=[finding1, finding2],
        spec_artifact=SpecArtifact(type="openapi", source_uri="spec.yaml", total_endpoints=10),
    )


def test_sarif_generation() -> None:
    summary = get_mock_summary()
    sarif_str = SarifReporter.generate(summary)
    data = json.loads(sarif_str)

    assert data["version"] == "2.1.0"
    assert len(data["runs"]) == 1
    run = data["runs"][0]

    assert run["tool"]["driver"]["name"] == "APISecurityEngine"
    assert len(run["results"]) == 2

    # Check mapping logic
    results = run["results"]
    c_find = next(
        r for r in results if r["level"] == "error" and "Test Missing Auth" in r["message"]["text"]
    )
    assert c_find["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "spec.yaml"
    assert c_find["locations"][0]["logicalLocations"][0]["name"] == "Test Missing Auth"


def test_html_generation() -> None:
    summary = get_mock_summary()
    html_str = HtmlReporter.generate(summary)

    # Basic validations
    assert "<!DOCTYPE html>" in html_str
    assert "target_url" not in html_str  # Should be formatted
    assert "https://api.example.com" in html_str
    assert "Test BOLA" in html_str
    assert "Test Missing Auth" in html_str
    assert "badge-critical" in html_str
    assert "badge-high" in html_str
    assert "API1:2023-BOLA" in html_str
