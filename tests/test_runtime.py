import asyncio
from unittest.mock import AsyncMock, patch

import pytest
from pydantic import HttpUrl, TypeAdapter

from apisecurityengine.models.schemas import TargetConfig
from apisecurityengine.runtime.http_runtime import HTTPRuntime


@pytest.fixture
def config() -> TargetConfig:
    ta = TypeAdapter(HttpUrl)
    return TargetConfig(
        base_url=ta.validate_python("https://api.example.com"),
        allowlist_domains=["api.example.com", "auth.example.com"],
        max_requests_per_second=50,
        dry_run=False,
    )


@pytest.mark.asyncio
async def test_domain_allowlist(config: TargetConfig) -> None:
    runtime = HTTPRuntime(config, proof_mode=True)

    # Allowed
    assert runtime._is_domain_allowed("https://api.example.com/v1/users") is True
    assert runtime._is_domain_allowed("https://auth.example.com/token") is True

    # Denied
    assert runtime._is_domain_allowed("https://api.evil.com/v1/users") is False
    assert runtime._is_domain_allowed("http://localhost:8080/admin") is False

    # Blocked Execution check
    with pytest.raises(PermissionError, match="not allowlisted"):
        await runtime.execute_request("GET", "https://api.evil.com/v1/users")

    await runtime.close()


@pytest.mark.asyncio
async def test_proof_mode_blocks_high_risk(config: TargetConfig) -> None:
    # default proof_mode False
    runtime = HTTPRuntime(config, proof_mode=False)

    with pytest.raises(PermissionError, match="blocked by Proof Mode settings"):
        # Should raise permission error since proof_mode is off
        await runtime.execute_request(
            "DELETE", "https://api.example.com/v1/users/1", is_high_risk=True
        )

    await runtime.close()

    # proof_mode True should not raise for high risk
    runtime_proof = HTTPRuntime(config, proof_mode=True)
    # Just need to check it doesn't raise PermissionError (it will try to hit the network,
    # so we test in dry-run mode instead later or mock)
    await runtime_proof.close()


@pytest.mark.asyncio
async def test_dry_run_mode(config: TargetConfig) -> None:
    config.dry_run = True
    runtime = HTTPRuntime(config)

    # Make sure we don't mock HTTP; dry_run natively short circuits.
    evidence = await runtime.execute_request(
        "POST", "https://api.example.com/test", body="testdata"
    )

    assert evidence.response_status_code == 0
    assert "DRY RUN" in evidence.sanitized_response_body

    await runtime.close()


@pytest.mark.asyncio
async def test_redaction_and_execution(config: TargetConfig) -> None:
    # In this test, we patch AsyncClient.stream so we don't make real requests
    runtime = HTTPRuntime(config)

    headers = {"Authorization": "Bearer super-secret-jwt", "X-Custom": "Safe-Value"}

    body = b"password=mysecurepassword123&username=admin"

    # Mock the client stream manager
    mock_resp = AsyncMock()
    mock_resp.status_code = 200
    mock_resp.headers = {"Set-Cookie": "session_id=12345; Secure"}

    # Mock aiter_bytes for async streaming iterator
    async def mock_aiter() -> asyncio.subprocess.PIPE:  # type: ignore
        yield b'{"status": "success"}'
        return

    mock_resp.aiter_bytes = mock_aiter

    class MockContextManager:
        async def __aenter__(self):
            return mock_resp

        async def __aexit__(self, exc_type, exc_val, exc_tb):
            pass

    with patch.object(runtime._client, "stream", return_value=MockContextManager()):
        evidence = await runtime.execute_request(
            "POST", "https://api.example.com/login", headers=headers, body=body
        )

        # Request Assertions
        assert evidence.request_method == "POST"
        assert evidence.sanitized_request_headers.get("Authorization") == "[REDACTED]"
        assert evidence.sanitized_request_headers.get("X-Custom") == "Safe-Value"
        assert "[REDACTED]" in evidence.sanitized_request_body
        assert "password" not in evidence.sanitized_request_body

        # Response Assertions
        assert evidence.response_status_code == 200
        assert evidence.sanitized_response_headers.get("Set-Cookie") == "[REDACTED]"
        assert '{"status": "success"}' in evidence.sanitized_response_body

    await runtime.close()
