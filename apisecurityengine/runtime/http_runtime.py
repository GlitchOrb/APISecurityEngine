import asyncio
import time
from typing import Any
from urllib.parse import urlparse

import httpx

from apisecurityengine.models.schemas import Evidence, RedactionRules, TargetConfig


class HTTPRuntime:
    """Safe HTTP execution runtime for DAST scanning."""

    def __init__(
        self,
        config: TargetConfig,
        proof_mode: bool = False,
        concurrency_cap: int = 5,
        max_response_size_bytes: int = 1048576,  # 1MB
        timeout_seconds: float = 10.0,
    ) -> None:
        self.config = config
        self.proof_mode = proof_mode
        self.concurrency_cap = concurrency_cap
        self.max_response_size_bytes = max_response_size_bytes
        self.timeout_seconds = timeout_seconds

        self._semaphore = asyncio.Semaphore(self.concurrency_cap)
        self._last_request_times: list[float] = []

        # Shared HTTP client configuration
        self._client = httpx.AsyncClient(
            timeout=self.timeout_seconds,
            verify=False,  # Typical for security testing, though warning might apply
            follow_redirects=False,  # Explicit control to prevent SSRF
            headers=self.config.auth_headers | self.config.custom_headers,
        )

    async def close(self) -> None:
        """Close the underlying HTTP client."""
        await self._client.aclose()

    def _is_domain_allowed(self, target_url: str) -> bool:
        """Check if the target URL's domain is strictly in the allowlist."""
        parsed = urlparse(target_url)
        domain = parsed.hostname
        if not domain:
            return False

        if not self.config.allowlist_domains:
            # If no allowlist is built, we assume the initial base_url's domain is the implicit allowlist
            base_parsed = urlparse(str(self.config.base_url))
            if domain == base_parsed.hostname:
                return True
            return False

        return domain in self.config.allowlist_domains

    async def _wait_for_rate_limit(self) -> None:
        """Enforces max_requests_per_second locally."""
        now = time.monotonic()

        # Remove timestamps older than 1 second
        self._last_request_times = [t for t in self._last_request_times if now - t < 1.0]

        if len(self._last_request_times) >= self.config.max_requests_per_second:
            time_to_wait = 1.0 - (now - self._last_request_times[0])
            if time_to_wait > 0:
                await asyncio.sleep(time_to_wait)

        self._last_request_times.append(time.monotonic())

    def _sanitize_headers(self, headers: dict[str, str]) -> dict[str, str]:
        sanitized = {}
        for k, v in headers.items():
            formatted = f"{k}: {v}"
            redacted = RedactionRules.redact(formatted)
            # Extracted back out of the redacted string cleanly
            if ":" in redacted:
                rk, rv = redacted.split(":", 1)
                sanitized[rk.strip()] = rv.strip()
            else:
                sanitized[k] = "[REDACTED]"
        return sanitized

    async def execute_request(
        self,
        method: str,
        url: str,
        headers: dict[str, str] | None = None,
        body: str | bytes | None = None,
        is_high_risk: bool = False,
    ) -> Evidence:
        """Executes a single HTTP request with strict safety checks."""
        method = method.upper()

        if headers is None:
            headers = {}

        # 1. Safety Gate: Domain Allowlist
        if not self._is_domain_allowed(url):
            raise PermissionError(f"Target domain is not allowlisted: {url}")

        # 2. Safety Gate: Proof Mode on Mutative Requests
        if is_high_risk and not self.proof_mode:
            raise PermissionError(
                f"High-risk test blocked by Proof Mode settings. Skipped: {method} {url}"
            )

        sanitized_req_headers = self._sanitize_headers(headers)
        sanitized_req_body = RedactionRules.redact(
            body.decode("utf-8", errors="replace") if isinstance(body, bytes) else (body or "")
        )

        # 3. Dry-Run Check
        if self.config.dry_run:
            # Return mocked evidence bridging the pipeline seamlessly
            return Evidence(
                request_method=method,
                request_url=url,
                sanitized_request_headers=sanitized_req_headers,
                sanitized_request_body=sanitized_req_body,
                response_status_code=0,
                sanitized_response_headers={},
                sanitized_response_body="[DRY RUN - NO TRAFFIC SENT]",
            )

        # Network Execution
        async with self._semaphore:
            await self._wait_for_rate_limit()

            req = self._client.build_request(
                method=method,
                url=url,
                headers=headers,
                content=body,
            )

            # Cap response size by reading implicitly constrained segments.
            resp_body_bytes = b""
            async with self._client.stream(
                req.method, req.url, headers=req.headers, content=req.content
            ) as resp:
                async for chunk in resp.aiter_bytes():
                    resp_body_bytes += chunk
                    if len(resp_body_bytes) > self.max_response_size_bytes:
                        # Stop fetching to protect memory
                        break

            # Reconstruct response maps
            resp_headers: dict[str, Any] = dict(resp.headers)
            sanitized_resp_headers = self._sanitize_headers(resp_headers)

            resp_text = resp_body_bytes.decode("utf-8", errors="replace")
            sanitized_resp_body = RedactionRules.redact(resp_text)

            return Evidence(
                request_method=method,
                request_url=url,
                sanitized_request_headers=sanitized_req_headers,
                sanitized_request_body=sanitized_req_body,
                response_status_code=resp.status_code,
                sanitized_response_headers=sanitized_resp_headers,
                sanitized_response_body=sanitized_resp_body,
            )
