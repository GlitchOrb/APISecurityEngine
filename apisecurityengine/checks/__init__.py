"""
Security checks mapped to OWASP API Security Top 10:2023.
"""

from abc import ABC, abstractmethod
from collections.abc import AsyncGenerator

from apisecurityengine.models.schemas import Finding, TargetConfig
from apisecurityengine.runtime.http_runtime import HTTPRuntime
from apisecurityengine.spec.endpoint_graph import EndpointGraph, EndpointNode


class BaseCheck(ABC):
    """Abstract base class for all vulnerability checks."""

    @abstractmethod
    async def execute(
        self,
        target_config: TargetConfig,
        runtime: HTTPRuntime,
        graph: EndpointGraph,
        auth_profiles: dict[str, dict[str, str]],
    ) -> AsyncGenerator[Finding, None]:
        """Execute the check and yield findings."""
        if False:
            yield NotImplemented
