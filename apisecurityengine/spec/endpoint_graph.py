from typing import Any

from pydantic import BaseModel, Field


class EndpointNode(BaseModel):
    """Represents a single API endpoint operation in the graph."""

    path: str
    method: str
    operation_id: str | None = None
    parameters: list[dict[str, Any]] = Field(default_factory=list)
    request_body: dict[str, Any] | None = None
    responses: dict[str, Any] = Field(default_factory=dict)

    # Heuristics metadata
    is_read: bool = False
    is_write: bool = False
    is_destructive: bool = False
    requires_auth: bool = False
    likely_object_identifiers: list[str] = Field(default_factory=list)


class EndpointGraph(BaseModel):
    """Graph of all discovered endpoints with stats processing."""

    endpoints: list[EndpointNode] = Field(default_factory=list)

    def total_read(self) -> int:
        return sum(1 for e in self.endpoints if e.is_read)

    def total_write(self) -> int:
        return sum(1 for e in self.endpoints if e.is_write)

    def total_destructive(self) -> int:
        return sum(1 for e in self.endpoints if e.is_destructive)

    def total_requires_auth(self) -> int:
        return sum(1 for e in self.endpoints if e.requires_auth)

    def total_endpoints(self) -> int:
        return len(self.endpoints)
