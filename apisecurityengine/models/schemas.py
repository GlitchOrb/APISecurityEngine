import hashlib
import re
from datetime import UTC, datetime
from enum import StrEnum
from typing import ClassVar, Literal

from pydantic import BaseModel, ConfigDict, Field, HttpUrl


class TargetConfig(BaseModel):
    """Configuration for a specific target being tested."""

    base_url: HttpUrl
    auth_headers: dict[str, str] = Field(default_factory=dict)
    allowlist_domains: list[str] = Field(default_factory=list)
    max_requests_per_second: int = Field(default=10, ge=1)
    max_duration_seconds: int = Field(default=600, ge=1)
    custom_headers: dict[str, str] = Field(default_factory=dict)
    dry_run: bool = False


class SpecArtifact(BaseModel):
    """Metadata regarding the ingested API schema/spec."""

    type: Literal["openapi", "graphql", "grpc"]
    version: str | None = None
    title: str | None = None
    total_endpoints: int = 0
    source_uri: str | None = None


class APITestCaseCategory(StrEnum):
    BOLA = "API1:2023-BOLA"
    BROKEN_AUTH = "API2:2023-BROKEN-AUTH"
    BOPLA = "API3:2023-BOPLA"
    RESOURCE_CONSUMPTION = "API4:2023-RESOURCE"
    BFLA = "API5:2023-BFLA"
    SSRF = "API6:2023-SSRF"
    SECURITY_MISCONFIG = "API7:2023-MISCONFIG"
    MASS_ASSIGNMENT = "API8:2023-MASS-ASSIGN"
    IMPROPER_INVENTORY = "API9:2023-INVENTORY"
    UNSAFE_CONSUMPTION = "API10:2023-UNSAFE-CONSUMPTION"
    MISC = "MISC"


class TestCase(BaseModel):
    """A single security test to be executed."""

    id: str
    category: APITestCaseCategory
    request_template: dict[str, str | dict[str, str]]
    mutation_strategy: str
    prerequisites: list[str] = Field(default_factory=list)
    description: str


class RedactionRules:
    """Rules for applying redaction to evidence logs."""

    PATTERNS: ClassVar[list[re.Pattern[str]]] = [
        re.compile(r"Bearer\s+[\w\-.]+"),
        re.compile(r"password=[\w\-!@#$%^&*]+"),
        re.compile(r"token=[\w\-.]+"),
        re.compile(r"secret[\w\-]*=[\w\-.]+"),
        re.compile(r"Set-Cookie:\s*[a-zA-Z0-9_\-]+=[^;]+;?"),
    ]

    @staticmethod
    def redact(text: str | None) -> str:
        if not text:
            return ""
        redacted_text = text
        for pattern in RedactionRules.PATTERNS:
            redacted_text = pattern.sub("[REDACTED]", redacted_text)
        return redacted_text


class Evidence(BaseModel):
    """Sanitized evidence of a completed request and its response."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    request_method: str
    request_url: str
    sanitized_request_headers: dict[str, str] = Field(default_factory=dict)
    sanitized_request_body: str = ""
    response_status_code: int
    sanitized_response_headers: dict[str, str] = Field(default_factory=dict)
    sanitized_response_body: str = ""

    @property
    def request_hash(self) -> str:
        content = f"{self.request_method}|{self.request_url}|{self.sanitized_request_body}"
        return hashlib.sha256(content.encode()).hexdigest()


class FindingSeverity(StrEnum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFORMATIONAL = "Informational"


class FindingConfidence(StrEnum):
    CONFIRMED = "Confirmed"
    SUSPECTED = "Suspected"
    INFORMATIONAL = "Informational"


class Finding(BaseModel):
    """A vulnerability or security issue discovered during a scan."""

    id: str
    title: str
    severity: FindingSeverity
    confidence: FindingConfidence
    owasp_api_2023_mapping: APITestCaseCategory
    cwe_mapping: str
    description: str
    remediation: str
    proof: Evidence | None = None


class RunSummaryStats(BaseModel):
    total_endpoints_discovered: int = 0
    total_requests_sent: int = 0
    safety_gate_blocks: int = 0
    critical_findings: int = 0
    high_findings: int = 0
    medium_findings: int = 0
    low_findings: int = 0
    informational_findings: int = 0


class RunSummary(BaseModel):
    """High-level summary of a complete engine execution."""

    run_id: str
    start_time: datetime
    end_time: datetime
    target_url: str
    stats: RunSummaryStats
    findings: list[Finding] = Field(default_factory=list)
    spec_artifact: SpecArtifact | None = None

    @property
    def duration_seconds(self) -> float:
        return (self.end_time - self.start_time).total_seconds()
