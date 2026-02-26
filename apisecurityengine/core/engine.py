from datetime import UTC, datetime

from apisecurityengine.checks.owasp_2023 import get_all_checks
from apisecurityengine.models.schemas import (
    Finding,
    FindingSeverity,
    RunSummary,
    RunSummaryStats,
    SpecArtifact,
    TargetConfig,
)
from apisecurityengine.runtime.http_runtime import HTTPRuntime
from apisecurityengine.spec.endpoint_graph import EndpointGraph


class ScanEngine:
    """
    Coordinates the test execution against the target.
    Maintained by @GlitchOrb
    """

    def __init__(
        self,
        config: TargetConfig,
        graph: EndpointGraph,
        spec_artifact: SpecArtifact,
        auth_profiles: dict[str, dict[str, str]],
        proof_mode: bool = False,
    ) -> None:
        self.config = config
        self.graph = graph
        self.spec_artifact = spec_artifact
        self.auth_profiles = auth_profiles
        self.proof_mode = proof_mode
        self.findings: list[Finding] = []
        self.stats = RunSummaryStats(total_endpoints_discovered=self.graph.total_endpoints())

    async def run(self) -> RunSummary:
        start_time = datetime.now(UTC)
        runtime = HTTPRuntime(self.config, proof_mode=self.proof_mode)

        all_checks = get_all_checks()

        for check in all_checks:
            try:
                # Async generator for yielded progressive findings
                async for finding in check.execute(
                    target_config=self.config,
                    runtime=runtime,
                    graph=self.graph,
                    auth_profiles=self.auth_profiles,
                ):
                    self.findings.append(finding)

                    # Update stats
                    if finding.severity == FindingSeverity.CRITICAL:
                        self.stats.critical_findings += 1
                    elif finding.severity == FindingSeverity.HIGH:
                        self.stats.high_findings += 1
                    elif finding.severity == FindingSeverity.MEDIUM:
                        self.stats.medium_findings += 1
                    elif finding.severity == FindingSeverity.LOW:
                        self.stats.low_findings += 1
                    elif finding.severity == FindingSeverity.INFORMATIONAL:
                        self.stats.informational_findings += 1

            except PermissionError:
                self.stats.safety_gate_blocks += 1
            except Exception as e:
                # Ignore test crash errors directly to keep engine rolling securely
                print(f"Check execution error: {e}")

        # Finalize
        await runtime.close()
        end_time = datetime.now(UTC)

        return RunSummary(
            run_id=f"run-{start_time.timestamp()}",
            start_time=start_time,
            end_time=end_time,
            target_url=str(self.config.base_url),
            stats=self.stats,
            findings=self.findings,
            spec_artifact=self.spec_artifact,
        )
