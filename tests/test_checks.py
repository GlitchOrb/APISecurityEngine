import pytest
from pydantic import HttpUrl, TypeAdapter

from apisecurityengine.checks.owasp_2023 import (
    API1BOLACheck,
    API2BrokenAuthCheck,
    API4UnrestrictedResourceCheck,
)
from apisecurityengine.core.engine import ScanEngine
from apisecurityengine.models.schemas import SpecArtifact, TargetConfig
from apisecurityengine.spec.openapi_loader import OpenAPILoader


@pytest.fixture
def test_config() -> TargetConfig:
    ta = TypeAdapter(HttpUrl)
    return TargetConfig(
        base_url=ta.validate_python("https://api.example.com"),
        dry_run=True,
    )


@pytest.fixture
def spec_graph():
    spec_dict = OpenAPILoader.load("tests/fixtures/example_openapi_v3.yaml")
    return OpenAPILoader.build_graph(spec_dict)


@pytest.mark.asyncio
async def test_api1_bola_check_skip_no_auth(test_config, spec_graph):
    # Needs A and B profiles
    check = API1BOLACheck()
    from apisecurityengine.runtime.http_runtime import HTTPRuntime

    runtime = HTTPRuntime(test_config)
    findings = [f async for f in check.execute(test_config, runtime, spec_graph, auth_profiles={})]
    await runtime.close()

    assert len(findings) == 0


@pytest.mark.asyncio
async def test_api2_broken_auth_check(test_config, spec_graph):
    check = API2BrokenAuthCheck()
    from apisecurityengine.runtime.http_runtime import HTTPRuntime

    runtime = HTTPRuntime(test_config)
    findings = [f async for f in check.execute(test_config, runtime, spec_graph, auth_profiles={})]
    await runtime.close()

    # The example graph has /users, /users/{userId}, /accounts/{accountId}/transfer all requiring auth
    # We execute dry-run so response code is 0, which misses the [200, 201, 204] threshold
    assert len(findings) == 0


@pytest.mark.asyncio
async def test_api4_unrestricted_resource(test_config, spec_graph):
    check = API4UnrestrictedResourceCheck()
    from apisecurityengine.runtime.http_runtime import HTTPRuntime

    runtime = HTTPRuntime(test_config)
    findings = [f async for f in check.execute(test_config, runtime, spec_graph, auth_profiles={})]
    await runtime.close()

    # /users and /users/{userId} and /public/ping are GETs
    # None have "limit" parameters configured in the example yaml.
    assert len(findings) == 3
    assert all(f.owasp_api_2023_mapping == "API4:2023-RESOURCE" for f in findings)


@pytest.mark.asyncio
async def test_full_scan_engine(test_config, spec_graph):
    profiles = {"A": {"Authorization": "Bearer AAA"}, "B": {"Authorization": "Bearer BBB"}}
    artifact = SpecArtifact(type="openapi", total_endpoints=len(spec_graph.endpoints))

    engine = ScanEngine(
        config=test_config,
        graph=spec_graph,
        spec_artifact=artifact,
        auth_profiles=profiles,
        proof_mode=False,
    )

    summary = await engine.run()

    assert summary.stats.total_endpoints_discovered == 6
    # It should find API4 (x3 from GET limit absence), API6 (Sensitive flow), API8 (Missing headers since dry_run doesn't output X-Content-Type), API10 etc based on heuristic heuristics firing immediately.
    assert len(summary.findings) > 0

    stats_dict = summary.model_dump()["stats"]
    assert stats_dict["informational_findings"] > 0
