import click
from rich.console import Console

console = Console()


@click.group()
@click.version_option()
def main() -> None:
    """APISecurityEngine (ase) - Safe DAST automation for APIs."""


@main.command()
@click.option("--target", "-t", required=True, help="Target API Base URL")
@click.option("--openapi", required=True, help="Path or URL to OpenAPI spec")
@click.option(
    "--auth-profile",
    multiple=True,
    help="Auth profiles mapping, format 'key:Header:Value', e.g., 'A:Authorization:Bearer token1'",
)
@click.option("--dry-run", is_flag=True, help="Dry run without sending mutative traffic")
@click.option("--proof-mode", is_flag=True, help="Execute potentially unsafe tests")
@click.option(
    "--format",
    "report_format",
    default="json",
    type=click.Choice(["json", "html", "sarif"]),
    help="Output report format",
)
def scan(
    target: str,
    openapi: str,
    auth_profile: list[str],
    dry_run: bool,
    proof_mode: bool,
    report_format: str,
) -> None:
    """Run a security scan against the target using the provided spec."""
    import asyncio

    from pydantic import HttpUrl, TypeAdapter

    from apisecurityengine.core.engine import ScanEngine
    from apisecurityengine.models.schemas import SpecArtifact, TargetConfig
    from apisecurityengine.spec.openapi_loader import OpenAPILoader

    # Parse Auth Profiles
    profiles = {}
    for prof in auth_profile:
        parts = prof.split(":", 2)
        if len(parts) == 3:
            key, header, value = parts
            profiles[key] = {header: value}

    try:
        url = TypeAdapter(HttpUrl).validate_python(target)
    except Exception as e:
        console.print(f"[red]Invalid target URL format:[/red] {e}")
        return

    # Ingest Graph
    try:
        spec_dict = OpenAPILoader.load(openapi)
        graph = OpenAPILoader.build_graph(spec_dict)
    except Exception as e:
        console.print(f"[red]Failed to ingest OpenAPI spec:[/red] {e}")
        return

    config = TargetConfig(base_url=url, dry_run=dry_run)
    artifact = SpecArtifact(
        type="openapi", source_uri=openapi, total_endpoints=graph.total_endpoints()
    )

    async def execute_scan() -> None:
        console.print("[cyan]Initializing Engine with Endpoints...[/cyan]")
        engine = ScanEngine(
            config=config,
            graph=graph,
            spec_artifact=artifact,
            auth_profiles=profiles,
            proof_mode=proof_mode,
        )

        summary = await engine.run()
        json_out = summary.model_dump_json(indent=2)

        if report_format == "html":
            from apisecurityengine.reporting.html import HtmlReporter

            html_content = HtmlReporter.generate(summary)
            with open("report.html", "w", encoding="utf-8") as f:
                f.write(html_content)
            console.print("[green]Report saved cleanly to report.html[/green]")
        elif report_format == "sarif":
            from apisecurityengine.reporting.sarif import SarifReporter

            sarif_content = SarifReporter.generate(summary)
            with open("report.sarif", "w", encoding="utf-8") as f:
                f.write(sarif_content)
            console.print("[green]SARIF Report saved cleanly to report.sarif[/green]")
        else:
            print(json_out)

    asyncio.run(execute_scan())


@main.command()
@click.option("--target", "-t", required=True, help="Target API URL")
@click.option("--openapi", required=True, help="Path or URL to OpenAPI spec")
@click.option("--ai", is_flag=True, help="Generate an AI-driven test scenario mapping (mocked)")
def plan(target: str, openapi: str, ai: bool) -> None:
    """Generate and output an advanced test plan scenario."""
    console.print(f"[blue]Generating test plan for target: {target}[/blue]")

    if ai:
        from apisecurityengine.ai.scenario_agent import ScenarioAgent
        from apisecurityengine.spec.openapi_loader import OpenAPILoader

        try:
            spec_dict = OpenAPILoader.load(openapi)
            graph = OpenAPILoader.build_graph(spec_dict)
            mock_json = ScenarioAgent.generate_mock_response(graph)
            
            # Print parsed JSON
            console.print("[cyan]Generating scenario response...[/cyan]")
            console.print(mock_json)
        except Exception as e:
            console.print(f"[red]Failed to generate AI plan:[/red] {e}")


@main.group()
def spec() -> None:
    """Operations related to API specs (OpenAPI, GraphQL)."""


@spec.command("summarize")
@click.option("--openapi", help="Path or URL to the OpenAPI specification")
def spec_summarize(openapi: str | None) -> None:
    """Summarize an OpenAPI specification."""
    if not openapi:
        console.print("[yellow]Notice: Provide a path or URL using --openapi.[/yellow]")
        return

    console.print(f"[cyan]Loading specification from: {openapi}[/cyan]")
    from apisecurityengine.spec.openapi_loader import OpenAPILoader

    try:
        spec_dict = OpenAPILoader.load(openapi)
        graph = OpenAPILoader.build_graph(spec_dict)
    except Exception as e:
        console.print(f"[red]Error loading specification: {e}[/red]")
        return

    console.print(f"[bold green]Summary for {openapi}:[/bold green]")
    console.print(f"Total Endpoints Discovered: [bold]{graph.total_endpoints()}[/bold]")
    console.print(f"  - Read: [blue]{graph.total_read()}[/blue]")
    console.print(f"  - Write: [magenta]{graph.total_write()}[/magenta]")
    console.print(f"  - Destructive: [red]{graph.total_destructive()}[/red]")
    console.print(f"  - Requiring Auth: [yellow]{graph.total_requires_auth()}[/yellow]")


@main.command("report")
@click.option(
    "--from",
    "from_file",
    required=True,
    type=click.Path(exists=True),
    help="Path to JSON run summary",
)
@click.option(
    "--format",
    "report_format",
    required=True,
    type=click.Choice(["html", "sarif"]),
    help="Format to convert to",
)
def convert_report(from_file: str, report_format: str) -> None:
    """Read a JSON run summary and convert it to SARIF or HTML."""
    from pydantic import TypeAdapter

    from apisecurityengine.models.schemas import RunSummary

    try:
        with open(from_file, "r", encoding="utf-8") as f:
            json_blob = f.read()
            
        start_idx = json_blob.find("{")
        if start_idx >= 0:
            json_blob = json_blob[start_idx:]
            
        ta = TypeAdapter(RunSummary)
        summary = ta.validate_json(json_blob)
    except Exception as e:
        console.print(f"[red]Failed to load or parse JSON source:[/red] {e}")
        return

    if report_format == "html":
        from apisecurityengine.reporting.html import HtmlReporter

        out_content = HtmlReporter.generate(summary)
        out_file = "report.html"
    else:
        from apisecurityengine.reporting.sarif import SarifReporter

        out_content = SarifReporter.generate(summary)
        out_file = "report.sarif"

    with open(out_file, "w", encoding="utf-8") as f:
        f.write(out_content)

    console.print(f"[green]Successfully generated {out_file}[/green]")


@main.group()
def runtime() -> None:
    """Operations related to Safe DAST HTTP Runtime."""


@runtime.command("check")
@click.option("--base-url", required=True, help="Base URL of the target API")
@click.option("--dry-run", is_flag=True, help="Mock requests without sending them")
@click.option(
    "--proof-mode", is_flag=True, help="Enable execution of potentially mutative payloads"
)
def runtime_check(base_url: str, dry_run: bool, proof_mode: bool) -> None:
    """Verify runtime connectivity and print safety boundaries."""
    import asyncio

    from pydantic import HttpUrl, TypeAdapter

    from apisecurityengine.models.schemas import TargetConfig
    from apisecurityengine.runtime.http_runtime import HTTPRuntime

    try:
        url = TypeAdapter(HttpUrl).validate_python(base_url)
    except Exception as e:
        console.print(f"[red]Invalid URL format:[/red] {e}")
        return

    config = TargetConfig(base_url=url, dry_run=dry_run)

    console.print(f"[bold green]Initializing Safe Runtime against: {base_url}[/bold green]")
    console.print(f"  - Max Requests/sec: {config.max_requests_per_second}")
    console.print(
        f"  - Domain Allowlist: {[url.host] if not config.allowlist_domains else config.allowlist_domains}"
    )
    console.print(f"  - Dry-Run Active: {config.dry_run}")
    console.print(f"  - Proof Mode (High Risk Allowed): {proof_mode}")

    # Connectivity Check
    async def run_check() -> None:
        runtime_env = HTTPRuntime(config, proof_mode=proof_mode)
        try:
            console.print("[cyan]Executing simple GET check (or mocked if dry-run)...[/cyan]")
            evidence = await runtime_env.execute_request("GET", base_url)
            console.print(
                f"[green]Connectivity Check Status:[/green] {evidence.response_status_code}"
            )
        except PermissionError as e:
            console.print(f"[yellow]Safety Check Blocked Request:[/yellow] {e}")
        except Exception as e:
            console.print(f"[red]Connection Error:[/red] {e}")
        finally:
            await runtime_env.close()

    asyncio.run(run_check())


@main.command("execute")
@click.option(
    "--plan", required=True, type=click.Path(exists=True), help="Path to scenario plan JSON"
)
@click.option("--target", required=True, help="Target API Base URL")
@click.option("--approve-destructive", is_flag=True, help="Approve execution of destructive steps")
def execute(plan: str, target: str, approve_destructive: bool) -> None:
    """Safely execute an AI generated scenario plan."""
    import asyncio

    from pydantic import HttpUrl, TypeAdapter

    from apisecurityengine.ai.scenario_agent import ScenarioAgent
    from apisecurityengine.models.schemas import TargetConfig
    from apisecurityengine.runtime.http_runtime import HTTPRuntime

    try:
        url = TypeAdapter(HttpUrl).validate_python(target)
    except Exception as e:
        console.print(f"[red]Invalid URL format:[/red] {e}")
        return

    config = TargetConfig(base_url=url, dry_run=False)  # Execution mode

    with open(plan, encoding="utf-8") as f:
        plan_data = f.read()

    try:
        scenario = ScenarioAgent.parse_and_validate(plan_data)
    except Exception as e:
        console.print(f"[red]Invalid Plan:[/red] {e}")
        return

    has_destructive = any(step.is_destructive for step in scenario.steps)
    if has_destructive and not approve_destructive:
        console.print(
            "[red]Plan contains destructive steps but --approve-destructive was not provided. Execution aborted.[/red]"
        )
        return

    console.print(f"[bold green]Executing Plan: {scenario.name}[/bold green]")
    console.print(f"[blue]Description:[/blue] {scenario.description}")

    async def run_scenario() -> None:
        runtime_env = HTTPRuntime(config, proof_mode=approve_destructive)
        try:
            for step in scenario.steps:
                console.print(f"[cyan]Executing Step: {step.id} - {step.description}[/cyan]")
                test_url = str(url).rstrip("/") + step.request.path
                body_bytes = step.request.body.encode() if step.request.body else None

                evidence = await runtime_env.execute_request(
                    method=step.request.method,
                    url=test_url,
                    headers=step.request.headers,
                    body=body_bytes,
                    is_high_risk=step.is_destructive,
                )

                console.print(f"[green]Status [{evidence.response_status_code}][/green]")
        except PermissionError as e:
            console.print(f"[yellow]Safety Check Blocked Request:[/yellow] {e}")
        except Exception as e:
            console.print(f"[red]Connection Error:[/red] {e}")
        finally:
            await runtime_env.close()

    asyncio.run(run_scenario())


if __name__ == "__main__":
    main()
