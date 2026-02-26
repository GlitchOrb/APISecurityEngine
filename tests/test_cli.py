from click.testing import CliRunner

from apisecurityengine.cli import main


def test_cli_help() -> None:
    """Test the CLI help command."""
    runner = CliRunner()
    result = runner.invoke(main, ["--help"])
    assert result.exit_code == 0
    assert "APISecurityEngine (ase)" in result.output


def test_scan_no_target() -> None:
    """Test scan command without a target/openapi (Should show usage error)."""
    runner = CliRunner()
    result = runner.invoke(main, ["scan"])
    assert result.exit_code == 2  # Click missing argument exit code


def test_scan_with_target() -> None:
    """Test scan command with proper required args."""
    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "scan",
            "--target",
            "http://localhost",
            "--openapi",
            "tests/fixtures/example_openapi_v3.yaml",
            "--dry-run",
        ],
    )
    assert result.exit_code == 0
    assert "Initializing Engine with Endpoints" in result.output


def test_plan_command() -> None:
    """Test plan command output."""
    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "plan",
            "--target",
            "http://localhost",
            "--openapi",
            "tests/fixtures/example_openapi_v3.yaml",
        ],
    )
    assert result.exit_code == 0
    assert "Generating test plan for target:" in result.output
