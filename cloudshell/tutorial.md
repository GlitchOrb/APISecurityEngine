<walkthrough-author name="APISecurityEngine team @GlitchOrb" tutorial-url="https://github.com/GlitchOrb/APISecurityEngine/tree/main/cloudshell/tutorial.md"/>

# APISecurityEngine Cloud Shell Demo

## Welcome to APISecurityEngine!

This interactive tutorial will guide you through running **APISecurityEngine**—a safe DAST automation tool for finding OWASP Top 10:2023 API vulnerabilities directly within Google Cloud Shell.

You will learn how to:
1. Initialize the Python environment natively.
2. Spin up a safe local mock target for testing.
3. Automatically execute the `scan` and view structured artifacts.

Let's get started!

<walkthrough-tutorial-duration duration="5"></walkthrough-tutorial-duration>

## Step 1: Bootstrap the Environment

First, we need to install the dependencies and optionally spin up a local safe target mock.

Run the bootstrap script provided in the repository. Click the copy button below, then paste and execute it in your Cloud Shell terminal.

```bash
bash scripts/cloudshell_bootstrap.sh
```

This script will seamlessly:
- Install `uv` (our fast Python dependency manager).
- Sync all requirements (`httpx`, `PyYAML`, `click`, etc).
- Launch a mock web server on `http://127.0.0.1:8080`.

## Step 2: Validate Installation

Verify that the CLI has been natively installed by checking the help command.

```bash
uv run ase --help
```

You should see our primary commands (`scan`, `plan`, `execute`, `spec`, `runtime`).

## Step 3: Run the Scan Engine

We have pre-packaged an example OpenAPI mock specification in `tests/fixtures/example_openapi_v3.yaml`. Let's test checking it against our locally spawned local machine.

Run the scan command:

```bash
uv run ase scan --target http://127.0.0.1:8080 \
  --openapi tests/fixtures/example_openapi_v3.yaml \
  --auth-profile "A:Authorization:Bearer USER_A_TOKEN" \
  --auth-profile "B:Authorization:Bearer USER_B_TOKEN" \
  --format html \
  --dry-run
```

Because of the `--dry-run` flag, no mutative network traffic runs implicitly across destructive routes, but heuristic testing immediately assesses the specification and outputs findings mapped to the OWASP Top 10 bounds.

## Step 4: Review the Artifacts

The scanner finished assessing the target and generated a report artifact. Your structured artifacts have been saved out completely mapping to CWEs and Remediation recommendations. 

Check for the output file:

```bash
cat report.html
```

<walkthrough-footnote>Alternatively, click "Open Editor" in Cloud Shell and native navigate to `report.html` to view the comprehensive graphical findings!</walkthrough-footnote>

## Conclusion

Congratulations! You have effectively simulated a secure API baseline assessment using **APISecurityEngine**. 

Make sure to stop the local mock web-server gracefully:
```bash
kill $(cat mock_server.pid) && rm mock_server.pid mock_response.json
```

<walkthrough-conclusion-trophy></walkthrough-conclusion-trophy>
