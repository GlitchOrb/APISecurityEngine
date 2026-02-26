# APISecurityEngine
> @GlitchOrb

An API security testing automation tool that ingests OpenAPI/GraphQL/gRPC definitions, generates automated test plans, executes them with safety controls, and produces evidence-based reports mapped to OWASP API Top 10:2023.


<img width="1914" height="898" alt="스크린샷 2026-02-26 125214" src="https://github.com/user-attachments/assets/242d7440-da64-4902-9921-264b93e440ce" />



## Requirements
- Python 3.12+
- [uv](https://github.com/astral-sh/uv) (recommended) or pip

## Installation & Setup

Using `uv`:

```bash
# Clone the repository
git clone https://github.com/GlitchOrb/APISecurityEngine.git
cd APISecurityEngine

# Install dependencies and sync environment
uv sync

# Run the CLI
uv run ase --help
```

## Development

```bash
# Install pre-commit hooks
uv run pre-commit install

# Run tests
uv run pytest

# Type checking
uv run mypy apisecurityengine/ tests/

# Linting & Formatting
uv run ruff check .
uv run ruff format .
```

## CLI Usage

APISecurityEngine is designed with safety first. It requires explicit flags to perform invasive tests.

```bash
# Get help
ase --help

# Scan a target safely (Dry Run)
# --dry-run parses the specification and looks for structural vulnerabilities 
# but DOES NOT send any mutative traffic to the target server.
ase scan --target https://api.example.com --dry-run

# Execute full destructive tests
# --proof-mode removes safety guards and executes real mutative payloads 
# (e.g., Mass Assignment POSTs, DELETE requests) against the target.
ase scan --target https://api.example.com --openapi schema.yaml --proof-mode
```

### Try it now in your browser
Want to see the engine in action without installing anything locally? Spin up a safe, sandboxed Cloud Shell environment with a pre-configured dangerously vulnerable mock API.

[![Open in Cloud Shell](https://gstatic.com/cloudssh/images/open-btn.svg)](https://shell.cloud.google.com/cloudshell/editor?cloudshell_git_repo=https://github.com/GlitchOrb/APISecurityEngine.git&cloudshell_tutorial=cloudshell/tutorial.md&show=ide%2Cterminal&cloudshell_workspace=.)


## Security Posture & Incident Patterns

APISecurityEngine includes checks and guidance for common real-world API incident patterns, such as:
- Authorization bypass patterns (BOLA/IDOR) and role boundary violations
- Weak authentication and token handling pitfalls
- Unrestricted resource consumption (rate limiting / cost amplification)
- SSRF-style URL fetch misuse
- Security misconfiguration signals (CORS/headers/debug endpoints)
- Improper API inventory exposure and forgotten endpoints
- Secrets hygiene: preventing API keys/tokens from leaking into source control

> **Note:** APISecurityEngine is a testing and validation tool. It does not “patch” CVEs automatically; it helps identify risky patterns and provides recommended defenses.

| OWASP API Top 10:2023 | Heuristic / Execution Check | CWE Relevance | Defense Snippet Guide |
| --- | --- | --- | --- |
| **API1: BOLA** | Cross-profile parameter swapping (`/users/{id}` vs Profile B) | [CWE-284](https://cwe.mitre.org/data/definitions/284.html) | [Object-Level Auth Defenses](docs/defenses/object_level_auth.md) |
| **API2: Broken Auth** | Unauthenticated execution on routes mapping `requires_auth=True` | [CWE-306](https://cwe.mitre.org/data/definitions/306.html) | [Secrets Hygiene Scanners](docs/defenses/secrets_hygiene.md) |
| **API3: BOPLA** | Permissive payload insertions (`"is_admin": true`) | [CWE-915](https://cwe.mitre.org/data/definitions/915.html) | Explicit DTO Serialization Models |
| **API4: Resource Consumption** | Enumerating missing limits/page schemas on collections | [CWE-770](https://cwe.mitre.org/data/definitions/770.html) | Implement Upper bounds pagination |
| **API5: BFLA** | Profile A executions against isolated admin/dashboard domains | [CWE-285](https://cwe.mitre.org/data/definitions/285.html) | [Function-Level Auth Guards](docs/defenses/function_level_auth.md) |
| **API6: Sensitive Flows** | Tracing business heuristics (`checkout`, `transfer`) | [CWE-799](https://cwe.mitre.org/data/definitions/799.html) | [Rate Limits & Bot Defenses](docs/defenses/rate_limiting.md) |
| **API7: SSRF** | Metadata IPs/Localhost pinging injected via URL query parameters | [CWE-918](https://cwe.mitre.org/data/definitions/918.html) | [SSRF & Rebinding Protections](docs/defenses/ssrf_protection.md) |
| **API8: Misconfigurations** | Trace/OPTIONS header evaluations and CORS misalignments | [CWE-16](https://cwe.mitre.org/data/definitions/16.html) | Enforce Global Proxies Security Headers |
| **API9: Improper Inventory** | Routing bypass attempts natively against version shifting (e.g. `/v2/`) | [CWE-1059](https://cwe.mitre.org/data/definitions/1059.html) | Deprecate and 404 old environments |
| **API10: Unsafe Consumption** | Unprotected webhook validations mapping omitted signature parameters | [CWE-300](https://cwe.mitre.org/data/definitions/300.html) | Always demand HMAC Webhook Signatures |
