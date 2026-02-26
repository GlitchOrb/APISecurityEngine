# Secrets Hygiene (Prevention & Scanning)

Committing explicit API keys, database credentials, JWT secrets, and tokens to Version Control Systems exposes APIs directly to Broken Authentication issues and infrastructure hijack.

## Defensive Strategy
Never hardcode environment strings. Instead, utilize `python-dotenv` or Cloud Secret Managers. Integrate CI/CD gates to scan and block pushes that match known credential formats natively.

---

### Local Workflows (pre-commit setup)
A developer environment should fail locally if they accidentally stage an AWS tag or GitHub PAT. Install `pre-commit` and maintain `.pre-commit-config.yaml` using [trufflehog](https://github.com/trufflesecurity/trufflehog).

```yaml
repos:
  - repo: https://github.com/trufflesecurity/trufflehog
    rev: v3.63.7
    hooks:
      - id: trufflehog
        name: TruffleHog Secrets Scan
        args: ["git", "file://.", "--only-verified"]
```

---

### CI/CD Deployment Blocking (GitHub Actions)
Ensure infrastructure deployments block aggressively if unverified keys reach production containers.

```yaml
# .github/workflows/secrets.yml
name: Secret Scanner
on: [push, pull_request]

jobs:
  trufflehog:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Code
        uses: actions/checkout@v3
        with:
          fetch-depth: 0
          
      - name: TruffleHog OSS
        uses: trufflesecurity/trufflehog@main
        with:
          path: ./
          base: ${{ github.event.repository.default_branch }}
          head: HEAD
          extra_args: --debug --only-verified
```
