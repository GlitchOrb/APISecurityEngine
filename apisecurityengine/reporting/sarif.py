import json
from typing import Any

from apisecurityengine.models.schemas import FindingSeverity, RunSummary


class SarifReporter:
    """Generates SARIF v2.1.0 compliant reports for GitHub Advanced Security ingestion."""

    # Map severity to SARIF levels
    # Valid levels: "none", "note", "warning", "error"
    LEVEL_MAP = {
        FindingSeverity.CRITICAL: "error",
        FindingSeverity.HIGH: "error",
        FindingSeverity.MEDIUM: "warning",
        FindingSeverity.LOW: "note",
        FindingSeverity.INFORMATIONAL: "note",
    }

    @classmethod
    def generate(cls, summary: RunSummary) -> str:
        """Translates a RunSummary directly to a SARIF JSON string."""
        rules_dict: dict[str, dict[str, Any]] = {}
        results = []

        for finding in summary.findings:
            rule_id = finding.owasp_api_2023_mapping
            if rule_id not in rules_dict:
                rules_dict[rule_id] = {
                    "id": str(rule_id),
                    "name": str(rule_id),
                    "shortDescription": {"text": f"OWASP API Security Top 10: {rule_id}"},
                    "fullDescription": {
                        "text": f"Vulnerability mapped to {rule_id} and {finding.cwe_mapping}."
                    },
                    "help": {"text": "Refer to OWASP documentation for this category."},
                    "properties": {"tags": ["security", "API", finding.cwe_mapping]},
                }

            level = cls.LEVEL_MAP.get(finding.severity, "note")

            # Try to build a logical location string (usually the path if we have proof)
            artifact_uri = (
                summary.spec_artifact.source_uri
                if summary.spec_artifact.source_uri
                else "dynamic_scan"
            )
            logical_location = ""
            if finding.proof and finding.proof.request_url:
                logical_location = str(finding.proof.request_url)
            else:
                logical_location = finding.title

            result: dict[str, Any] = {
                "ruleId": str(rule_id),
                "level": level,
                "message": {"text": finding.title + ": " + finding.description},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": artifact_uri},
                        },
                        "logicalLocations": [{"name": logical_location, "kind": "api-endpoint"}],
                    }
                ],
                "properties": {
                    "severity": finding.severity.value,
                    "confidence": finding.confidence.value,
                    "remediation": finding.remediation,
                },
            }
            results.append(result)

        driver_rules = list(rules_dict.values())

        sarif_log = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "APISecurityEngine",
                            "informationUri": "https://github.com/GlitchOrb/APISecurityEngine",
                            "semanticVersion": "1.0.0",
                            "rules": driver_rules,
                        }
                    },
                    "results": results,
                }
            ],
        }

        return json.dumps(sarif_log, indent=2)
