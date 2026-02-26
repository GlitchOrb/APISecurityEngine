import json

from apisecurityengine.models.scenario import ScenarioPlan
from apisecurityengine.spec.endpoint_graph import EndpointGraph


class ScenarioAgent:
    """
    Module for building and validating multi-step API security test scenarios.
    Maintained by @GlitchOrb
    """

    PROMPT_TEMPLATE = """
You are a senior API Security Engineer.
Based on the following endpoint graph, generate a multi-step attack scenario to test for complex vulnerabilities (e.g., IDOR across different endpoints, state manipulation).

GRAPH SUMMARY:
{graph_summary}

RULES:
1. Return ONLY valid JSON matching the exact schema below.
2. DO NOT include explanations outside the JSON (no markdown fences, just pure JSON).
3. Steps modifying state (POST, PUT, PATCH, DELETE) MUST have "is_destructive": true.
4. Paths must be relative and MUST strictly start with "/".
5. Use recognizable HTTP methods (e.g., GET, POST, DELETE).

REQUIRED JSON SCHEMA:
{{
  "name": "string",
  "description": "string",
  "steps": [
    {{
      "id": "string",
      "description": "string",
      "request": {{
        "method": "string",
        "path": "string",
        "headers": {{"string": "string"}},
        "body": "string | null"
      }},
      "is_destructive": boolean
    }}
  ],
  "expected_signals": ["string"],
  "stop_conditions": ["string"]
}}
"""

    @staticmethod
    def build_prompt(graph: EndpointGraph) -> str:
        """Create the prompt injected with the endpoint graph context."""
        summary_lines = []
        for e in graph.endpoints:
            params = [p.get("name") for p in e.parameters if p.get("name")]
            summary_lines.append(f"- {e.method} {e.path} (params: {', '.join(params)})")  # type: ignore
        graph_summary = "\n".join(summary_lines)
        return ScenarioAgent.PROMPT_TEMPLATE.format(graph_summary=graph_summary)

    @staticmethod
    def parse_and_validate(json_str: str) -> ScenarioPlan:
        """Parses the generator output and executes a deterministic safety validation sequence."""
        data = json.loads(json_str.strip())
        plan = ScenarioPlan(**data)

        # Safety Validations
        for step in plan.steps:
            method = step.request.method.upper()

            # Method Check
            if method not in ["GET", "OPTIONS", "HEAD", "TRACE", "POST", "PUT", "PATCH", "DELETE"]:
                raise ValueError(f"Step '{step.id}' uses an unrecognized method: {method}")

            # Safety Flag Check (Mutative actions must be marked)
            is_mutative = method in ["POST", "PUT", "PATCH", "DELETE"]
            if is_mutative and not step.is_destructive:
                raise ValueError(
                    f"Step '{step.id}' uses mutative method {method} but 'is_destructive' is False. "
                    "All mutative operations must explicitly be marked destructive."
                )

            # Routing Check (Ensure relative routing bounding)
            if not step.request.path.startswith("/"):
                raise ValueError(
                    f"Step '{step.id}' has an invalid path '{step.request.path}'. "
                    "Paths must be absolute relative to the target base_url (starting with '/')."
                )

        return plan

    @staticmethod
    def generate_mock_response(graph: EndpointGraph) -> str:
        """A deterministic mock payload mimicking a generator output matching the constraints."""
        return json.dumps(
            {
                "name": "BOLA Sequence Test",
                "description": "Creates an object with Profile A, attempts to fetch it with Profile B.",
                "steps": [
                    {
                        "id": "step_1",
                        "description": "Create object",
                        "request": {
                            "method": "POST",
                            "path": "/users",
                            "headers": {"Content-Type": "application/json"},
                            "body": '{"name": "test"}',
                        },
                        "is_destructive": True,
                    },
                    {
                        "id": "step_2",
                        "description": "Fetch object",
                        "request": {"method": "GET", "path": "/users/123", "headers": {}},
                        "is_destructive": False,
                    },
                ],
                "expected_signals": ["201 Created on step_1", "403 Forbidden on step_2"],
                "stop_conditions": ["Failed to create object in step_1"],
            }
        )
