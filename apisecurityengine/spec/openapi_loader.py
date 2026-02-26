import json
import re
from pathlib import Path
from typing import Any

import httpx
import yaml

from apisecurityengine.spec.endpoint_graph import EndpointGraph, EndpointNode


class OpenAPILoader:
    """Parser specifically for OpenAPI v2 and v3 standard specs."""

    @staticmethod
    def load(path_or_url: str) -> dict[str, Any]:
        """Load an OpenAPI spec from a local path or remote URL."""
        content: str = ""
        if path_or_url.startswith("http://") or path_or_url.startswith("https://"):
            response = httpx.get(path_or_url, timeout=10.0)
            response.raise_for_status()
            content = response.text
        else:
            with Path(path_or_url).open(encoding="utf-8") as f:
                content = f.read()

        try:
            parsed: dict[str, Any] = json.loads(content)
            return parsed
        except json.JSONDecodeError:
            parsed = yaml.safe_load(content)
            if not isinstance(parsed, dict):
                raise ValueError("Parsed YAML is not an OpenAPI dictionary")
            return parsed

    @staticmethod
    def build_graph(spec: dict[str, Any]) -> EndpointGraph:
        """Parses the OpenAPI document mapping routes to an EndpointGraph."""
        graph = EndpointGraph()

        global_security = spec.get("security", [])
        paths = spec.get("paths", {})

        id_pattern = re.compile(r"(?i)(id|uuid|account|user|tenant)")

        for path, path_item in paths.items():
            if not isinstance(path_item, dict):
                continue

            # extract path level parameters to distribute across operations
            path_level_params = path_item.get("parameters", [])
            if not isinstance(path_level_params, list):
                path_level_params = []

            for method, operation in path_item.items():
                if not isinstance(operation, dict):
                    continue

                if method.lower() not in [
                    "get",
                    "post",
                    "put",
                    "patch",
                    "delete",
                    "options",
                    "head",
                    "trace",
                ]:
                    continue

                method = method.upper()

                op_id = operation.get("operationId")

                # Combine parameters (naive extension without resolving $refs for MVP)
                op_params = operation.get("parameters", [])
                if not isinstance(op_params, list):
                    op_params = []

                parameters = path_level_params + op_params

                req_body = operation.get("requestBody")
                responses = operation.get("responses", {})

                # Check operations heuristics
                is_read = method in ["GET", "HEAD", "OPTIONS"]
                is_write = method in ["POST", "PUT", "PATCH"]
                is_destructive = method == "DELETE"

                # Override with keyword scanning for destructive operations
                combined_text = f"{path} {op_id or ''}".lower()
                if (
                    "delete" in combined_text
                    or "remove" in combined_text
                    or "destroy" in combined_text
                ):
                    is_destructive = True
                    is_read = False
                    is_write = False

                # Authentication requirements check
                op_security = operation.get("security")
                requires_auth = False
                if op_security is not None:
                    if len(op_security) > 0:
                        requires_auth = True
                elif len(global_security) > 0:
                    requires_auth = True

                # Likely Identifier Extractions
                identifiers = []
                for p in parameters:
                    if not isinstance(p, dict):
                        continue
                    name = p.get("name", "")
                    in_field = p.get("in", "")
                    if id_pattern.search(name) and in_field in ["path", "query", "header"]:
                        identifiers.append(name)

                # Append node directly to graph
                node = EndpointNode(
                    path=path,
                    method=method,
                    operation_id=op_id,
                    parameters=parameters,  # Type ignores might be needed until proper strict parsing is applied
                    request_body=req_body,
                    responses=responses,
                    is_read=is_read,
                    is_write=is_write,
                    is_destructive=is_destructive,
                    requires_auth=requires_auth,
                    likely_object_identifiers=list(set(identifiers)),
                )
                graph.endpoints.append(node)

        return graph
