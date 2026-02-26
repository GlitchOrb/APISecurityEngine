import json

import pytest

from apisecurityengine.ai.scenario_agent import ScenarioAgent
from apisecurityengine.spec.endpoint_graph import EndpointGraph, EndpointNode


@pytest.fixture
def mock_graph() -> EndpointGraph:
    graph = EndpointGraph()
    graph.endpoints.append(
        EndpointNode(path="/users", method="POST", is_destructive=True, is_write=True)
    )
    graph.endpoints.append(EndpointNode(path="/users/1", method="GET", is_read=True))
    return graph


def test_build_prompt(mock_graph: EndpointGraph) -> None:
    prompt = ScenarioAgent.build_prompt(mock_graph)
    assert "- POST /users" in prompt
    assert "- GET /users/1" in prompt


def test_valid_scenario_parsing(mock_graph: EndpointGraph) -> None:
    json_str = ScenarioAgent.generate_mock_response(mock_graph)
    plan = ScenarioAgent.parse_and_validate(json_str)

    assert plan.name == "BOLA Sequence Test"
    assert len(plan.steps) == 2
    assert plan.steps[0].request.method == "POST"
    assert plan.steps[0].is_destructive is True
    assert plan.steps[1].request.method == "GET"
    assert plan.steps[1].is_destructive is False


def test_invalid_path_rejection() -> None:
    # Path missing leading slash
    bad_json = json.dumps(
        {
            "name": "Bad Path",
            "description": "",
            "steps": [
                {
                    "id": "1",
                    "description": "",
                    "request": {"method": "GET", "path": "users", "headers": {}},
                    "is_destructive": False,
                }
            ],
            "expected_signals": [],
            "stop_conditions": [],
        }
    )

    with pytest.raises(ValueError, match="must be absolute relative"):
        ScenarioAgent.parse_and_validate(bad_json)


def test_unsafe_method_rejection() -> None:
    # POST without is_destructive tracking
    unsafe_json = json.dumps(
        {
            "name": "Unsafe Post",
            "description": "",
            "steps": [
                {
                    "id": "1",
                    "description": "",
                    "request": {"method": "POST", "path": "/users", "headers": {}},
                    "is_destructive": False,  # Must be True
                }
            ],
            "expected_signals": [],
            "stop_conditions": [],
        }
    )

    with pytest.raises(ValueError, match="is_destructive' is False"):
        ScenarioAgent.parse_and_validate(unsafe_json)
