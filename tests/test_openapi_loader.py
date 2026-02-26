from pathlib import Path

import pytest
from httpx import RequestError

from apisecurityengine.spec.openapi_loader import OpenAPILoader


def test_openapi_loader_with_fixture() -> None:
    fixture_path = Path("tests/fixtures/example_openapi_v3.yaml").resolve()
    assert fixture_path.exists(), "Fixture does not exist"

    spec = OpenAPILoader.load(str(fixture_path))
    graph = OpenAPILoader.build_graph(spec)

    assert graph.total_endpoints() == 6
    assert graph.total_read() == 3  # GET /users, GET /users/{userId}, GET /public/ping
    assert graph.total_write() == 2  # POST /users, POST /accounts/{accountId}/transfer
    assert graph.total_destructive() == 1  # DELETE /users/{userId}

    # Verify authorization mechanics (global vs override)
    auth_endpoints = [e for e in graph.endpoints if e.requires_auth]
    assert len(auth_endpoints) == 5

    ping_endpoint = next((e for e in graph.endpoints if e.path == "/public/ping"), None)
    assert ping_endpoint is not None
    assert ping_endpoint.requires_auth is False

    # Check identifier extractions
    delete_user = next(
        (e for e in graph.endpoints if e.path == "/users/{userId}" and e.method == "DELETE"), None
    )
    assert delete_user is not None
    assert "userId" in delete_user.likely_object_identifiers

    transfer = next(
        (e for e in graph.endpoints if e.path == "/accounts/{accountId}/transfer"), None
    )
    assert transfer is not None
    assert "accountId" in transfer.likely_object_identifiers


def test_openapi_loader_invalid_file() -> None:
    with pytest.raises(FileNotFoundError):
        OpenAPILoader.load("does_not_exist.yaml")


def test_openapi_loader_invalid_url() -> None:
    # Testing an unreachable URL throws HTTPStatusError
    with pytest.raises(RequestError):
        OpenAPILoader.load("https://httpstat.us/404")
