"""Issue 2: anyone could resolve an approval; no credential was checked."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from sentinel.core.types import ToolCallRequest
from sentinel.server import app as server


@pytest.fixture
def client_and_id(monkeypatch):
    monkeypatch.setenv("SENTINEL_API_KEY", "k-test")
    a = server.gateway.inspect(ToolCallRequest(tool_name="execute_bash", arguments={"command": "rm -rf /"}))
    return TestClient(server.app), a.approval_id


def test_resolve_without_key_is_401(client_and_id):
    client, aid = client_and_id
    assert client.post(f"/api/v1/approvals/{aid}/resolve", json={"approve": True}).status_code == 401


def test_resolve_with_wrong_key_is_401(client_and_id):
    client, aid = client_and_id
    r = client.post(f"/api/v1/approvals/{aid}/resolve", json={"approve": True}, headers={"X-API-Key": "nope"})
    assert r.status_code == 401


def test_resolve_with_key_succeeds(client_and_id):
    client, aid = client_and_id
    r = client.post(f"/api/v1/approvals/{aid}/resolve", json={"approve": True}, headers={"X-API-Key": "k-test"})
    assert r.status_code == 200


def test_no_key_configured_fails_closed(client_and_id, monkeypatch):
    client, aid = client_and_id
    monkeypatch.delenv("SENTINEL_API_KEY")
    r = client.post(f"/api/v1/approvals/{aid}/resolve", json={"approve": True}, headers={"X-API-Key": ""})
    assert r.status_code == 401
