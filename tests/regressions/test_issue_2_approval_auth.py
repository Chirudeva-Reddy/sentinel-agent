"""Issue 2: anyone could resolve an approval; no credential was checked."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from sentinel.core.gateway import SentinelGateway
from sentinel.core.types import ToolCallRequest
from sentinel.sandbox.approval import ApprovalCoordinator, ApprovalStore
from sentinel.server.app import create_app


@pytest.fixture
def client_and_id(monkeypatch):
    monkeypatch.setenv("SENTINEL_APPROVER_KEY", "k-test")
    gw = SentinelGateway(approval_coordinator=ApprovalCoordinator(ApprovalStore(":memory:")))
    a = gw.inspect(ToolCallRequest(tool_name="execute_bash", arguments={"command": "rm -rf /"}))
    return TestClient(create_app(gw)), a.approval_id


def _resolve(client, aid, **headers):
    return client.post(f"/api/v1/approvals/{aid}/resolve", json={"approve": True}, headers=headers)


def test_resolve_without_key_is_401(client_and_id):
    assert _resolve(*client_and_id).status_code == 401


def test_resolve_with_wrong_key_is_401(client_and_id):
    assert _resolve(*client_and_id, **{"X-API-Key": "nope"}).status_code == 401


def test_resolve_with_key_succeeds(client_and_id):
    assert _resolve(*client_and_id, **{"X-API-Key": "k-test"}).status_code == 200


def test_no_key_configured_fails_closed(client_and_id, monkeypatch):
    monkeypatch.delenv("SENTINEL_APPROVER_KEY")
    assert _resolve(*client_and_id, **{"X-API-Key": ""}).status_code == 401
