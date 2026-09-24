"""Full remote HITL flow over the API: intercept -> poll -> resolve -> poll -> redeem once."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from sentinel.core.gateway import SentinelGateway
from sentinel.sandbox.approval import ApprovalCoordinator, ApprovalStore
from sentinel.server.app import create_app

AGENT = {"X-API-Key": "agent-k"}
APPROVER = {"X-API-Key": "approver-k"}
CALL = {"tool_name": "execute_bash", "arguments": {"command": "rm -rf ./build"}}


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setenv("SENTINEL_AGENT_KEY", "agent-k")
    monkeypatch.setenv("SENTINEL_APPROVER_KEY", "approver-k")
    gw = SentinelGateway(approval_coordinator=ApprovalCoordinator(ApprovalStore(":memory:")))
    return TestClient(create_app(gw))


def test_full_flow(client):
    a = client.post("/api/v1/intercept", json=CALL, headers=AGENT).json()
    assert a["decision"] == "REQUIRE_APPROVAL"
    aid = a["approval_id"]

    assert client.get(f"/api/v1/approvals/{aid}", headers=AGENT).json()["status"] == "PENDING"
    assert [p["id"] for p in client.get("/api/v1/approvals/pending", headers=APPROVER).json()] == [aid]

    r = client.post(f"/api/v1/approvals/{aid}/resolve", json={"approve": True, "approver": "alice"}, headers=APPROVER)
    assert r.status_code == 200

    polled = client.get(f"/api/v1/approvals/{aid}", headers=AGENT).json()
    assert polled["status"] == "APPROVED" and polled["approval_token"]

    body = {**CALL, "token": polled["approval_token"]}
    assert client.post(f"/api/v1/approvals/{aid}/redeem", json=body, headers=AGENT).status_code == 200
    assert client.post(f"/api/v1/approvals/{aid}/redeem", json=body, headers=AGENT).status_code == 409

    swapped = {**body, "arguments": {"command": "rm -rf /"}}
    assert client.post(f"/api/v1/approvals/{aid}/redeem", json=swapped, headers=AGENT).status_code == 403


@pytest.mark.parametrize(
    "method, path, headers",
    [
        ("post", "/api/v1/intercept", {}),
        ("post", "/api/v1/intercept", APPROVER),  # roles are separate
        ("get", "/api/v1/approvals/pending", AGENT),  # an agent cannot see or resolve the queue
        ("post", "/api/v1/approvals/x/resolve", AGENT),
        ("get", "/api/v1/audit", AGENT),
    ],
)
def test_role_enforcement(client, method, path, headers):
    kwargs = {"json": CALL if "intercept" in path else {"approve": True}} if method == "post" else {}
    assert getattr(client, method)(path, headers=headers, **kwargs).status_code == 401


def test_unknown_approval_is_404(client):
    assert client.get("/api/v1/approvals/nope", headers=AGENT).status_code == 404


def test_health_is_open(client):
    assert client.get("/api/v1/health").json()["status"] == "healthy"
