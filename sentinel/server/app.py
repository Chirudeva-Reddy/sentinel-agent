"""FastAPI server: interception, remote HITL approvals and audit, with separate agent/approver keys.

Run: SENTINEL_AGENT_KEY=... SENTINEL_APPROVER_KEY=... uvicorn sentinel.server.app:app
"""

from __future__ import annotations

import os
import secrets
import time
from collections.abc import Callable
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel

from sentinel.core.gateway import SentinelGateway
from sentinel.core.types import (
    ApprovalRequest,
    AuditRecord,
    DecisionAction,
    ResultAssessment,
    RiskAssessment,
    ToolCallRequest,
)
from sentinel.sandbox.approval import ApprovalCoordinator, ApprovalError, DigestMismatch, webhook_notifier


def require_role(role: str) -> Callable[..., None]:
    """X-API-Key must equal $SENTINEL_<ROLE>_KEY. Fails closed: no key configured means no access."""
    env = f"SENTINEL_{role.upper()}_KEY"

    def check(x_api_key: str = Header(default="")) -> None:
        expected = os.environ.get(env, "")
        if not expected or not secrets.compare_digest(x_api_key.encode(), expected.encode()):
            raise HTTPException(status_code=401, detail=f"Missing or invalid X-API-Key for role '{role}'")

    return check


agent = Depends(require_role("agent"))
approver = Depends(require_role("approver"))


class ResolvePayload(BaseModel):
    approve: bool
    approver: str = "security-officer"
    reason: str | None = None


class ResultPayload(BaseModel):
    tool_call: ToolCallRequest
    """The call that produced the output; its session_id links the output to later calls for taint tracking."""
    result: Any = None


class RedeemPayload(BaseModel):
    tool_name: str
    arguments: dict[str, Any]
    token: str


def _default_gateway() -> SentinelGateway:
    url = os.environ.get("SENTINEL_WEBHOOK_URL")
    return SentinelGateway(approval_coordinator=ApprovalCoordinator(notifier=webhook_notifier(url) if url else None))


def create_app(gateway: SentinelGateway | None = None) -> FastAPI:
    gw = gateway or _default_gateway()
    app = FastAPI(
        title="SentinelAgent API",
        description="Zero-Trust Security Gateway & Governance API for Autonomous AI Agents",
        version="0.2.0",
    )
    app.state.gateway = gw

    def _get(request_id: str) -> ApprovalRequest:
        req = gw.approval.get_request(request_id)
        if req is None:
            raise HTTPException(status_code=404, detail=f"Approval request {request_id} not found.")
        return req

    @app.get("/api/v1/health")
    def health() -> dict[str, Any]:
        valid, err = gw.ledger.verify_integrity()
        return {
            "status": "healthy",
            "ledger_entries": len(gw.ledger.records),
            "ledger_valid": valid,
            "integrity_error": err,
            "timestamp": time.time(),
        }

    @app.get("/metrics", response_class=PlainTextResponse)
    def metrics() -> str:
        """Prometheus text format. Counts only, no call contents."""
        st = gw.stats
        lines = ["# TYPE sentinel_decisions_total counter"]
        lines += [
            f'sentinel_decisions_total{{decision="{d.value}"}} {st[f"decision:{d.value}"]}' for d in DecisionAction
        ]
        lines += [
            "# TYPE sentinel_tool_results_total counter",
            f'sentinel_tool_results_total{{injection="true"}} {st["results:true"]}',
            f'sentinel_tool_results_total{{injection="false"}} {st["results:false"]}',
            "# TYPE sentinel_detector_errors_total counter",
            f"sentinel_detector_errors_total {st['detector_errors']}",
            "# TYPE sentinel_inspect_latency_ms summary",
            f"sentinel_inspect_latency_ms_sum {st['latency_ms_sum']:.3f}",
            f"sentinel_inspect_latency_ms_count {st['latency_ms_count']}",
            "# TYPE sentinel_pending_approvals gauge",
            f"sentinel_pending_approvals {len(gw.approval.list_pending())}",
        ]
        return "\n".join(lines) + "\n"

    # --- approver role (static paths first so "pending" is not read as an approval id) ---

    @app.get("/api/v1/approvals/pending", response_model=list[ApprovalRequest], dependencies=[approver])
    def pending() -> list[ApprovalRequest]:
        return gw.approval.list_pending()

    # --- agent role ---

    @app.post("/api/v1/intercept", response_model=RiskAssessment, dependencies=[agent])
    def intercept(request: ToolCallRequest) -> RiskAssessment:
        return gw.inspect(request)

    @app.post("/api/v1/results", response_model=ResultAssessment, dependencies=[agent])
    def guard_result(body: ResultPayload) -> ResultAssessment:
        """Send tool output here before giving it to the model: it is scanned, fenced if untrusted, and
        fingerprinted so later calls in the same session_id are checked against it."""
        return gw.inspect_result(body.tool_call, body.result)

    @app.get("/api/v1/approvals/{request_id}", dependencies=[agent])
    def poll(request_id: str) -> dict[str, Any]:
        """Agent polls its approval. The token appears once APPROVED and only authorises the approved call."""
        req = _get(request_id)
        return {
            "id": req.id,
            "status": req.status.value,
            "resolved_by": req.resolved_by,
            "approval_token": req.approval_token,
            "token_expires_at": req.token_expires_at,
        }

    @app.post("/api/v1/approvals/{request_id}/redeem", dependencies=[agent])
    def redeem(request_id: str, body: RedeemPayload) -> dict[str, Any]:
        """Exchange a token for permission to run exactly the approved call, once."""
        call = ToolCallRequest(tool_name=body.tool_name, arguments=body.arguments)
        try:
            req = gw.approval.redeem(request_id, body.token, call)
        except DigestMismatch as exc:
            gw.ledger.append("APPROVAL_DIGEST_MISMATCH", {"approval_id": request_id, "tool_name": body.tool_name})
            raise HTTPException(status_code=403, detail=str(exc)) from None
        except ApprovalError as exc:
            code = 409 if "already used" in str(exc) else 403
            raise HTTPException(status_code=code, detail=str(exc)) from None
        gw.ledger.append("APPROVAL_REDEEMED", {"approval_id": req.id, "tool_name": body.tool_name})
        return {"authorized": True, "approval_id": req.id}

    @app.post("/api/v1/approvals/{request_id}/resolve", dependencies=[approver])
    def resolve(request_id: str, payload: ResolvePayload) -> dict[str, Any]:
        _get(request_id)
        req = gw.approval.resolve(request_id, approve=payload.approve, approver=payload.approver)
        gw.ledger.append(
            f"APPROVAL_{req.status.value}",
            {"approval_id": req.id, "by": req.resolved_by, "reason": payload.reason},
        )
        return {"status": "resolved", "approval_status": req.status.value, "resolved_by": req.resolved_by}

    @app.get("/api/v1/audit", response_model=list[AuditRecord], dependencies=[approver])
    def audit(limit: int = 50) -> list[AuditRecord]:
        return gw.ledger.get_recent(limit=limit)

    return app


def __getattr__(name: str) -> Any:
    # `uvicorn sentinel.server.app:app` builds the app on first access, not at import time,
    # so importing this module (e.g. in tests) never touches SENTINEL_HOME.
    if name == "app":
        return create_app()
    raise AttributeError(name)
