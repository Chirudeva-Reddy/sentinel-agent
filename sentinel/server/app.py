"""FastAPI Server for SentinelAgent Gateway, Approvals, and Audit."""

from __future__ import annotations

import os
import secrets
import time
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel

from sentinel.core.gateway import SentinelGateway
from sentinel.core.types import (
    ApprovalRequest,
    AuditRecord,
    RiskAssessment,
    ToolCallRequest,
)

app = FastAPI(
    title="SentinelAgent API",
    description="Zero-Trust Security Gateway & Governance API for Autonomous AI Agents",
    version="0.1.0",
)

gateway = SentinelGateway()


def require_api_key(x_api_key: str = Header(default="")) -> None:
    """Approver credential. Fails closed: with no SENTINEL_API_KEY configured, nobody can resolve."""
    expected = os.environ.get("SENTINEL_API_KEY", "")
    if not expected or not secrets.compare_digest(x_api_key.encode(), expected.encode()):
        raise HTTPException(status_code=401, detail="Missing or invalid X-API-Key")


class ResolveApprovalPayload(BaseModel):
    approve: bool
    approver: str = "security-officer"
    reason: str | None = None


@app.get("/api/v1/health")
def health_check() -> dict[str, Any]:
    valid, err = gateway.ledger.verify_integrity()
    return {
        "status": "healthy",
        "ledger_entries": len(gateway.ledger.records),
        "ledger_cryptographically_valid": valid,
        "integrity_error": err,
        "timestamp": time.time(),
    }


@app.post("/api/v1/intercept", response_model=RiskAssessment)
def intercept_tool_call(request: ToolCallRequest) -> RiskAssessment:
    """Interception endpoint for agent frameworks and MCP servers."""
    return gateway.inspect(request)


@app.get("/api/v1/approvals/pending", response_model=list[ApprovalRequest])
def list_pending_approvals() -> list[ApprovalRequest]:
    """Retrieves all high-risk tool calls currently waiting for human approval."""
    return gateway.approval.list_pending()


@app.post("/api/v1/approvals/{request_id}/resolve", dependencies=[Depends(require_api_key)])
def resolve_approval(request_id: str, payload: ResolveApprovalPayload) -> dict[str, Any]:
    """Human-in-the-loop authorization endpoint."""
    try:
        req = gateway.approval.resolve(
            request_id=request_id,
            approve=payload.approve,
            approver=payload.approver,
        )
        return {
            "status": "resolved",
            "approval_status": req.status.value,
            "resolved_at": req.resolved_at,
            "resolved_by": req.resolved_by,
        }
    except KeyError:
        raise HTTPException(status_code=404, detail=f"Approval request {request_id} not found.") from None


@app.get("/api/v1/audit", response_model=list[AuditRecord])
def get_audit_records(limit: int = 50) -> list[AuditRecord]:
    """Returns recent cryptographic audit records."""
    return gateway.ledger.get_recent(limit=limit)
