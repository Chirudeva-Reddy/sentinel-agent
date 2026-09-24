"""Human-in-the-loop approvals: shared store, call-bound HMAC tokens, single-use redemption.

An approval authorises exactly one call: the request stores a digest of (tool, arguments) and the
token issued on approval is HMAC(key, id|digest|expiry|approver). Redeeming checks the MAC, the
expiry, that the call being executed has the same digest, and burns the token.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import sqlite3
import threading
import time
import urllib.request
from collections.abc import Callable
from pathlib import Path

from sentinel.core.types import ApprovalRequest, ApprovalStatus, RiskAssessment, ToolCallRequest
from sentinel.normalize import fold_tool_name
from sentinel.settings import secret_key, sentinel_home

log = logging.getLogger(__name__)

Notifier = Callable[[ApprovalRequest], None]


class ApprovalError(Exception):
    """The approval can't authorise this execution (pending, rejected, expired, forged or used)."""


class DigestMismatch(ApprovalError):
    """The call being executed is not the call that was approved."""


def call_digest(call: ToolCallRequest) -> str:
    """Canonical sha256 over the folded tool name and key-sorted arguments."""
    body = json.dumps(
        [fold_tool_name(call.tool_name), call.arguments], sort_keys=True, separators=(",", ":"), default=str
    )
    return hashlib.sha256(body.encode()).hexdigest()


class ApprovalStore:
    """SQLite-backed approval queue shared by the API, dashboard and CLI.

    Pass ":memory:" for a private in-process store (tests). ponytail: waiters poll; switch to Redis
    pub/sub or Postgres LISTEN if sub-100ms approval latency or many API replicas matter.
    """

    def __init__(self, path: str | Path | None = None) -> None:
        self.path = str(path or sentinel_home() / "approvals.db")
        self._lock = threading.Lock()
        self._db = sqlite3.connect(self.path, check_same_thread=False, isolation_level=None, timeout=10)
        if self.path != ":memory:":
            self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute(
            "CREATE TABLE IF NOT EXISTS approvals ("
            " id TEXT PRIMARY KEY, status TEXT NOT NULL, created_at REAL NOT NULL, data TEXT NOT NULL,"
            " token_used INTEGER NOT NULL DEFAULT 0)"
        )

    def close(self) -> None:
        self._db.close()

    __del__ = close

    def add(self, req: ApprovalRequest) -> None:
        with self._lock:
            self._db.execute(
                "INSERT INTO approvals (id, status, created_at, data) VALUES (?, ?, ?, ?)",
                (req.id, req.status.value, req.created_at, req.model_dump_json()),
            )

    def get(self, request_id: str) -> ApprovalRequest | None:
        with self._lock:
            row = self._db.execute("SELECT data FROM approvals WHERE id = ?", (request_id,)).fetchone()
        return ApprovalRequest.model_validate_json(row[0]) if row else None

    def pending(self) -> list[ApprovalRequest]:
        with self._lock:
            rows = self._db.execute(
                "SELECT data FROM approvals WHERE status = 'PENDING' ORDER BY created_at"
            ).fetchall()
        return [ApprovalRequest.model_validate_json(r[0]) for r in rows]

    def finish(self, req: ApprovalRequest) -> bool:
        """Move a PENDING request to its final state. False if someone else resolved it first."""
        with self._lock:
            cur = self._db.execute(
                "UPDATE approvals SET status = ?, data = ? WHERE id = ? AND status = 'PENDING'",
                (req.status.value, req.model_dump_json(), req.id),
            )
        return cur.rowcount == 1

    def burn_token(self, request_id: str) -> bool:
        """Mark the token used. False if it already was (replay)."""
        with self._lock:
            cur = self._db.execute("UPDATE approvals SET token_used = 1 WHERE id = ? AND token_used = 0", (request_id,))
        return cur.rowcount == 1


def webhook_notifier(url: str, timeout: float = 5.0) -> Notifier:
    """Posts a Slack-compatible {"text": ...} message per pending approval, off the request path."""

    def send(req: ApprovalRequest) -> None:
        text = (
            f":warning: Sentinel approval needed for `{req.tool_call.tool_name}` "
            f"(score {req.assessment.overall_score}): {req.assessment.reason}\nApproval id: {req.id}"
        )
        body = json.dumps({"text": text, "approval_id": req.id}).encode()
        http = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"})

        def post() -> None:
            try:
                urllib.request.urlopen(http, timeout=timeout).close()  # noqa: S310 - operator-configured URL
            except OSError as exc:
                log.warning("approval webhook failed: %s", exc)

        threading.Thread(target=post, daemon=True).start()

    return send


class ApprovalCoordinator:
    """Creates, resolves and redeems approvals against a (possibly shared) ApprovalStore."""

    def __init__(
        self,
        store: ApprovalStore | None = None,
        default_timeout: float = 30.0,
        token_ttl: float = 300.0,
        poll_interval: float = 0.2,
        notifier: Notifier | None = None,
        key: bytes | None = None,
    ) -> None:
        self.store = store or ApprovalStore()
        self.default_timeout = default_timeout
        self.token_ttl = token_ttl
        self.poll_interval = poll_interval
        self.notifier = notifier
        self._key = key or secret_key("approval")
        self.cli_prompt_handler: Callable[[ApprovalRequest], bool] | None = None

    def register_cli_handler(self, handler: Callable[[ApprovalRequest], bool]) -> None:
        self.cli_prompt_handler = handler

    def _sign(self, req: ApprovalRequest) -> str:
        msg = f"{req.id}|{req.call_digest}|{req.token_expires_at}|{req.resolved_by}".encode()
        return hmac.new(self._key, msg, hashlib.sha256).hexdigest()

    def create_request(self, tool_call: ToolCallRequest, assessment: RiskAssessment) -> ApprovalRequest:
        req = ApprovalRequest(tool_call=tool_call, assessment=assessment, call_digest=call_digest(tool_call))
        self.store.add(req)
        if self.notifier:
            try:
                self.notifier(req)
            except Exception:  # noqa: BLE001 - a broken notifier must not break interception
                log.exception("approval notifier failed")
        return req

    def resolve(self, request_id: str, approve: bool, approver: str = "human-operator") -> ApprovalRequest:
        return self._finish(request_id, ApprovalStatus.APPROVED if approve else ApprovalStatus.REJECTED, approver)

    def _finish(self, request_id: str, status: ApprovalStatus, approver: str) -> ApprovalRequest:
        req = self.store.get(request_id)
        if req is None:
            raise KeyError(f"Approval request {request_id} not found.")
        if req.status != ApprovalStatus.PENDING:
            return req
        req.status, req.resolved_at, req.resolved_by = status, time.time(), approver
        if status == ApprovalStatus.APPROVED:
            req.token_expires_at = req.resolved_at + self.token_ttl
            req.approval_token = self._sign(req)
        if not self.store.finish(req):  # lost a race with another resolver: theirs stands
            return self.store.get(request_id) or req
        return req

    async def wait_for_decision(self, request_id: str, timeout: float | None = None) -> ApprovalRequest:
        req = self.store.get(request_id)
        if req is None:
            raise KeyError(f"Approval request {request_id} not found.")

        if self.cli_prompt_handler:
            approved = await asyncio.get_running_loop().run_in_executor(None, self.cli_prompt_handler, req)
            return self.resolve(request_id, approve=approved, approver="cli-user")

        deadline = time.monotonic() + (timeout or self.default_timeout)
        while req.status == ApprovalStatus.PENDING:
            if time.monotonic() >= deadline:
                return self._finish(request_id, ApprovalStatus.EXPIRED, "system-timeout")
            await asyncio.sleep(self.poll_interval)
            req = self.store.get(request_id) or req
        return req

    def redeem(self, request_id: str, token: str, call: ToolCallRequest) -> ApprovalRequest:
        """Authorise executing `call` under approval `request_id`. Raises ApprovalError otherwise."""
        req = self.store.get(request_id)
        if req is None:
            raise ApprovalError("unknown approval")
        if req.status != ApprovalStatus.APPROVED or not req.approval_token:
            raise ApprovalError(f"approval is {req.status.value}")
        if not hmac.compare_digest(self._sign(req), token or ""):
            raise ApprovalError("invalid token")
        if req.token_expires_at is None or time.time() > req.token_expires_at:
            raise ApprovalError("token expired")
        if not hmac.compare_digest(call_digest(call), req.call_digest):
            raise DigestMismatch("call differs from the approved call")
        if not self.store.burn_token(request_id):
            raise ApprovalError("token already used")
        return req

    def list_pending(self) -> list[ApprovalRequest]:
        return self.store.pending()

    def get_request(self, request_id: str) -> ApprovalRequest | None:
        return self.store.get(request_id)
