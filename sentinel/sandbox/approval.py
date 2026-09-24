"""Human-in-the-Loop Approval Sandbox and Queue."""

from __future__ import annotations

import asyncio
import time
from collections.abc import Callable

from sentinel.core.types import (
    ApprovalRequest,
    ApprovalStatus,
    RiskAssessment,
    ToolCallRequest,
)


class ApprovalCoordinator:
    """Coordinates synchronous and asynchronous human sign-offs for high-risk actions."""

    def __init__(self, default_timeout: float = 30.0):
        self.default_timeout = default_timeout
        self.pending_requests: dict[str, ApprovalRequest] = {}
        self.completed_requests: dict[str, ApprovalRequest] = {}
        self._waiters: dict[str, asyncio.Event] = {}
        self.cli_prompt_handler: Callable[[ApprovalRequest], bool] | None = None

    def register_cli_handler(self, handler: Callable[[ApprovalRequest], bool]) -> None:
        self.cli_prompt_handler = handler

    def create_request(self, tool_call: ToolCallRequest, assessment: RiskAssessment) -> ApprovalRequest:
        req = ApprovalRequest(
            tool_call=tool_call,
            assessment=assessment,
            status=ApprovalStatus.PENDING,
        )
        self.pending_requests[req.id] = req
        self._waiters[req.id] = asyncio.Event()
        return req

    async def wait_for_decision(self, request_id: str, timeout: float | None = None) -> ApprovalRequest:
        timeout = timeout or self.default_timeout
        req = self.pending_requests.get(request_id)
        if not req:
            raise KeyError(f"Approval request {request_id} not found.")

        # If a CLI prompt handler is set (for synchronous CLI operation)
        if self.cli_prompt_handler:
            loop = asyncio.get_event_loop()
            approved = await loop.run_in_executor(None, self.cli_prompt_handler, req)
            if approved:
                return self.resolve(request_id, approve=True, approver="cli-user")
            else:
                return self.resolve(request_id, approve=False, approver="cli-user")

        # Otherwise wait for asynchronous webhook/UI event
        event = self._waiters.get(request_id)
        if not event:
            return req

        try:
            await asyncio.wait_for(event.wait(), timeout=timeout)
        except asyncio.TimeoutError:
            return self.resolve(request_id, approve=False, approver="system-timeout")

        return self.completed_requests.get(request_id, req)

    def resolve(self, request_id: str, approve: bool, approver: str = "human-operator") -> ApprovalRequest:
        req = self.pending_requests.pop(request_id, None)
        if not req:
            if request_id in self.completed_requests:
                return self.completed_requests[request_id]
            raise KeyError(f"Pending approval request {request_id} not found.")

        req.status = ApprovalStatus.APPROVED if approve else ApprovalStatus.REJECTED
        req.resolved_at = time.time()
        req.resolved_by = approver

        self.completed_requests[request_id] = req

        # Signal any waiting coroutines
        event = self._waiters.pop(request_id, None)
        if event:
            event.set()

        return req

    def list_pending(self) -> list[ApprovalRequest]:
        return list(self.pending_requests.values())

    def get_request(self, request_id: str) -> ApprovalRequest | None:
        return self.pending_requests.get(request_id) or self.completed_requests.get(request_id)
