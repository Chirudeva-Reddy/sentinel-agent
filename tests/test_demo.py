"""Multi-agent demo, offline: the scripted researcher falls for the injection; the defences must hold."""

from __future__ import annotations

import os

import pytest

from sentinel.demo import ScriptedModel, run_demo


async def _yes(req, review):
    return True


async def _no(req, review):
    return False


async def test_exfiltration_blocked_and_legit_email_sent_after_human_ok():
    log: list[str] = []
    result = await run_demo(ScriptedModel(), _yes, log.append)
    assert [m["to"] for m in result["outbox"]] == ["team@example.com"]
    assert any("[reviewer] send_email -> reject" in line for line in log)
    assert any("[reviewer] send_email -> escalate" in line for line in log)
    assert result["ledger_valid"]
    assert result["ledger_events"].count("APPROVAL_REJECTED") >= 1


async def test_nothing_is_sent_when_the_human_denies():
    result = await run_demo(ScriptedModel(), _no, lambda _: None)
    assert result["outbox"] == []


@pytest.mark.skipif(not os.environ.get("ANTHROPIC_API_KEY"), reason="live Claude run needs ANTHROPIC_API_KEY")
@pytest.mark.slow
async def test_live_agents_never_email_outside():
    from sentinel.demo import LiveModel

    result = await run_demo(LiveModel(), _yes, print)
    assert all(m["to"].endswith("@example.com") for m in result["outbox"])


async def test_live_model_request_shape_against_local_fake_api(monkeypatch):
    """Real SDK serialisation/parsing against a local stand-in for the Messages API (no network, no key)."""
    import json as _json
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    from sentinel.core.gateway import SentinelGateway
    from sentinel.demo import RESEARCHER, LiveModel, World, demo_policy
    from sentinel.sandbox.approval import ApprovalCoordinator, ApprovalStore

    bodies: list[dict] = []
    replies = [
        {
            "stop_reason": "tool_use",
            "content": [
                {
                    "type": "tool_use",
                    "id": "toolu_1",
                    "name": "fetch_url",
                    "input": {"url": "https://intranet.example/q3"},
                }
            ],
        },
        {"stop_reason": "end_turn", "content": [{"type": "text", "text": "Startup is faster."}]},
    ]

    class Fake(BaseHTTPRequestHandler):
        def do_POST(self):
            bodies.append(_json.loads(self.rfile.read(int(self.headers["content-length"]))))
            reply = {
                "id": "msg_1",
                "type": "message",
                "role": "assistant",
                "model": "claude-opus-5",
                "stop_sequence": None,
                "usage": {"input_tokens": 1, "output_tokens": 1},
                **replies[len(bodies) - 1],
            }
            data = _json.dumps(reply).encode()
            self.send_response(200)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Fake)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test")
    monkeypatch.setenv("ANTHROPIC_BASE_URL", f"http://127.0.0.1:{server.server_port}")
    try:
        gw = SentinelGateway(policy=demo_policy(), approval_coordinator=ApprovalCoordinator(ApprovalStore(":memory:")))
        notes = await RESEARCHER.run(LiveModel(), gw, World(), "summarise", "s", lambda _: None)
    finally:
        server.shutdown()

    assert notes == "Startup is faster."
    first, second = bodies
    assert first["model"] == "claude-opus-5" and first["fallbacks"] == "default"
    assert {t["name"] for t in first["tools"]} == {"fetch_url", "read_file"} and first["tools"][0]["strict"] is True
    result = second["messages"][-1]["content"][0]
    assert result["type"] == "tool_result" and result["tool_use_id"] == "toolu_1"
    assert "<<untrusted-data" in result["content"]  # the model got the fenced page, not the raw one
