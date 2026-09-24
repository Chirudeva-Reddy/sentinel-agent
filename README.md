<div align="center">

# 🛡️ SentinelAgent

**A deny-by-default security gateway, human-approval sandbox and MCP proxy for AI agents**

[![CI](https://github.com/Chirudeva-Reddy/sentinel-agent/actions/workflows/ci.yml/badge.svg)](https://github.com/Chirudeva-Reddy/sentinel-agent/actions)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.13-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

[Why](#why) • [Quickstart](#quickstart) • [How it works](#how-it-works) • [Evaluation](#evaluation) • [Architecture](docs/ARCHITECTURE.md)

</div>

---

## Why

An agent with shell, database, email and browser tools can be steered by anything it reads. SentinelAgent sits
between the agent and its tools and checks **both directions**:

- **Calls going out.** Each tool call is normalized (Unicode, URL-decoding, a 64 KB cap), scored by pluggable detectors, and
  checked against a YAML policy that denies unknown tools by default. Risky calls pause until a human approves
  exactly that call.
- **Results coming back.** Output from untrusted sources (web, email, files) is scanned, wrapped as data, and
  fingerprinted. If that data, or a session that has seen an injection attempt, later reaches a high-risk sink
  like `send_email`, a human has to approve it. This is how indirect prompt injection actually arrives.

## Features

| | |
|---|---|
| **Detectors** | Prompt injection / jailbreak (bounded regexes, base64), blast radius (shell parsed to argv, so `rm -r -f /`, `find / -delete` and `curl … \| sh` are caught under any tool name), argument validation (SSRF parsed with `ipaddress`: decimal/hex/octal/IPv6/v4-mapped/private ranges). Detectors are entry-point plugins; a crashing or slow detector fails closed. |
| **Policy** | One YAML schema (`sentinel/policies/default.yaml`), unknown keys rejected, profiles `default` / `dev` / `strict`. Unknown tools get `REQUIRE_APPROVAL` or `BLOCK`, never `ALLOW`. |
| **Human approval** | Each approval is bound to a SHA-256 digest of the exact call. The HMAC token expires and works once. Arguments swapped during the wait are refused. Approvals live in a shared SQLite store used by the API, dashboard, CLI and MCP proxy. Agent and approver keys are separate. Optional Slack-compatible webhook. |
| **Output guard + taint** | `inspect_result()` spotlights untrusted output. Per-session taint tracking gates high-risk sinks. |
| **Audit ledger** | Append-only JSONL, HMAC-SHA256 chained with sequence numbers and a signed head (detects edits, deletion, reordering, truncation), file-locked for concurrent writers, secrets redacted before writing. |
| **Integrations** | `sentinel mcp-proxy` (official MCP SDK) in front of any MCP server; an OpenAI-style function-calling wrapper; FastAPI server with `/metrics`; Streamlit dashboard as an API client. |

## Quickstart

```bash
git clone https://github.com/Chirudeva-Reddy/sentinel-agent.git && cd sentinel-agent
uv sync --all-extras          # or: pip install -e ".[server,dashboard,mcp]"
```

```bash
sentinel inspect --tool run_shell --args '{"cmd": "rm -r -f /"}'   # REQUIRE_APPROVAL, recursive rm of /
sentinel eval                                                      # detection / false-positive rates
sentinel verify-ledger                                             # HMAC chain + head check
```

### Put it in front of an MCP server

```jsonc
// Claude Desktop / any MCP client config
{ "mcpServers": { "files": {
    "command": "sentinel",
    "args": ["mcp-proxy", "--", "npx", "-y", "@modelcontextprotocol/server-filesystem", "/Users/me/projects"]
} } }
```

Blocked calls return an error to the model. Calls that need approval wait until someone approves them in the dashboard or API
(same `SENTINEL_HOME`), and tool output reaches the model fenced as untrusted data.

### Run the API and dashboard

```bash
export SENTINEL_AGENT_KEY=... SENTINEL_APPROVER_KEY=...
uvicorn sentinel.server.app:app --port 8000
SENTINEL_API_URL=http://localhost:8000 sentinel dashboard
# or: docker compose -f docker/docker-compose.yml up   (needs the four SENTINEL_*_KEY vars)
```

Agents call `POST /api/v1/intercept`, poll `GET /api/v1/approvals/{id}`, and exchange the token at
`POST /api/v1/approvals/{id}/redeem` before running the tool. Approvers use `/approvals/pending` and `/resolve`.

### In Python

```python
from sentinel.core.gateway import SentinelGateway

gateway = SentinelGateway()

# Checks the call, waits for approval if needed, runs exactly the approved arguments, guards the output.
out = await gateway.execute_gated("fetch_url", {"url": url}, fetch_url, session_id="chat-42")
model_sees = out["sanitized_result"]
```

## How it works

```mermaid
flowchart LR
    A[Agent / MCP client] -->|tool call| N[normalize] --> D[detector plugins] --> G[aggregate noisy-OR] --> P{policy floors<br/>+ taint rule}
    P -->|ALLOW / WARN| T[tool]
    P -->|REQUIRE_APPROVAL| H[(approval store)] -->|HMAC token, digest-bound| T
    P -->|BLOCK| X[error to agent]
    T -->|result| O[output guard] -->|fenced, fingerprinted| A
    P --> L[(signed audit ledger)]
    O --> L
```

Details, threat model and limits: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Evaluation

All numbers come from [`docs/BENCHMARKS.md`](docs/BENCHMARKS.md), which `sentinel eval --markdown` generates from
the corpora in `sentinel/corpus/`. A test fails if the file and the code disagree. On the current 42 attack / 50 benign cases:
every attack is flagged, 88% are stopped by detector evidence alone, and there are no false positives. Known misses are listed there.

The corpus is small and hand-written, so treat these as regression numbers, not a coverage claim. Latency is measured by
the CI `benchmark` job (`pytest -m benchmark`).

## Development

See [AGENTS.md](AGENTS.md) for the workflow (tests first, one regression test per bug, generated docs).

```bash
uv run ruff check . && uv run ruff format --check . && uv run mypy && uv run pytest --cov
```

## License

[Apache 2.0](LICENSE)
