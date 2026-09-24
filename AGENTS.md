# Working on sentinel-agent (for humans and coding agents)

Sentinel is a security gateway: a wrong "ALLOW" is the worst bug this repo can have. Work accordingly.

## Loop
1. **Red first.** Every bug gets a regression test in `tests/regressions/test_issue_<n>.py` that fails on `main` before you touch code. New detection cases go in `tests/corpus/{attacks,benign}.yaml`, not in test code.
2. **Green** with the smallest change, at the shared choke point (the gateway / normaliser), not in one caller.
3. **Check** before every commit:
   ```bash
   uv run ruff check . && uv run ruff format --check . && uv run mypy && uv run pytest --cov
   ```
4. If `tests/characterization/snapshot.json` changes, say why in the commit message
   (regenerate with `SENTINEL_UPDATE_SNAPSHOT=1 uv run pytest tests/characterization`).

## Rules
- Fail closed: a detector error, a timeout, an unknown tool or an unparsable argument never yields ALLOW.
- Detectors read the normalised call (`sentinel.normalize`), never raw strings, and never scan the tool name as content.
- No test writes to the repo; `tests/conftest.py` points `SENTINEL_HOME` at a tmp dir. CI fails on a dirty tree.
- Secrets never reach the ledger unredacted.
- No new runtime dependency without a reason in the PR; heavy integrations go in extras (`[server]`, `[dashboard]`, `[mcp]`).
- One branch + PR per phase/issue; conventional commit messages.

## Map
| Path | What |
|---|---|
| `sentinel/core/` | types, policy, gateway (the decision point) |
| `sentinel/detectors/` | detector plugins (entry point group `sentinel.detectors`) |
| `sentinel/sandbox/` | approval store + HMAC tokens, signed audit ledger |
| `sentinel/server/` | FastAPI app factory; Streamlit dashboard talks to it over HTTP |
| `sentinel/adapters/` | MCP proxy, OpenAI tool wrapper |
| `tests/corpus/` | attack + benign YAML corpora; `sentinel eval` reports detection/FP rates |
