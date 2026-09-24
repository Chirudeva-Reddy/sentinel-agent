# SentinelAgent: Technical Portfolio & Architecture One-Pager
**Staff+ / Principal Systems & AI Security Engineering Brag Document**

**Author & Architect**: Chirudeva Reddy  
**Target Roles**: Staff / Principal Software Engineer, AI Systems Architect, Security Infrastructure Lead  
**Live Interactive Demo (WASM)**: [https://chirudeva-reddy.github.io/sentinel-agent/](https://chirudeva-reddy.github.io/sentinel-agent/)  
**GitHub Repository**: [https://github.com/chirudeva-reddy/sentinel-agent](https://github.com/chirudeva-reddy/sentinel-agent)  
**Package**: `sentinel-agent-gateway` (v0.2.1) on PyPI / GitHub  

---

## 1. Executive Summary & Problem Space

As Large Language Models transition from conversational assistants to autonomous agents with access to real-world tools (shell execution, database write keys, financial APIs, cloud infrastructure), they introduce a critical architectural vulnerability: **Indirect Prompt Injection**.

Because transformer architectures lack hardware-level separation between instructions and data (a fundamental Von Neumann limitation), an agent reading untrusted web data, emails, or documents can be hijacked to execute destructive commands or exfiltrate private credentials. Probabilistic guardrails, prompt engineering, and model alignment fail because they attempt to enforce security from within the model's non-deterministic token generation loop.

**SentinelAgent** is a high-performance, deny-by-default security gateway, human-in-the-loop (HITL) authorization sandbox, and Model Context Protocol (MCP) proxy. It operates at the wire level between the model and its execution environment, enforcing deterministic zero-trust policies, sub-millisecond heuristic inspection, anti-TOCTOU cryptographic approvals, and tamper-evident audit logging.

---

## 2. Architectural Highlights & Technical Decisions

```
              ┌─────────────────────────────────────────────────────────┐
              │                Autonomous Agent / LLM                   │
              └────────────────────────────┬────────────────────────────┘
                                           │ ToolCallRequest
                                           ▼
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                        SentinelAgent Gateway (Wire Boundary)                           │
│                                                                                        │
│  1. Input Normalization & Flattening                                                   │
│     [NFKC Unicode Folding] ── [Zero-Width Stripping] ── [3-Round URL Decode] ── [64KB] │
│                                                                                        │
│  2. Deterministic 3-Pillar Security Engine (Pluggable Entry Points)                    │
│     ├── Pillar 1: Injection & Obfuscation (Bounded regex, Base64 unpacking)           │
│     ├── Pillar 2: Blast Radius Analyzer (AST shell parser, wrapper stripping, SQL)     │
│     └── Pillar 3: Parameter Validator (SSRF parser: decimal/hex/IPv6, command chains) │
│                                                                                        │
│  3. Score Aggregation & Policy Enforcement                                             │
│     Noisy-OR Formula: Score = (1 - Π(1 - s_i/100)) * 100 ── Deny-By-Default Floors    │
│                                                                                        │
│  4. Cryptographic Anti-TOCTOU Sandbox                                                  │
│     SHA-256 Canonical Argument Digest ── Single-Use HMAC-SHA256 Token (SQLite WAL)    │
│                                                                                        │
│  5. Tamper-Evident SHA-256 HMAC Audit Ledger                                           │
│     Sequential Hash Chaining ── Signed .head Checkpoint ── POSIX fcntl.flock Lock      │
└────────────────────────────┬─────────────────────────────┬─────────────────────────────┘
                             │                             │
                     [ALLOW: Execute]              [REQUIRE_APPROVAL]
                             │                             │
                             ▼                             ▼
                 ┌───────────────────────┐     ┌───────────────────────┐
                 │ Target System / Tool  │     │ Human Operator / API  │
                 │ (Shell, DB, Network)  │     │ (Sign HMAC Token)     │
                 └───────────┬───────────┘     └───────────────────────┘
                             │ Tool Result
                             ▼
┌────────────────────────────────────────────────────────────────────────────────────────┐
│  6. Bi-Directional Output Guard & Session Taint Tracker                                │
│     64KB Overlapping Scanning ── Spotlight Fencing (<<untrusted-data>>) ── 20-Char     │
│     Shingle Fingerprints Halting Downstream Privileged Sinks                           │
└────────────────────────────────────────────────────────────────────────────────────────┘
```

### Key Technical Decisions:
1. **Deterministic Heuristics over Secondary LLMs**:
   - *Problem*: Traditional "guardrail" models introduce 200–800 ms of latency, cost significant GPU compute, and can themselves be jailbroken.
   - *Decision*: Built a deterministic regex and AST parsing engine with linear-time complexity and bounded quantifiers. Interception executes in **0.06 ms (30.2 µs core detector)** with zero GPU requirements and zero external network calls.
2. **Canonical Normalization Pipeline (`sentinel.normalize`)**:
   - *Decision*: All incoming calls pass through NFKC Unicode normalization, zero-width character stripping, recursive 3-round URL decoding (defeating `%252e%252e%252f`), and strict 64 KB truncation (truncation incurs a +40 risk score penalty).
3. **AST Shell Command Tokenization & Wrapper Peeling**:
   - *Problem*: Attackers hide catastrophic commands behind nested wrappers (`sudo timeout 10 sh -c 'rm -rf /'`).
   - *Decision*: Implemented an iterative tokenizer using `shlex(posix=True)` that strips leading environment variables (`VAR=val`), peels execution wrappers (`sudo`, `timeout`, `env`, `nice`, `flock`, `eval`) up to 3 levels deep, and identifies catastrophic operations (`rm -rf /`, `dd of=/dev/sda`, fork bombs) on root targets.
4. **SSRF Parsing Across Obfuscated Representations**:
   - *Decision*: Parameter validator handles decimal dword IP formats (`http://2852039166/`), hexadecimal IP encodings (`http://0xA9FEA9FE/`), IPv4-mapped IPv6 (`[::ffff:169.254.169.254]`), and blocks Cloud Instance Metadata Services (AWS/GCP IMDS at `169.254.169.254`) and internal RFC 1918 subnets.
5. **Anti-TOCTOU Cryptographic Approval Tokens (`sentinel.sandbox.approval`)**:
   - *Problem*: In naive human-in-the-loop systems, an agent can mutate its tool arguments in memory between human authorization and actual execution.
   - *Decision*: Binds authorizations to a canonical argument digest: `SHA-256(tool || canonical_json(arguments))`. The approver signs an HMAC-SHA256 token with strict TTL. On redemption, the engine recalculates the live digest; any discrepancy raises `DigestMismatch` and halts execution. Tokens are burned atomically in SQLite (WAL mode).
6. **Tamper-Evident SHA-256 HMAC Audit Ledger (`sentinel.sandbox.ledger`)**:
   - *Decision*: Append-only JSONL audit log where record $N$ HMAC-chains to record $N-1$, paired with an atomic signed `.head` checkpoint file to detect log truncation or rollback. Synchronized across multi-process workers via POSIX `fcntl.flock`.
   - *Zero-Exposure Credential Scrubbing*: Automatically redacts API keys, JWTs, AWS credentials, and SSH private keys into correlatable short hashes (`[REDACTED sha256:...]`) before writing to disk.
7. **Pure Client-Side WebAssembly Deployment (Pyodide v314.0.7)**:
   - *Decision*: The entire `sentinel-agent-gateway` package compiles to a pure-Python wheel via `uv build` and executes client-side inside the user's browser via Pyodide. No server infrastructure, zero hosting costs, and instant zero-install interactive auditing.

---

## 3. Empirical Performance Scorecard

All metrics verified through live microbenchmarks, historical commit baselines (`commit ea58ca9a`), and automated test runners on standard Apple Silicon (macOS Darwin, Python 3.13 / uv):

| Benchmark Metric | Measured Result | Production SLA Target | Margin / Improvement |
|---|---|---|---|
| **Interception Latency Overhead** | **0.06 ms** (60 microseconds) | < 15.00 ms | **250x faster than SLA** |
| **Pure 3-Pillar Detector Latency** | **0.0302 ms** (30.2 microseconds) | — | Instantaneous CPU execution |
| **Pre-Ledger Gateway Engine** | **0.0325 ms** (32.5 microseconds) | — | > 30,760 req/sec capacity |
| **p95 Latency Overhead** | **0.08 ms** | < 25.00 ms | **312x faster than SLA** |
| **p99 Latency Overhead** | **0.15 ms** | < 50.00 ms | **333x faster than SLA** |
| **Single-Worker Throughput** | **17,037 req/sec** | > 500 req/sec | **34x higher than target** |
| **Memory Footprint (RSS)** | **~32 MB** (52.59 MB full stack) | < 100 MB | Extremely compact |
| **Red-Team Attack Catch Rate** | **100.0%** (48/48 attack vectors) | > 95.0% | Zero missed vectors in corpus |
| **Detector Stop Rate (CRITICAL)** | **89.6%** (43/48 attack vectors) | — | Stopped on heuristic alone |
| **Default Policy Stop Rate** | **93.8%** (45/48 attack vectors) | — | Stopped under deny-by-default |
| **False Positive Rate** | **0.0%** (0/55 benign requests) | < 1.0% | Zero developer interruption |

---

## 4. Code Craftsmanship & Engineering Rigor

SentinelAgent was engineered according to the highest standards of systems programming and software craftsmanship:

- **246 Unit & Integration Tests Passing**:
  Full test suite (`pytest`) runs in **6.4 seconds**, covering detector algorithms, multi-stage taint tracking, TOCTOU attack vectors, ReDoS resistance, and cryptographic ledger verification.
- **100% Strict Type Coverage (`mypy --strict`)**:
  Zero type errors across 25 source files with Pydantic v2 strict plugin validation.
- **Zero Linter Warnings (`ruff`)**:
  Adheres strictly to modern Python 3.10+ conventions (clean imports, modern type union syntax `|`, zero dead code).
- **Concurrency & Non-Blocking Architecture**:
  - SQLite WAL mode (`PRAGMA journal_mode=WAL`) eliminates read lock contention during approvals.
  - Advisory file locking (`fcntl.flock`) enables safe concurrent logging across distributed worker processes.
- **Property-Based Testing**:
  Utilizes `hypothesis` for randomized property fuzzing across argument normalizers, URL decoders, and regex parsers to prevent ReDoS catastrophic backtracking.
- **Extensible Plugin Architecture**:
  Detectors are registered as standard Python entry points (`[project.entry-points."sentinel.detectors"]`), allowing enterprise security teams to drop in custom proprietary rules with zero core modifications.

---

## 5. Live Artifacts & Quickstart

### Public Resources:
- **Interactive WebAssembly Playground**: [https://chirudeva-reddy.github.io/sentinel-agent/](https://chirudeva-reddy.github.io/sentinel-agent/)
- **GitHub Repository**: [https://github.com/chirudeva-reddy/sentinel-agent](https://github.com/chirudeva-reddy/sentinel-agent)

### Quick Installation:
```bash
pip install sentinel-agent-gateway
# or using uv:
uv add sentinel-agent-gateway
```

### Reproducible CLI Verification Commands:
```bash
# 1. Inspect a destructive tool call in real time
sentinel inspect --tool run_shell --args '{"cmd": "rm -r -f /"}'

# 2. Verify tamper-evident HMAC audit ledger integrity
sentinel verify-ledger

# 3. Execute red-team corpus evaluation and print metrics table
sentinel eval --markdown

# 4. Run local performance and throughput benchmark
sentinel benchmark --iterations 500
```
