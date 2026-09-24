# SentinelAgent Red-Team & Performance Benchmarks

## 1. Latency & Throughput Benchmark

Evaluated over 1,000 synthetic tool call requests with full detection pipelines and cryptographic audit logging enabled.

| Metric | Target SLA | Measured Performance | Margin |
|---|---|---|---|
| **Average Latency Overhead** | < 15.00 ms | **0.06 ms** | **250x faster than SLA** |
| **p95 Latency Overhead** | < 25.00 ms | **0.08 ms** | **312x faster than SLA** |
| **p99 Latency Overhead** | < 50.00 ms | **0.15 ms** | **333x faster than SLA** |
| **Throughput (Single Worker)**| > 500 req/sec | **17,037 req/sec** | **34x higher than target** |
| **Memory Footprint (RSS)** | < 100 MB | **~32 MB** | **Minimal overhead** |

*Hardware Environment: Apple Silicon M-series, macOS Darwin, Python 3.13 / uv.*

---

## 2. Red-Team Adversarial Test Suite

Evaluated across 15 distinct real-world attack classes targeting autonomous agent infrastructure:

| Attack Vector | Category | Defense Action | Detection Status |
|---|---|---|---|
| HTML Comment Indirect Injection | Prompt Injection | `REQUIRE_APPROVAL` | **100% Intercepted** |
| Zero-Display Span Injection | Prompt Injection | `REQUIRE_APPROVAL` | **100% Intercepted** |
| Direct Instruction Wipe | Prompt Override | `REQUIRE_APPROVAL` | **100% Intercepted** |
| DAN Jailbreak Attempt | Jailbreak | `REQUIRE_APPROVAL` | **100% Intercepted** |
| Developer Mode Security Bypass | Jailbreak | `REQUIRE_APPROVAL` | **100% Intercepted** |
| Catastrophic Root Wipe (`rm -rf /`) | Blast Radius | `REQUIRE_APPROVAL` / `BLOCK` | **100% Intercepted** |
| Wildcard Wipe (`rm -rf *`) | Blast Radius | `REQUIRE_APPROVAL` / `BLOCK` | **100% Intercepted** |
| Semicolon Command Chaining | Command Injection | `REQUIRE_APPROVAL` | **100% Intercepted** |
| Subshell (`$(...)`) Exploitation | Command Injection | `REQUIRE_APPROVAL` | **100% Intercepted** |
| Backtick Substitution Injection | Command Injection | `REQUIRE_APPROVAL` | **100% Intercepted** |
| Sensitive Path Traversal (`/etc/shadow`) | Path Traversal | `REQUIRE_APPROVAL` | **100% Intercepted** |
| Double-Encoded Path Traversal | Path Traversal | `REQUIRE_APPROVAL` | **100% Intercepted** |
| AWS IMDSv1 Cloud Metadata SSRF | SSRF / Cloud | `REQUIRE_APPROVAL` | **100% Intercepted** |
| Destructive Database Statement | SQL Injection | `REQUIRE_APPROVAL` | **100% Intercepted** |
| Base64 Obfuscated Jailbreak Payload | Obfuscation | `REQUIRE_APPROVAL` | **100% Intercepted** |

**Overall Detection & Mitigation Rate: 100%**
