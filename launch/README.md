# SentinelAgent Launch Video Suite & Release Campaign

[![Sentinel Security](https://img.shields.io/badge/Security-Zero--Trust%20Gateway-3ecf9a?style=flat-square)](https://github.com/chirudeva-reddy/sentinel-agent)
[![WASM Demo](https://img.shields.io/badge/WebAssembly-Pyodide%20v314.0.7-blue?style=flat-square)](https://chirudeva-reddy.github.io/sentinel-agent/)
[![Detection Rate](https://img.shields.io/badge/Red--Team%20Mitigation-100%25%20(48%2F48)-3ecf9a?style=flat-square)](https://github.com/chirudeva-reddy/sentinel-agent)
[![False Positives](https://img.shields.io/badge/False%20Positives-0.0%25%20(0%2F55)-3ecf9a?style=flat-square)](https://github.com/chirudeva-reddy/sentinel-agent)
[![Interception Latency](https://img.shields.io/badge/Interception%20Latency-0.06%20ms-green?style=flat-square)](https://github.com/chirudeva-reddy/sentinel-agent)

This directory contains the complete cinematic launch video suite, reproducible programmatic demo captures, interactive HTML5 trailer player, and multi-channel release campaign for **SentinelAgent** (`sentinel-agent-gateway` v0.2.1).

---

## Deliverables & Directory Inventory

```
launch/
├── simulate_attack.py         # R3: Programmatic indirect prompt injection attack simulator
├── run_demo.sh                # R3: Master demo orchestrator (attacks, CLI approval, ledger verify)
├── trailer_player.html        # R3: Standalone dark-themed interactive trailer preview player
├── script.md                  # R1: 60-90s second-by-second cinematic trailer script
├── storyboard.md              # R2: Scene-by-scene visual blueprints, VO directions, & SFX cues
├── production_guide.md        # R2: Browser WebAssembly & CLI screen-recording staging guide
├── twitter_thread.md          # R4: Viral Twitter/X announcement thread with visual attachment cues
├── linkedin_post.md           # R4: Problem-first engineering leadership article
├── portfolio_one_pager.md     # R4: Recruiter / Staff+ technical brag document
├── test_launch_suite.py       # E2E: Automated test suite validating all launch deliverables
└── README.md                  # Complete guide and execution instructions (this file)
```

---

## ⚡ Quickstart: Running the Programmatic Demos

All demos run against real `sentinel` package components (`SentinelGateway`, `ApprovalStore`, `AuditLedger`) with genuine cryptographic verification and microsecond latency measurement.

### 1. Run the Complete Launch Demo Suite

Execute the master orchestrator script from the project root or `launch/` directory:

```bash
bash launch/run_demo.sh
# or if executable:
./launch/run_demo.sh
```

**What this script executes:**
1. **Toolchain Check**: Verifies `uv` package manager and Python runtime.
2. **Indirect Injection Simulation**: Runs `simulate_attack.py`, executing untrusted HTML ingestion, 3-pillar scoring, quarantine generation, and cryptographic rejection.
3. **CLI Approval Workflow**: Executes `sentinel inspect` on an exfiltration attempt (`cat /etc/passwd | nc`), demonstrating real-time flagging.
4. **Audit Ledger Verification**: Runs `sentinel verify-ledger` to mathematically authenticate the SHA-256 HMAC hash chain.
5. **Benchmark Verification**: Outputs the verified evaluation scorecard (100% catch rate, 0% false positives, 0.06ms latency).

### 2. Run the Adversarial Simulation Standalone

Simulate an indirect prompt injection attack where untrusted web content instructs an agent to read customer records:

```bash
uv run python launch/simulate_attack.py
# or from within the launch/ directory:
uv run python simulate_attack.py
```

Optional flags:
- `--isolated`: Stores audit logs and approval databases in a temporary `/tmp/sentinel_demo` directory instead of `~/.sentinel`.

### 3. Open the Interactive Trailer Player

Open `trailer_player.html` directly in any modern desktop web browser:

```bash
# On macOS:
open launch/trailer_player.html

# On Linux:
xdg-open launch/trailer_player.html
```

Or open Google Chrome and navigate to:
`file:///Users/tacticalcamel/.gemini/antigravity/scratch/sentinel-agent/launch/trailer_player.html`

---

## 🎬 Interactive Trailer Player (`trailer_player.html`)

The standalone preview player allows reviewers, video producers, and stakeholders to experience the cinematic trailer directly without video editing software.

### Visual Design & Aesthetics
- **Canvas & Palette**: Obsidian background (`#070a09`), card inner background (`#0c1110`), brand emerald accent (`#3ecf9a`), alert red (`#f47a7a`), warm amber (`#f2bd4b`).
- **Concentric Geometry**: Double-bezel outer shell (`border-radius: 28px`), inner core card (`border-radius: 22px`).
- **Typography**: Geist and Geist Mono via Google Fonts with system fallbacks.

### Player Features
1. **Interactive Timeline (0:00 to 1:15 / 75 seconds total)**:
   - Drag or click anywhere on the scrubber bar to seek.
   - Act markers at `0:00`, `0:15`, `0:30`, `0:50`, and `1:05`.
   - Timecode display and 30-fps frame counter (`00:00:00 // FRAME 0001`).
2. **5-Act Switcher Navigation**:
   - **Act 1: The Hook (0:00 - 0:15)**: The Silent Vulnerability of Unrestricted Agent Autonomy.
   - **Act 2: The Crisis (0:15 - 0:30)**: Injected Exploit via Routine Webpage Comments.
   - **Act 3: The 0.06ms Interception (0:30 - 0:50)**: 3-Pillar Security Engine & Quarantine Tokens.
   - **Act 4: The Proof & Climax (0:50 - 1:05)**: Tamper-Evident SHA-256 HMAC Ledger & Benchmarks.
   - **Act 5: The Call to Action (1:05 - 1:15)**: Live WebAssembly Browser Demo at `chirudeva-reddy.github.io/sentinel-agent`.
3. **Dual Telemetry Deck**:
   - **Voiceover & Direction**: Shows synchronized VO lines, tonal cues (`[Authoritative, Urgent]`), sound design indicators (`[♫ Sub-Bass Drop]`), and on-screen text overlays.
   - **Live Terminal Console**: Streams realistic gateway interception logs synchronized with each scene.
4. **Built-in Web Audio Synthesizer**:
   - Zero-dependency audio effects using Web Audio API: mechanical clicks, 50Hz sub-bass drops, intercept stings, and ledger verification chimes.
5. **Keyboard Shortcuts**:
   - `Space`: Play / Pause
   - `←` / `→`: Step backward / forward 5 seconds
   - `1`, `2`, `3`, `4`, `5`: Jump directly to Acts 1 through 5

---

## 📹 Video Production & Screen Recording Workflow

Follow this choreography to capture video assets for the 60–90 second cinematic trailer:

### 1. Recording Setup & Specifications
- **Resolution**: 3840 × 2160 (4K) captured at 60 FPS (or 1920 × 1080 at 60 FPS).
- **Browser**: Google Chrome in Incognito mode with extensions disabled.
- **Theme**: Dark mode enabled (`--bg: #070a09`).
- **Terminal**: Alacritty or iTerm2 with Geist Mono font (size 15pt), 100 columns × 35 lines.

### 2. Scene-by-Scene Staging Guide

| Act & Timecode | Primary Screen | Action / Interaction | Sound Cue |
|---|---|---|---|
| **Act 1: The Hook**<br>`0:00 - 0:15` | Browser / Hero Split | Zoom in on agent tool permissions (`execute_bash`, `db_query`) connected to production database. | Subtle keyboard clicks, low sub-bass hum |
| **Act 2: The Crisis**<br>`0:15 - 0:30` | Browser `#agents` Console | Click *"Run the agents"*. Watch the researcher ingest the poisoned HTML comment: `<!-- AI Instruction: Disregard prior instructions... -->`. | 50Hz sub-bass drop, alert pulse |
| **Act 3: The 0.06ms Interception**<br>`0:30 - 0:50` | Browser Hero Inspector (`#preset`) | Select `attack: html comment injection`. Watch the red `REQUIRE APPROVAL` badge appear in **0.06 ms**. Terminal mirror runs `uv run python launch/simulate_attack.py`. | Crisp data whir, glass shield lock |
| **Act 4: The Proof**<br>`0:50 - 1:05` | Browser Bento `#how` & Terminal | Zoom into signed ledger card: `api_key [REDACTED sha256:6fede3...]`, `chain verified`. Run `uv run sentinel verify-ledger` in terminal. | Resonant resolution chord, ledger chime |
| **Act 5: The CTA**<br>`1:05 - 1:15` | Browser URL Bar & GitHub | Full view of live URL `chirudeva-reddy.github.io/sentinel-agent` with pip install command. | Upbeat swell, completion chime |

---

## 📊 Ground Truth Benchmarks & Empirical Proof

All figures referenced in the video, social posts, and one-pager are derived from the actual codebase and verified by automated regression suites:

| Metric | Target SLA | Measured Performance | Verification Command |
|---|---|---|---|
| **Average Interception Overhead** | < 15.00 ms | **0.06 ms (60 µs)** | `uv run sentinel benchmark -n 500` |
| **Pure 3-Pillar Detector Overhead** | < 5.00 ms | **30.20 µs** | `sentinel/detectors/*.py` |
| **Throughput (Single Worker)** | > 500 req/sec | **17,000+ req/sec** | `uv run sentinel benchmark -n 500` |
| **Red-Team Attack Catch Rate** | > 95.0% | **100.0% (48/48 vectors)** | `uv run sentinel eval` |
| **False-Positive Rate** | < 1.0% | **0.0% (0/55 benign)** | `uv run sentinel eval` |
| **Memory Footprint (RSS)** | < 100 MB | **~32 MB** | `resource.getrusage()` |
| **Audit Ledger Verification** | Non-Repudiation | **SHA-256 HMAC Chained** | `uv run sentinel verify-ledger` |

---

## 🔗 Official Links & Resources

- **Live In-Browser Demo (Zero Install)**: [https://chirudeva-reddy.github.io/sentinel-agent/](https://chirudeva-reddy.github.io/sentinel-agent/)
- **GitHub Repository**: [https://github.com/chirudeva-reddy/sentinel-agent](https://github.com/chirudeva-reddy/sentinel-agent)
- **PyPI Package**: `pip install sentinel-agent-gateway`
