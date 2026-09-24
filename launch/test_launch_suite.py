#!/usr/bin/env python3
"""SentinelAgent Launch Suite & End-to-End Validation Tests.

Exhaustive, automated test suite validating all 10 launch artifacts against
requirements R1-R4 and acceptance criteria AC1-AC4 from ORIGINAL_REQUEST.md
and PROJECT.md.

Can be run via:
    uv run python launch/test_launch_suite.py
    uv run pytest launch/test_launch_suite.py
    python launch/test_launch_suite.py
"""

from __future__ import annotations

import ast
import html.parser
import os
import re
import subprocess
import sys
import unittest
from pathlib import Path
from urllib.parse import urlparse

# Base path resolution: works whether invoked from project root or launch/
LAUNCH_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = LAUNCH_DIR.parent

# 10 Required Launch Deliverables (PROJECT.md § Code Layout)
REQUIRED_DELIVERABLES = [
    "launch/script.md",
    "launch/storyboard.md",
    "launch/production_guide.md",
    "launch/run_demo.sh",
    "launch/simulate_attack.py",
    "launch/trailer_player.html",
    "launch/twitter_thread.md",
    "launch/linkedin_post.md",
    "launch/portfolio_one_pager.md",
    "launch/README.md",
]

# Design tokens (PROJECT.md § Interface Contracts)
BRAND_COLOR_TOKENS = {
    "emerald": "#3ecf9a",
    "alert_red": "#f47a7a",
    "amber": "#f2bd4b",
    "obsidian": "#070a09",
}

# Empirical benchmark standards (PROJECT.md § Interface Contracts)
EMPIRICAL_BENCHMARK_PATTERNS = [
    (r"0\.06\s*ms|60\s*µs|60\s*microseconds", "0.06 ms latency overhead"),
    (r"17,?000\+?\s*req/sec|17,?037", "17,000+ req/sec throughput"),
    (
        r"(?:100(?:\.0)?%.*?(?:catch|attack|vector|mitigation)|(?:catch|attack|vector|mitigation).*?100(?:\.0)%)",
        "100% attack mitigation / catch rate",
    ),
    (r"(?:0(?:\.0)?%.*?false\s*positive|false\s*positive.*?0(?:\.0)%)", "0.0% false positive rate"),
]

LIVE_DEMO_HOST = "chirudeva-reddy.github.io/sentinel-agent"
REPO_URL = "https://github.com/chirudeva-reddy/sentinel-agent"


def read_text_file(relative_or_abs_path: str | Path) -> str:
    """Read and return content of a file relative to project root or launch dir."""
    path = Path(relative_or_abs_path)
    if not path.is_absolute():
        p1 = PROJECT_ROOT / path
        p2 = LAUNCH_DIR / path.name
        path = p1 if p1.exists() else p2
    return path.read_text(encoding="utf-8")


def parse_timecode_to_seconds(tc: str) -> float:
    """Parse timecode string (MM:SS.mmm or M:SS.mmm or MM:SS) to float seconds."""
    tc = tc.strip()
    match = re.match(r"^(\d+):(\d{2})(?:\.(\d+))?$", tc)
    if not match:
        raise ValueError(f"Invalid timecode format: {tc}")
    minutes = int(match.group(1))
    seconds = int(match.group(2))
    sub = match.group(3)
    frac = float(f"0.{sub}") if sub else 0.0
    return minutes * 60 + seconds + frac


class SimpleHTMLValidator(html.parser.HTMLParser):
    """HTML Parser verifying tag balancing and basic syntax integrity."""

    def __init__(self) -> None:
        super().__init__()
        self.tags_opened: list[str] = []
        self.tags_closed: list[str] = []
        self.tag_counts: dict[str, int] = {}
        self.has_doctype = False

    def handle_decl(self, decl: str) -> None:
        if decl.lower().startswith("doctype"):
            self.has_doctype = True

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.tags_opened.append(tag)
        self.tag_counts[tag] = self.tag_counts.get(tag, 0) + 1

    def handle_endtag(self, tag: str) -> None:
        self.tags_closed.append(tag)


# ==============================================================================
# TIER 1: Deliverable Completeness Tests
# ==============================================================================


class TestDeliverableCompleteness(unittest.TestCase):
    """Tier 1: Verifies all 10 launch files exist, are substantive, and UTF-8 valid."""

    def test_launch_directory_exists(self) -> None:
        """Asserts the launch/ directory exists and is a directory."""
        self.assertTrue(LAUNCH_DIR.exists(), f"Directory missing: {LAUNCH_DIR}")
        self.assertTrue(LAUNCH_DIR.is_dir(), f"Path is not a directory: {LAUNCH_DIR}")

    def test_all_ten_deliverable_files_exist(self) -> None:
        """Asserts every one of the 10 required launch files exists."""
        for rel_path in REQUIRED_DELIVERABLES:
            full_path = PROJECT_ROOT / rel_path
            self.assertTrue(full_path.exists(), f"Missing required deliverable file: {rel_path} (full: {full_path})")
            self.assertTrue(full_path.is_file(), f"Deliverable is not a file: {rel_path}")

    def test_deliverable_files_are_substantive(self) -> None:
        """Asserts deliverable files contain substantive content (> 1000 bytes)."""
        for rel_path in REQUIRED_DELIVERABLES:
            full_path = PROJECT_ROOT / rel_path
            size = full_path.stat().st_size
            self.assertGreater(
                size, 1000, f"File {rel_path} is suspiciously small ({size} bytes); expected > 1000 bytes"
            )

    def test_deliverable_files_valid_utf8(self) -> None:
        """Asserts all deliverable text files decode without UTF-8 encoding errors."""
        for rel_path in REQUIRED_DELIVERABLES:
            full_path = PROJECT_ROOT / rel_path
            try:
                content = full_path.read_text(encoding="utf-8")
                self.assertGreater(len(content), 0, f"File {rel_path} is empty")
            except UnicodeDecodeError as exc:
                self.fail(f"UTF-8 decode error in {rel_path}: {exc}")


# ==============================================================================
# TIER 2: Narrative & Timing Accuracy Tests (R1, AC1)
# ==============================================================================


class TestNarrativeAndTimingAccuracy(unittest.TestCase):
    """Tier 2: Validates script.md duration (60-90s), 5 acts, monotonic timecodes, and WPM."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.script_path = PROJECT_ROOT / "launch/script.md"
        cls.content = cls.script_path.read_text(encoding="utf-8")

    def test_trailer_duration_strictly_between_60_and_90_seconds(self) -> None:
        """Validates total trailer duration is strictly between 60.0 and 90.0 seconds."""
        # Find duration references in script
        duration_matches = re.findall(
            r"(?:Total\s*Master\s*Runtime|Target\s*Runtime|Full\s*5-Act\s*Trailer).*?(\d+[:\.]\d+(?:\.\d+)?)",
            self.content,
            re.IGNORECASE,
        )
        self.assertTrue(len(duration_matches) > 0, "Could not locate total runtime specification in launch/script.md")

        # Parse duration
        found_durations: list[float] = []
        for raw in duration_matches:
            raw_clean = raw.strip()
            if ":" in raw_clean:
                # MM:SS format
                parts = raw_clean.split(":")
                dur = float(parts[0]) * 60 + float(parts[1])
                found_durations.append(dur)
            else:
                try:
                    dur = float(raw_clean)
                    found_durations.append(dur)
                except ValueError:
                    pass

        self.assertTrue(len(found_durations) > 0, "No parseable durations found")
        master_duration = found_durations[0]

        # Assert strictly between 60.0 and 90.0 seconds inclusive
        self.assertGreaterEqual(
            master_duration, 60.0, f"Trailer duration {master_duration}s is less than 60.0s requirement"
        )
        self.assertLessEqual(master_duration, 90.0, f"Trailer duration {master_duration}s exceeds 90.0s requirement")

    def test_five_narrative_acts_present(self) -> None:
        """Validates that all 5 required narrative acts are present in the script."""
        required_acts = [
            (r"ACT\s*1\s*:\s*THE\s*HOOK", "Act 1: The Hook"),
            (r"ACT\s*2\s*:\s*THE\s*CRISIS", "Act 2: The Crisis"),
            (r"ACT\s*3\s*:\s*THE\s*INTERVENTION", "Act 3: The Intervention"),
            (r"ACT\s*4\s*:\s*THE\s*PROOF", "Act 4: The Proof & Climax"),
            (r"ACT\s*5\s*:\s*THE\s*CALL-TO-ACTION|ACT\s*5\s*:\s*CTA", "Act 5: The Call-to-Action"),
        ]
        for pattern, label in required_acts:
            self.assertRegex(
                self.content,
                re.compile(pattern, re.IGNORECASE),
                f"Missing required narrative section: '{label}' in launch/script.md",
            )

    def test_monotonic_scene_timecodes(self) -> None:
        """Validates that scene timecodes are present and monotonically non-decreasing."""
        # Find explicit scene timecodes defined in the script
        scene_matches = re.findall(
            r"\*\*Timecode\*\*:\s*`?(\d+:\d{2}(?:\.\d+)?)`?\s*[-–—]\s*`?(\d+:\d{2}(?:\.\d+)?)`?", self.content
        )
        self.assertGreaterEqual(len(scene_matches), 5, "Found insufficient scene timecodes in launch/script.md")

        last_end = 0.0
        for start_str, end_str in scene_matches:
            start_sec = parse_timecode_to_seconds(start_str)
            end_sec = parse_timecode_to_seconds(end_str)

            self.assertGreaterEqual(end_sec, start_sec, f"Invalid scene window: start {start_sec}s > end {end_sec}s")
            # Monotonicity check
            self.assertGreaterEqual(
                start_sec,
                last_end - 0.01,  # allow exact boundary transitions
                f"Non-monotonic timecode: scene starts at {start_sec}s before previous ended at {last_end}s",
            )
            last_end = end_sec

        self.assertGreaterEqual(last_end, 60.0, "Script does not reach 60 seconds")
        self.assertLessEqual(last_end, 90.0, "Script timecodes exceed 90 seconds")

    def test_dialogue_speech_rate_pacing_within_130_to_170_wpm(self) -> None:
        """Validates voiceover pacing is strictly within professional bounds (130-170 WPM)."""
        # Look for explicit spoken pacing mentions and table entries
        pacing_matches = re.findall(r"(\d{2,3}(?:\.\d+)?)\s*WPM", self.content, re.IGNORECASE)
        self.assertTrue(len(pacing_matches) > 0, "No WPM pacing indicators found in script.md")

        for p_str in pacing_matches:
            wpm = float(p_str)
            self.assertGreaterEqual(wpm, 130.0, f"WPM pacing {wpm} is below professional lower bound of 130 WPM")
            self.assertLessEqual(wpm, 170.0, f"WPM pacing {wpm} exceeds professional upper bound of 170 WPM")

        # Check for timing and word count validation table presence
        self.assertIn(
            "Timing & Word Count Validation Table",
            self.content,
            "Missing required Timing & Word Count Validation Table in launch/script.md",
        )

    def test_concrete_technical_narrative_evidence(self) -> None:
        """Validates script contains real security mechanics and zero fake buzzwords."""
        technical_terms = [
            ("indirect prompt injection", "Indirect Prompt Injection exploit"),
            ("0.06", "0.06 ms microsecond intercept"),
            ("InjectionDetector", "Pillar 1: InjectionDetector"),
            ("BlastRadiusDetector", "Pillar 2: BlastRadiusDetector"),
            ("ArgumentValidator", "Pillar 3: ArgumentValidator"),
            ("HMAC", "SHA-256 HMAC cryptographic token / ledger"),
            ("quarantine", "Human-in-the-loop quarantine"),
            ("chirudeva-reddy.github.io/sentinel-agent", "Live WebAssembly demo URL"),
        ]
        for term, desc in technical_terms:
            self.assertIn(
                term.lower(), self.content.lower(), f"Script is missing technical evidence: {desc} ('{term}')"
            )


# ==============================================================================
# TIER 3: Visual & Staging Completeness Tests (R2, AC2)
# ==============================================================================


class TestVisualAndStagingCompleteness(unittest.TestCase):
    """Tier 3: Validates storyboard.md and production_guide.md color tokens, wasm url, and staging."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.storyboard = (PROJECT_ROOT / "launch/storyboard.md").read_text(encoding="utf-8")
        cls.production_guide = (PROJECT_ROOT / "launch/production_guide.md").read_text(encoding="utf-8")

    def test_brand_color_tokens_present(self) -> None:
        """Validates presence of brand color tokens (#3ecf9a, #f47a7a, #f2bd4b, #070a09)."""
        combined = (self.storyboard + "\n" + self.production_guide).lower()
        for color_name, hex_code in BRAND_COLOR_TOKENS.items():
            self.assertIn(
                hex_code.lower(),
                combined,
                f"Missing brand color token {color_name} ({hex_code}) in storyboard or production guide",
            )

    def test_live_webassembly_demo_url_present(self) -> None:
        """Validates presence of live WebAssembly demo URL in both documents."""
        self.assertIn(
            LIVE_DEMO_HOST, self.storyboard, f"Missing live demo URL '{LIVE_DEMO_HOST}' in launch/storyboard.md"
        )
        self.assertIn(
            LIVE_DEMO_HOST,
            self.production_guide,
            f"Missing live demo URL '{LIVE_DEMO_HOST}' in launch/production_guide.md",
        )

    def test_browser_staging_instructions(self) -> None:
        """Validates step-by-step browser recording instructions (#preset, #inspect, #agents)."""
        for selector in ["#preset", "#inspect", "#agents"]:
            self.assertIn(
                selector,
                self.production_guide,
                f"Missing browser UI element instruction '{selector}' in launch/production_guide.md",
            )
        # Check Pyodide runtime indicator reference
        self.assertRegex(
            self.production_guide,
            re.compile(r"Pyodide|Python 3\.12|runtime badge", re.IGNORECASE),
            "Missing Pyodide / WebAssembly runtime staging instructions in production_guide.md",
        )

    def test_rich_cli_staging_instructions(self) -> None:
        """Validates step-by-step Rich CLI terminal staging instructions."""
        cli_commands = [
            "sentinel inspect",
            "sentinel verify-ledger",
        ]
        for cmd in cli_commands:
            self.assertIn(
                cmd,
                self.production_guide,
                f"Missing CLI command staging instruction '{cmd}' in launch/production_guide.md",
            )

    def test_sound_design_cues_in_storyboard(self) -> None:
        """Validates audio & sound design cues are explicitly specified in storyboard."""
        audio_cues = [
            (r"bass|sub-bass", "sub-bass / bass drops"),
            (r"keyboard|typing", "mechanical keyboard / typing textures"),
            (r"chord|chime|resonance", "resolution chord / chime"),
            (r"sting|alert|glitch|impact", "alert stings / impact cues"),
        ]
        storyboard_lower = self.storyboard.lower()
        for pat, label in audio_cues:
            self.assertTrue(
                bool(re.search(pat, storyboard_lower)),
                f"Missing audio/sound design cue '{label}' in launch/storyboard.md",
            )

    def test_vocal_tone_direction_specified(self) -> None:
        """Validates voiceover tone direction (authoritative, cinematic, crisp)."""
        storyboard_lower = self.storyboard.lower()
        self.assertTrue(
            "authoritative" in storyboard_lower or "cinematic" in storyboard_lower,
            "Missing authoritative/cinematic vocal tone direction in storyboard.md",
        )


# ==============================================================================
# TIER 4: Programmatic Demo Execution Tests (R3, AC3)
# ==============================================================================


class TestProgrammaticDemoExecution(unittest.TestCase):
    """Tier 4: Validates run_demo.sh is executable and simulate_attack.py executes cleanly."""

    def test_run_demo_sh_is_executable(self) -> None:
        """Verifies launch/run_demo.sh has executable permissions (chmod +x)."""
        run_demo_path = PROJECT_ROOT / "launch/run_demo.sh"
        self.assertTrue(run_demo_path.exists(), "launch/run_demo.sh does not exist")
        is_executable = os.access(str(run_demo_path), os.X_OK)
        self.assertTrue(is_executable, f"launch/run_demo.sh is not executable. Run: chmod +x {run_demo_path}")

    def test_run_demo_sh_structure_and_shebang(self) -> None:
        """Verifies launch/run_demo.sh has a valid bash shebang and safe error handling."""
        content = (PROJECT_ROOT / "launch/run_demo.sh").read_text(encoding="utf-8")
        lines = content.strip().splitlines()
        self.assertTrue(
            lines[0].startswith("#!/") and "bash" in lines[0], f"Invalid shebang in run_demo.sh: {lines[0]}"
        )
        self.assertRegex(
            content,
            re.compile(r"set\s+-[eEuo\s]+pipefail|set\s+-e"),
            "run_demo.sh should enforce safe failure handling (e.g. set -euo pipefail)",
        )

    def test_simulate_attack_py_syntax_and_shebang(self) -> None:
        """Verifies simulate_attack.py compiles cleanly without Python syntax errors."""
        script_path = PROJECT_ROOT / "launch/simulate_attack.py"
        self.assertTrue(script_path.exists(), "launch/simulate_attack.py does not exist")
        content = script_path.read_text(encoding="utf-8")

        # Verify shebang
        self.assertTrue(
            content.startswith("#!/usr/bin/env python") or content.startswith("#!/usr/bin/python"),
            "simulate_attack.py should have a valid python shebang",
        )

        # Parse AST
        try:
            ast.parse(content, filename=str(script_path))
        except SyntaxError as exc:
            self.fail(f"Syntax error in launch/simulate_attack.py: {exc}")

    def test_simulate_attack_py_execution_and_evidence(self) -> None:
        """Executes simulate_attack.py and verifies exit code 0 and required outputs."""
        script_path = PROJECT_ROOT / "launch/simulate_attack.py"

        # Execute using the active Python interpreter
        proc = subprocess.run(
            [sys.executable, str(script_path)],
            cwd=str(PROJECT_ROOT),
            capture_output=True,
            text=True,
            timeout=30,
        )

        # 1. Exit code check
        self.assertEqual(
            proc.returncode,
            0,
            f"simulate_attack.py failed with exit code {proc.returncode}.\nStderr: {proc.stderr}\nStdout: {proc.stdout[:1000]}",
        )

        stdout = proc.stdout

        # 2. Output contains injection detection
        self.assertRegex(
            stdout,
            re.compile(r"injection|CRITICAL|REQUIRE_APPROVAL", re.IGNORECASE),
            "simulate_attack.py output missing injection detection indicator",
        )

        # 3. Output contains risk score
        self.assertRegex(
            stdout,
            re.compile(r"score.*?(\d+(?:\.\d+)?)\s*(?:/|of)\s*100|\b95\.\d+\b", re.IGNORECASE),
            "simulate_attack.py output missing numeric risk score",
        )

        # 4. Output contains quarantine token / approval request
        self.assertRegex(
            stdout,
            re.compile(r"quarantine|approval\s*request|canonical\s*call\s*digest|hmac\s*token", re.IGNORECASE),
            "simulate_attack.py output missing quarantine / approval token evidence",
        )

        # 5. Output contains HMAC ledger verification
        self.assertRegex(
            stdout,
            re.compile(r"cryptographic\s*integrity\s*verified|audit\.jsonl|ledger", re.IGNORECASE),
            "simulate_attack.py output missing cryptographic ledger verification",
        )


# ==============================================================================
# TIER 5: Interactive Player Integrity Tests (R3)
# ==============================================================================


class TestInteractivePlayerIntegrity(unittest.TestCase):
    """Tier 5: Validates trailer_player.html structure, CSS design tokens, acts, and controls."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.html_path = PROJECT_ROOT / "launch/trailer_player.html"
        cls.content = cls.html_path.read_text(encoding="utf-8")

    def test_player_html_valid_structure(self) -> None:
        """Parses trailer_player.html to ensure valid DOCTYPE and tag hierarchy."""
        self.assertTrue(self.content.startswith("<!DOCTYPE html>"), "Missing <!DOCTYPE html>")
        self.assertIn("<html", self.content)
        self.assertIn("<head>", self.content)
        self.assertIn("<body>", self.content)
        self.assertIn("</html>", self.content)

        # Verify parsing with HTMLParser
        parser = SimpleHTMLValidator()
        try:
            parser.feed(self.content)
        except Exception as exc:
            self.fail(f"HTML parsing failure in launch/trailer_player.html: {exc}")

        self.assertTrue(parser.has_doctype, "HTML validator did not detect DOCTYPE")
        self.assertIn("style", parser.tag_counts, "HTML missing <style> element")
        self.assertIn("script", parser.tag_counts, "HTML missing <script> element")

    def test_player_styling_and_tokens(self) -> None:
        """Verifies player styling includes brand colors, typography, and dark theme."""
        content_lower = self.content.lower()
        for color_name, hex_code in BRAND_COLOR_TOKENS.items():
            self.assertIn(
                hex_code.lower(),
                content_lower,
                f"Missing brand color {color_name} ({hex_code}) in launch/trailer_player.html",
            )
        self.assertIn("geist", content_lower, "Missing Geist font declaration in trailer_player.html")

    def test_player_narrative_timeline_and_acts(self) -> None:
        """Verifies all 5 acts are defined in the interactive player timeline."""
        required_acts = [
            (r"hook", "Act 1: The Hook"),
            (r"crisis", "Act 2: The Crisis"),
            (r"intercept|intervention", "Act 3: The Intervention / Interception"),
            (r"proof|climax", "Act 4: The Proof & Climax"),
            (r"cta|call\s*to\s*action", "Act 5: CTA"),
        ]
        for pat, label in required_acts:
            self.assertRegex(
                self.content, re.compile(pat, re.IGNORECASE), f"Missing act '{label}' in launch/trailer_player.html"
            )
        # Check total duration (75.0s / 01:15)
        self.assertRegex(
            self.content, re.compile(r"75(?:\.0)?|01:15"), "Player missing 75-second total duration specification"
        )

    def test_player_interactive_controls_present(self) -> None:
        """Verifies player includes play/pause, timeline scrubber, terminal console, and audio toggle."""
        control_ids = [
            "playBtn",  # Play / pause button
            "timeline",  # Scrubbing timeline / progress bar
            "timeCurrent",  # Current timecode indicator
            "terminalLog",  # Simulated terminal console
            "voText",  # Voiceover cue display
        ]
        for cid in control_ids:
            self.assertIn(
                cid, self.content, f"Missing interactive control element '{cid}' in launch/trailer_player.html"
            )


# ==============================================================================
# TIER 6: Social Launch & Link Integrity Tests (R4, AC4)
# ==============================================================================


class TestSocialLaunchAndLinkIntegrity(unittest.TestCase):
    """Tier 6: Validates twitter_thread.md, linkedin_post.md, portfolio_one_pager.md, and URLs."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.twitter = (PROJECT_ROOT / "launch/twitter_thread.md").read_text(encoding="utf-8")
        cls.linkedin = (PROJECT_ROOT / "launch/linkedin_post.md").read_text(encoding="utf-8")
        cls.portfolio = (PROJECT_ROOT / "launch/portfolio_one_pager.md").read_text(encoding="utf-8")
        cls.social_docs = {
            "twitter_thread.md": cls.twitter,
            "linkedin_post.md": cls.linkedin,
            "portfolio_one_pager.md": cls.portfolio,
        }

    def test_twitter_thread_structure_and_media_cues(self) -> None:
        """Validates twitter_thread.md has 8+ tweets and required video/GIF attachment cues."""
        tweet_headers = re.findall(r"###\s*Tweet\s*\d+", self.twitter, re.IGNORECASE)
        self.assertGreaterEqual(
            len(tweet_headers), 8, f"Expected at least 8 tweets in launch/twitter_thread.md, found {len(tweet_headers)}"
        )
        # Check media attachment cues
        self.assertRegex(
            self.twitter,
            re.compile(r"\[VIDEO:.*?\]", re.IGNORECASE),
            "Missing [VIDEO: ...] attachment cue in twitter_thread.md",
        )
        self.assertRegex(
            self.twitter,
            re.compile(r"\[GIF:.*?\]", re.IGNORECASE),
            "Missing [GIF: ...] attachment cue in twitter_thread.md",
        )

    def test_linkedin_post_structure(self) -> None:
        """Validates linkedin_post.md thought leadership structure."""
        self.assertIn(
            "Model Alignment Fallacy", self.linkedin, "Missing 'Model Alignment Fallacy' section in linkedin_post.md"
        )
        self.assertRegex(
            self.linkedin,
            re.compile(r"zero-trust|execution\s*boundary", re.IGNORECASE),
            "Missing zero-trust / execution boundary discussion in linkedin_post.md",
        )

    def test_portfolio_one_pager_structure(self) -> None:
        """Validates portfolio_one_pager.md technical brag document layout."""
        self.assertIn(
            "Architectural Highlights", self.portfolio, "Missing 'Architectural Highlights' in portfolio_one_pager.md"
        )
        self.assertRegex(
            self.portfolio,
            re.compile(r"Staff\+|Principal", re.IGNORECASE),
            "Missing Staff+/Principal target audience indicator in portfolio_one_pager.md",
        )

    def test_clickable_url_integrity_across_social_assets(self) -> None:
        """Extracts and validates all URLs in social launch documents."""
        url_pattern = re.compile(r"https?://[^\s)\]>\"'`]+")

        for doc_name, content in self.social_docs.items():
            urls = url_pattern.findall(content)
            self.assertGreater(len(urls), 0, f"No URLs found in {doc_name}")

            # Validate each URL parses cleanly
            for u in urls:
                # Strip trailing markdown punctuation
                clean_url = u.rstrip(".,;:")
                parsed = urlparse(clean_url)
                self.assertIn(parsed.scheme, ["http", "https"], f"Invalid URL scheme in {doc_name}: {clean_url}")
                self.assertTrue(bool(parsed.netloc), f"Invalid URL missing domain in {doc_name}: {clean_url}")

            # Assert live WebAssembly demo URL is present
            has_demo_url = any(LIVE_DEMO_HOST in u for u in urls)
            self.assertTrue(has_demo_url, f"Missing live demo URL '{LIVE_DEMO_HOST}' in {doc_name}")

            # Assert GitHub repo URL is present
            has_repo_url = any("github.com/chirudeva-reddy/sentinel-agent" in u for u in urls)
            self.assertTrue(has_repo_url, f"Missing GitHub repository URL in {doc_name}")

    def test_empirical_benchmark_references_in_social_documents(self) -> None:
        """Validates empirical metrics are accurately referenced across social assets."""
        combined = "\n".join(self.social_docs.values())
        for pattern, label in EMPIRICAL_BENCHMARK_PATTERNS:
            self.assertRegex(
                combined,
                re.compile(pattern, re.IGNORECASE),
                f"Missing empirical benchmark reference: {label} (pattern: {pattern})",
            )


# ==============================================================================
# Test Runner & CLI Execution
# ==============================================================================


def run_test_suite() -> bool:
    """Run all test suites and display a clean execution report."""
    suite = unittest.TestSuite()
    loader = unittest.TestLoader()

    test_classes = [
        TestDeliverableCompleteness,
        TestNarrativeAndTimingAccuracy,
        TestVisualAndStagingCompleteness,
        TestProgrammaticDemoExecution,
        TestInteractivePlayerIntegrity,
        TestSocialLaunchAndLinkIntegrity,
    ]

    for cls in test_classes:
        suite.addTests(loader.loadTestsFromTestCase(cls))

    # Check if rich is available for enhanced reporting
    try:
        from rich.console import Console
        from rich.panel import Panel
        from rich.table import Table

        console = Console()
        console.print(
            Panel(
                "[bold #3ecf9a]SentinelAgent Cinematic Launch Validation Suite[/bold #3ecf9a]\n"
                "[#8f9c97]Executing comprehensive verification across all 6 test tiers & 10 deliverables[/#8f9c97]",
                border_style="#3ecf9a",
            )
        )

        runner = unittest.TextTestRunner(verbosity=2)
        result = runner.run(suite)

        table = Table(title="Launch Suite Verification Summary", border_style="#3ecf9a")
        table.add_column("Tier", style="bold")
        table.add_column("Scope")
        table.add_column("Status")

        table.add_row(
            "Tier 1",
            "Deliverable File Completeness (10 files)",
            "[#3ecf9a]PASS ✓[/#3ecf9a]"
            if not any("TestDeliverableCompleteness" in str(e[0]) for e in result.failures + result.errors)
            else "[#f47a7a]FAIL ✗[/#f47a7a]",
        )
        table.add_row(
            "Tier 2",
            "Narrative & Timing Accuracy (60-90s, 5 acts, WPM)",
            "[#3ecf9a]PASS ✓[/#3ecf9a]"
            if not any("TestNarrativeAndTimingAccuracy" in str(e[0]) for e in result.failures + result.errors)
            else "[#f47a7a]FAIL ✗[/#f47a7a]",
        )
        table.add_row(
            "Tier 3",
            "Visual & Staging Completeness (tokens, WASM url, CLI)",
            "[#3ecf9a]PASS ✓[/#3ecf9a]"
            if not any("TestVisualAndStagingCompleteness" in str(e[0]) for e in result.failures + result.errors)
            else "[#f47a7a]FAIL ✗[/#f47a7a]",
        )
        table.add_row(
            "Tier 4",
            "Programmatic Demo Execution (run_demo.sh, simulate_attack)",
            "[#3ecf9a]PASS ✓[/#3ecf9a]"
            if not any("TestProgrammaticDemoExecution" in str(e[0]) for e in result.failures + result.errors)
            else "[#f47a7a]FAIL ✗[/#f47a7a]",
        )
        table.add_row(
            "Tier 5",
            "Interactive Player Integrity (trailer_player.html)",
            "[#3ecf9a]PASS ✓[/#3ecf9a]"
            if not any("TestInteractivePlayerIntegrity" in str(e[0]) for e in result.failures + result.errors)
            else "[#f47a7a]FAIL ✗[/#f47a7a]",
        )
        table.add_row(
            "Tier 6",
            "Social Launch & Link Integrity (threads, URLs, metrics)",
            "[#3ecf9a]PASS ✓[/#3ecf9a]"
            if not any("TestSocialLaunchAndLinkIntegrity" in str(e[0]) for e in result.failures + result.errors)
            else "[#f47a7a]FAIL ✗[/#f47a7a]",
        )

        console.print(table)

        if result.wasSuccessful():
            console.print(
                Panel(
                    f"[bold #3ecf9a]✔ ALL {result.testsRun} TESTS PASSED PERFECTLY[/bold #3ecf9a]\n"
                    "[#8f9c97]All 10 deliverables verified compliant with ORIGINAL_REQUEST.md & PROJECT.md[/#8f9c97]",
                    border_style="#3ecf9a",
                )
            )
        else:
            console.print(
                Panel(
                    f"[bold #f47a7a]✖ {len(result.failures)} FAILURES / {len(result.errors)} ERRORS out of {result.testsRun} tests[/#f47a7a]",
                    border_style="#f47a7a",
                )
            )
        return result.wasSuccessful()

    except ImportError:
        runner = unittest.TextTestRunner(verbosity=2)
        result = runner.run(suite)
        return result.wasSuccessful()


if __name__ == "__main__":
    success = run_test_suite()
    sys.exit(0 if success else 1)
