"""Corpus metrics gate + docs/BENCHMARKS.md must be exactly what `sentinel eval --markdown` produces."""

from __future__ import annotations

import os
from pathlib import Path

from sentinel.eval import evaluate, to_markdown

DOC = Path(__file__).parents[2] / "docs" / "BENCHMARKS.md"

# Set from the first honest run; raise them as detectors improve, never lower them silently.
MIN_FLAGGED = 0.95
MIN_DETECTOR_STOP = 0.85
MAX_FALSE_POSITIVE = 0.05


def test_metrics_meet_gates():
    m = evaluate().metrics
    assert m["flagged_rate"] >= MIN_FLAGGED, m
    assert m["detector_stop_rate"] >= MIN_DETECTOR_STOP, m
    assert m["false_positive_rate"] <= MAX_FALSE_POSITIVE, m
    assert m["attacks"] >= 40 and m["benign"] >= 50


def test_benchmarks_doc_is_generated_from_code():
    md = to_markdown(evaluate())
    if os.environ.get("SENTINEL_UPDATE_SNAPSHOT"):
        DOC.write_text(md)
    assert DOC.read_text() == md, "docs/BENCHMARKS.md is stale: run `sentinel eval --markdown > docs/BENCHMARKS.md`"
