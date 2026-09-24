"""Issues 17 and 18: destructive commands hidden in `sh -c '...'` or behind wrapper flags were not detected."""

from __future__ import annotations

import pytest

from sentinel.detectors.blast_radius import catastrophic_commands


@pytest.mark.parametrize(
    "cmd",
    [
        "sh -c 'rm -rf /'",
        'bash -c "rm -rf ~"',
        "bash -lc 'find / -delete'",
        "zsh -c \"sh -c 'rm -rf /'\"",
        "eval 'rm -rf /'",
        "sudo -u root rm -rf /",
        "sudo -E -H rm -rf /",
        "env -i PATH=/bin rm -rf /",
        "timeout 5 rm -rf /",
        "nice -n 10 rm -rf ~",
        "sudo -u root sh -c 'rm -rf /'",
    ],
)
def test_nested_and_wrapped_destruction_is_caught(cmd):
    assert catastrophic_commands(cmd), cmd


@pytest.mark.parametrize(
    "cmd", ["sh -c 'ls -la'", "sudo -u www apt list", "timeout 5 pytest", "git rm -r --cached build"]
)
def test_benign_nested_and_wrapped_commands_are_clean(cmd):
    assert catastrophic_commands(cmd) == [], cmd
