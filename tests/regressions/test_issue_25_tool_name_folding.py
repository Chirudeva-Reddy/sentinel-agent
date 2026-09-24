"""Issue 25: tool names were folded three different ways; the policy skipped NFKC, so fullwidth names missed lists."""

from __future__ import annotations

from sentinel.core.policy import PolicyEngine
from sentinel.core.types import ToolCallRequest
from sentinel.normalize import fold_tool_name, normalize
from sentinel.sandbox.approval import call_digest

FULLWIDTH = "ｂｙｐａｓｓ_ｓｅｃｕｒｉｔｙ"


def test_policy_folds_like_the_normalizer():
    assert PolicyEngine().is_tool_blocked(FULLWIDTH)
    assert PolicyEngine().does_tool_require_approval(" ＥＸＥＣＵＴＥ_ＢＡＳＨ ")


def test_one_folding_function_everywhere():
    assert fold_tool_name(FULLWIDTH) == "bypass_security" == normalize(ToolCallRequest(tool_name=FULLWIDTH)).tool
    a = ToolCallRequest(tool_name=FULLWIDTH, arguments={"x": 1})
    b = ToolCallRequest(tool_name="bypass_security", arguments={"x": 1})
    assert call_digest(a) == call_digest(b)
