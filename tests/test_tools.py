"""tools/list snapshot + error-envelope mapping tests.

No network calls: tool enumeration goes through FastMCP's in-process
list_tools(), and the error-code mapping is tested directly against
CheckPointError, independent of any real HTTP request.
"""

import pytest

from checkpoint_mcp.api_client import CheckPointError
from checkpoint_mcp.config import Settings
from checkpoint_mcp.server import create_mcp_server

EXPECTED_TOOLS = {
    "checkpoint_get_policy_modifications": {"rule_id"},
    "checkpoint_get_policy_assignments": {"rule_id"},
    "checkpoint_get_remediation_results_slim": {"remediation_id"},
    "checkpoint_get_quarantine_files": set(),
    "checkpoint_get_vulnerability_data": set(),
    "checkpoint_search_organization_tree": set(),
    "checkpoint_get_computers_filtered": set(),
    "checkpoint_get_vulnerability_devices": {"device_ids"},
    "checkpoint_get_remediation_status": set(),
    "checkpoint_get_vulnerability_scan_status": set(),
    "checkpoint_get_policy_metadata": set(),
}


@pytest.mark.asyncio
async def test_tools_list_snapshot():
    mcp = create_mcp_server(Settings())
    tools = await mcp.list_tools()
    names = {t.name for t in tools}
    assert names == set(EXPECTED_TOOLS), f"unexpected tool set: {names}"

    by_name = {t.name: t for t in tools}
    for name, expected_required in EXPECTED_TOOLS.items():
        tool = by_name[name]
        required = set(tool.inputSchema.get("required", []))
        assert required == expected_required, f"{name}: required={required}"
        assert tool.annotations is not None and tool.annotations.readOnlyHint is True
        assert len(tool.description or "") <= 500, f"{name}: description too long"
        first_line = (tool.description or "").strip().splitlines()[0]
        assert len(first_line) <= 100, f"{name}: first line too long: {first_line!r}"
        assert "API:" not in (tool.description or ""), f"{name}: leaked implementation detail"


@pytest.mark.asyncio
async def test_service_instructions_present_and_bounded():
    mcp = create_mcp_server(Settings())
    assert mcp.instructions
    assert len(mcp.instructions) <= 1500


@pytest.mark.parametrize(
    "status_code,expected_code,expected_retryable",
    [
        (0, "upstream_error", True),
        (400, "invalid_argument", False),
        (401, "unauthorized", False),
        (403, "unauthorized", False),
        (404, "not_found", False),
        (422, "invalid_argument", False),
        (429, "rate_limited", True),
        (500, "upstream_error", True),
        (503, "upstream_error", True),
    ],
)
def test_error_envelope_mapping(status_code, expected_code, expected_retryable):
    import json

    err = CheckPointError(status_code, "boom")
    envelope = json.loads(err.to_envelope())
    assert envelope["error"]["code"] == expected_code
    assert envelope["error"]["retryable"] is expected_retryable
    assert envelope["error"]["message"] == "boom"
