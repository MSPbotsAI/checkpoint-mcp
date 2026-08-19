from collections.abc import Callable

from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations

from .._json import dump_json_capped
from ..api_client import CheckPointClient, CheckPointError
from ._common import NO_TOKEN

_MAX_PAGE_SIZE = 200


def register(mcp: FastMCP, client_factory: Callable[[], CheckPointClient | None]) -> None:

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
    async def checkpoint_get_policy_modifications(rule_id: str) -> str:
        """List the modification history of a Harmony Endpoint policy rule.

        Args:
            rule_id: Required. The policy rule ID (get one from
                checkpoint_get_policy_metadata).
        """
        client = client_factory()
        if client is None:
            return NO_TOKEN
        try:
            result = await client.call("GET", f"policy/{rule_id}/modifications")
            return dump_json_capped(result)
        except CheckPointError as e:
            return e.to_envelope()

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
    async def checkpoint_get_policy_assignments(rule_id: str) -> str:
        """List what a Harmony Endpoint policy rule is assigned to
        (computers, groups, the whole organization, etc.).

        Args:
            rule_id: Required. The policy rule ID (get one from
                checkpoint_get_policy_metadata).
        """
        client = client_factory()
        if client is None:
            return NO_TOKEN
        try:
            result = await client.call("GET", f"policy/{rule_id}/assignments")
            return dump_json_capped(result)
        except CheckPointError as e:
            return e.to_envelope()

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
    async def checkpoint_get_remediation_results_slim(
        remediation_id: str, offset: int = 0, page_size: int = 150
    ) -> str:
        """Get a slim (summary) result set for a remediation/response action.

        Args:
            remediation_id: Required. The remediation action ID (get one
                from checkpoint_get_remediation_status).
            offset: Optional. Pagination offset. Default 0.
            page_size: Optional. Page size. Default 150, max 200.
        """
        client = client_factory()
        if client is None:
            return NO_TOKEN
        page_size = min(page_size, _MAX_PAGE_SIZE)
        try:
            result = await client.call(
                "POST",
                f"remediation/{remediation_id}/results/slim",
                json_body={"paging": {"offset": offset, "pageSize": page_size}},
            )
            return dump_json_capped(result)
        except CheckPointError as e:
            return e.to_envelope()

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
    async def checkpoint_get_quarantine_files(offset: int = 0, page_size: int = 100) -> str:
        """List quarantined files across the organization.

        Args:
            offset: Optional. Pagination offset. Default 0.
            page_size: Optional. Page size. Default 100, max 200.
        """
        client = client_factory()
        if client is None:
            return NO_TOKEN
        page_size = min(page_size, _MAX_PAGE_SIZE)
        try:
            result = await client.call(
                "POST",
                "quarantine-management/file/data",
                json_body={"paging": {"offset": offset, "pageSize": page_size}},
            )
            return dump_json_capped(result)
        except CheckPointError as e:
            return e.to_envelope()

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
    async def checkpoint_get_vulnerability_data(offset: int = 0, page_size: int = 100) -> str:
        """List vulnerability posture findings across the organization.

        Args:
            offset: Optional. Pagination offset. Default 0.
            page_size: Optional. Page size. Default 100, max 200.
        """
        client = client_factory()
        if client is None:
            return NO_TOKEN
        page_size = min(page_size, _MAX_PAGE_SIZE)
        try:
            result = await client.call(
                "GET", "posture/vulnerability/data", params={"offset": offset, "pageSize": page_size}
            )
            return dump_json_capped(result)
        except CheckPointError as e:
            return e.to_envelope()

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
    async def checkpoint_search_organization_tree(
        search_term: str = "",
        search_type: str = "CONTAINS",
        entity_types: list[str] | None = None,
        offset: int = 0,
        page_size: int = 100,
    ) -> str:
        """Search the organization tree (groups, users, computers).

        Args:
            search_term: Optional. Text to search for. Default "" (no filter).
            search_type: Optional. Match type, e.g. "CONTAINS" (default) or
                "EQUALS".
            entity_types: Optional. Entity types to include. Default
                ["GROUP", "VIRTUAL_GROUP", "USER", "COMPUTER", "OFFLINE_GROUP"].
            offset: Optional. Pagination offset. Default 0.
            page_size: Optional. Page size. Default 100, max 200.
        """
        client = client_factory()
        if client is None:
            return NO_TOKEN
        if entity_types is None:
            entity_types = ["GROUP", "VIRTUAL_GROUP", "USER", "COMPUTER", "OFFLINE_GROUP"]
        page_size = min(page_size, _MAX_PAGE_SIZE)
        try:
            result = await client.call(
                "POST",
                "organization/tree/search",
                json_body={
                    "paging": {"offset": offset, "pageSize": page_size},
                    "searchTerm": search_term,
                    "searchType": search_type,
                    "entityTypesToSearch": entity_types,
                },
            )
            return dump_json_capped(result)
        except CheckPointError as e:
            return e.to_envelope()

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
    async def checkpoint_get_computers_filtered(filter: dict | None = None) -> str:
        """List managed computers/endpoints, optionally filtered.

        Args:
            filter: Optional. Vendor-defined filter object. Omit for an
                unfiltered listing (matches MSPbots' own configured usage,
                which sends an empty body).
        """
        client = client_factory()
        if client is None:
            return NO_TOKEN
        try:
            result = await client.call(
                "POST", "asset-management/computers/filtered", json_body=filter or {}
            )
            return dump_json_capped(result)
        except CheckPointError as e:
            return e.to_envelope()

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
    async def checkpoint_get_vulnerability_devices(
        device_ids: list[str], offset: int = 0, page_size: int = 100
    ) -> str:
        """Get vulnerability posture details for specific devices.

        Args:
            device_ids: Required. List of device IDs (get them from
                checkpoint_get_vulnerability_scan_status or
                checkpoint_get_computers_filtered).
            offset: Optional. Pagination offset. Default 0.
            page_size: Optional. Page size. Default 100, max 200.
        """
        client = client_factory()
        if client is None:
            return NO_TOKEN
        page_size = min(page_size, _MAX_PAGE_SIZE)
        try:
            result = await client.call(
                "POST",
                "posture/vulnerability/devices",
                json_body={
                    "paging": {"offset": offset, "pageSize": page_size},
                    "deviceIds": device_ids,
                },
            )
            return dump_json_capped(result)
        except CheckPointError as e:
            return e.to_envelope()

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
    async def checkpoint_get_remediation_status() -> str:
        """List the status of remediation/response actions across the
        organization.

        No required parameters.
        """
        client = client_factory()
        if client is None:
            return NO_TOKEN
        try:
            result = await client.call("GET", "remediation/status")
            return dump_json_capped(result)
        except CheckPointError as e:
            return e.to_envelope()

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
    async def checkpoint_get_vulnerability_scan_status() -> str:
        """Get the status of vulnerability scans across the organization.

        No required parameters.
        """
        client = client_factory()
        if client is None:
            return NO_TOKEN
        try:
            result = await client.call("POST", "posture/vulnerability/scan/status", json_body={})
            return dump_json_capped(result)
        except CheckPointError as e:
            return e.to_envelope()

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
    async def checkpoint_get_policy_metadata() -> str:
        """List all Harmony Endpoint policy rules (metadata only — name,
        family, assignment summary, default-rule flag, etc.).

        No required parameters.
        """
        client = client_factory()
        if client is None:
            return NO_TOKEN
        try:
            result = await client.call("GET", "policy/metadata")
            return dump_json_capped(result)
        except CheckPointError as e:
            return e.to_envelope()
