import json
from collections.abc import Callable

from mcp.server.fastmcp import FastMCP

from ..api_client import CheckPointClient, CheckPointError
from ._common import NO_TOKEN


def register(mcp: FastMCP, client_factory: Callable[[], CheckPointClient | None]) -> None:

    @mcp.tool()
    async def checkpoint_get_policy_modifications(rule_id: str) -> str:
        """List the modification history of a Harmony Endpoint policy rule.

        API: GET policy/{rule_id}/modifications (async job)

        Args:
            rule_id: Required. The policy rule ID (get one from
                checkpoint_get_policy_metadata).
        """
        client = client_factory()
        if client is None:
            return NO_TOKEN
        try:
            result = await client.call("GET", f"policy/{rule_id}/modifications")
            return json.dumps(result, indent=2)
        except CheckPointError as e:
            return f"Error: {e}"

    @mcp.tool()
    async def checkpoint_get_policy_assignments(rule_id: str) -> str:
        """List what a Harmony Endpoint policy rule is assigned to
        (computers, groups, the whole organization, etc.).

        API: GET policy/{rule_id}/assignments (async job)

        Args:
            rule_id: Required. The policy rule ID (get one from
                checkpoint_get_policy_metadata).
        """
        client = client_factory()
        if client is None:
            return NO_TOKEN
        try:
            result = await client.call("GET", f"policy/{rule_id}/assignments")
            return json.dumps(result, indent=2)
        except CheckPointError as e:
            return f"Error: {e}"

    @mcp.tool()
    async def checkpoint_get_remediation_results_slim(
        remediation_id: str, offset: int = 0, page_size: int = 150
    ) -> str:
        """Get a slim (summary) result set for a remediation/response action.

        API: POST remediation/{remediation_id}/results/slim (async job)

        Args:
            remediation_id: Required. The remediation action ID (get one
                from checkpoint_get_remediation_status).
            offset: Optional. Pagination offset. Default 0.
            page_size: Optional. Page size. Default 150.
        """
        client = client_factory()
        if client is None:
            return NO_TOKEN
        try:
            result = await client.call(
                "POST",
                f"remediation/{remediation_id}/results/slim",
                json_body={"paging": {"offset": offset, "pageSize": page_size}},
            )
            return json.dumps(result, indent=2)
        except CheckPointError as e:
            return f"Error: {e}"

    @mcp.tool()
    async def checkpoint_get_quarantine_files(offset: int = 0, page_size: int = 100) -> str:
        """List quarantined files across the organization.

        API: POST quarantine-management/file/data (async job)

        Args:
            offset: Optional. Pagination offset. Default 0.
            page_size: Optional. Page size. Default 100.
        """
        client = client_factory()
        if client is None:
            return NO_TOKEN
        try:
            result = await client.call(
                "POST",
                "quarantine-management/file/data",
                json_body={"paging": {"offset": offset, "pageSize": page_size}},
            )
            return json.dumps(result, indent=2)
        except CheckPointError as e:
            return f"Error: {e}"

    @mcp.tool()
    async def checkpoint_get_vulnerability_data(offset: int = 0, page_size: int = 100) -> str:
        """List vulnerability posture findings across the organization.

        API: GET posture/vulnerability/data (async job)

        Args:
            offset: Optional. Pagination offset. Default 0.
            page_size: Optional. Page size. Default 100.
        """
        client = client_factory()
        if client is None:
            return NO_TOKEN
        try:
            result = await client.call(
                "GET", "posture/vulnerability/data", params={"offset": offset, "pageSize": page_size}
            )
            return json.dumps(result, indent=2)
        except CheckPointError as e:
            return f"Error: {e}"

    @mcp.tool()
    async def checkpoint_search_organization_tree(
        search_term: str = "",
        search_type: str = "CONTAINS",
        entity_types: list[str] | None = None,
        offset: int = 0,
        page_size: int = 100,
    ) -> str:
        """Search the organization tree (groups, users, computers).

        API: POST organization/tree/search (async job)

        Args:
            search_term: Optional. Text to search for. Default "" (no filter).
            search_type: Optional. One of "CONTAINS" (default), "EQUALS",
                or other vendor-supported match types.
            entity_types: Optional. Entity types to include. Default
                ["GROUP", "VIRTUAL_GROUP", "USER", "COMPUTER", "OFFLINE_GROUP"]
                (matches MSPbots' own configured usage).
            offset: Optional. Pagination offset. Default 0.
            page_size: Optional. Page size. Default 100.
        """
        client = client_factory()
        if client is None:
            return NO_TOKEN
        if entity_types is None:
            entity_types = ["GROUP", "VIRTUAL_GROUP", "USER", "COMPUTER", "OFFLINE_GROUP"]
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
            return json.dumps(result, indent=2)
        except CheckPointError as e:
            return f"Error: {e}"

    @mcp.tool()
    async def checkpoint_get_computers_filtered(filter: dict | None = None) -> str:
        """List managed computers/endpoints, optionally filtered.

        API: POST asset-management/computers/filtered (async job)

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
            return json.dumps(result, indent=2)
        except CheckPointError as e:
            return f"Error: {e}"

    @mcp.tool()
    async def checkpoint_get_vulnerability_devices(
        device_ids: list[str], offset: int = 0, page_size: int = 100
    ) -> str:
        """Get vulnerability posture details for specific devices.

        API: POST posture/vulnerability/devices (async job)

        Args:
            device_ids: Required. List of device IDs (get them from
                checkpoint_get_vulnerability_scan_status or
                checkpoint_get_computers_filtered).
            offset: Optional. Pagination offset. Default 0.
            page_size: Optional. Page size. Default 100.
        """
        client = client_factory()
        if client is None:
            return NO_TOKEN
        try:
            result = await client.call(
                "POST",
                "posture/vulnerability/devices",
                json_body={
                    "paging": {"offset": offset, "pageSize": page_size},
                    "deviceIds": device_ids,
                },
            )
            return json.dumps(result, indent=2)
        except CheckPointError as e:
            return f"Error: {e}"

    @mcp.tool()
    async def checkpoint_get_remediation_status() -> str:
        """List the status of remediation/response actions across the
        organization.

        API: GET remediation/status (async job)

        No required parameters.
        """
        client = client_factory()
        if client is None:
            return NO_TOKEN
        try:
            result = await client.call("GET", "remediation/status")
            return json.dumps(result, indent=2)
        except CheckPointError as e:
            return f"Error: {e}"

    @mcp.tool()
    async def checkpoint_get_vulnerability_scan_status() -> str:
        """Get the status of vulnerability scans across the organization.

        API: POST posture/vulnerability/scan/status (async job)

        No required parameters.
        """
        client = client_factory()
        if client is None:
            return NO_TOKEN
        try:
            result = await client.call("POST", "posture/vulnerability/scan/status", json_body={})
            return json.dumps(result, indent=2)
        except CheckPointError as e:
            return f"Error: {e}"

    @mcp.tool()
    async def checkpoint_get_policy_metadata() -> str:
        """List all Harmony Endpoint policy rules (metadata only — name,
        family, assignment summary, default-rule flag, etc.).

        API: GET policy/metadata (async job)

        No required parameters.
        """
        client = client_factory()
        if client is None:
            return NO_TOKEN
        try:
            result = await client.call("GET", "policy/metadata")
            return json.dumps(result, indent=2)
        except CheckPointError as e:
            return f"Error: {e}"
