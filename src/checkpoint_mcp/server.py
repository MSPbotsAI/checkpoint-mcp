import contextvars
from collections.abc import Callable

from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

from .api_client import CheckPointClient
from .config import Settings

# Per-request credential isolation via contextvars.
# GatewayTokenMiddleware sets this before the MCP handler runs.
# Python asyncio copies context per task, so concurrent SSE connections are isolated.
_gateway_creds_var: contextvars.ContextVar[tuple[str, str, str] | None] = contextvars.ContextVar(
    "checkpoint_gateway_creds", default=None
)


def get_client_from_context(settings: Settings) -> CheckPointClient | None:
    """Resolve the active CheckPointClient for the current request context."""
    creds = _gateway_creds_var.get()
    if not creds:
        return None
    client_id, access_key, region = creds
    return CheckPointClient(client_id, access_key, region)


class GatewayTokenMiddleware:
    """ASGI middleware.

    Reads X-CheckPoint-Client-Id, X-CheckPoint-Access-Key, and
    X-CheckPoint-Region (all required) from request headers and stores
    them in the contextvar. Returns 401 if any is missing on /mcp requests.
    """

    def __init__(self, app: ASGIApp, settings: Settings):
        self.app = app
        self.settings = settings

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        path = scope.get("path", "")
        if not path.startswith("/mcp"):
            await self.app(scope, receive, send)
            return

        request = Request(scope)
        client_id = request.headers.get("x-checkpoint-client-id")
        access_key = request.headers.get("x-checkpoint-access-key")
        region = request.headers.get("x-checkpoint-region")
        if not client_id or not access_key or not region:
            response = JSONResponse(
                {
                    "error": "Missing credentials",
                    "message": (
                        "This server requires the X-CheckPoint-Client-Id, "
                        "X-CheckPoint-Access-Key, and X-CheckPoint-Region headers"
                    ),
                    "required_headers": [
                        "X-CheckPoint-Client-Id",
                        "X-CheckPoint-Access-Key",
                        "X-CheckPoint-Region",
                    ],
                    "optional_headers": [],
                },
                status_code=401,
            )
            await response(scope, receive, send)
            return

        ctx_token = _gateway_creds_var.set((client_id, access_key, region))
        try:
            await self.app(scope, receive, send)
        finally:
            _gateway_creds_var.reset(ctx_token)


def create_mcp_server(settings: Settings) -> FastMCP:
    """Build the FastMCP server instance and register all Check Point tools."""
    # DNS-rebinding protection is a browser-oriented safeguard that rejects
    # non-localhost Host headers with 421. Disable it so the server works
    # correctly behind a reverse proxy or docker network.
    mcp = FastMCP(
        name="checkpoint-mcp",
        instructions=(
            "Check Point Harmony Endpoint is a cloud-managed endpoint protection / "
            "EDR platform for an organization's computers (agents). Core concepts: "
            "policy rules (threat-prevention config assigned to computers/groups), "
            "remediation actions (investigation/response tasks run on endpoints), "
            "quarantine (isolated suspicious files), vulnerability posture "
            "(missing patches/CVEs per device), and the organization tree "
            "(groups, users, computers). Every underlying API call is an async "
            "job; tools submit the job and poll it to completion internally, so "
            "results are returned directly without extra client-side polling. "
            "Typical flow: checkpoint_get_policy_metadata to find a policy rule "
            "ID, then checkpoint_get_policy_assignments / "
            "checkpoint_get_policy_modifications for what it applies to and its "
            "change history. checkpoint_search_organization_tree or "
            "checkpoint_get_computers_filtered to find computers/groups, then "
            "checkpoint_get_vulnerability_devices for their CVE exposure. "
            "checkpoint_get_vulnerability_data and "
            "checkpoint_get_vulnerability_scan_status give org-wide vulnerability "
            "posture and scan status. checkpoint_get_remediation_status lists "
            "response actions; checkpoint_get_remediation_results_slim gets one "
            "action's results. checkpoint_get_quarantine_files lists isolated "
            "files. All 11 tools are read-only queries; there are no write/delete "
            "tools in this service."
        ),
        transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False),
    )

    client_factory: Callable[[], CheckPointClient | None] = lambda: get_client_from_context(settings)

    from .tools import resources

    resources.register(mcp, client_factory)

    return mcp
