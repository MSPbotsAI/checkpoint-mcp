import asyncio
import json

import httpx

from ._json import error_envelope

_IN_PROGRESS_STATUSES = {"IN_PROGRESS", "PENDING", "RUNNING", "PROCESSING"}

_TIMEOUT = httpx.Timeout(connect=5.0, read=30.0, write=10.0, pool=5.0)
_RETRYABLE_STATUS = {429, 500, 502, 503, 504}
_MAX_RETRIES = 3
_MAX_BACKOFF_SECONDS = 20.0

# One shared connection pool for the process lifetime. No credentials are
# ever stored on it — client_id/access_key/region are passed per-request via
# CheckPointClient instances built from the request-scoped contextvar (see
# server.py), so sharing this pool across tenants/requests is safe.
_http_client: httpx.AsyncClient | None = None


def _get_http_client() -> httpx.AsyncClient:
    global _http_client
    if _http_client is None:
        _http_client = httpx.AsyncClient(timeout=_TIMEOUT)
    return _http_client


# status_code -> (error code, retryable). status_code 0 means a network/
# connection-level failure (no response at all), or a client-side condition
# such as a job that never left an in-progress state.
_STATUS_TO_CODE: dict[int, tuple[str, bool]] = {
    0: ("upstream_error", True),
    400: ("invalid_argument", False),
    401: ("unauthorized", False),
    403: ("unauthorized", False),
    404: ("not_found", False),
    422: ("invalid_argument", False),
    429: ("rate_limited", True),
}


def _classify(status_code: int) -> tuple[str, bool]:
    if status_code in _STATUS_TO_CODE:
        return _STATUS_TO_CODE[status_code]
    if status_code >= 500:
        return "upstream_error", True
    return "invalid_argument", False


class CheckPointError(Exception):
    def __init__(self, status_code: int, message: str):
        self.status_code = status_code
        self.message = message
        super().__init__(f"Check Point Harmony Endpoint API error {status_code}: {message}")

    def to_envelope(self) -> str:
        code, retryable = _classify(self.status_code)
        return error_envelope(code, self.message, retryable)


def _retry_delay(resp: httpx.Response, attempt: int) -> float:
    retry_after = resp.headers.get("Retry-After")
    if retry_after:
        try:
            return min(float(retry_after), _MAX_BACKOFF_SECONDS)
        except ValueError:
            pass
    return min(2**attempt, _MAX_BACKOFF_SECONDS)


async def _request_with_retry(
    client: httpx.AsyncClient, method: str, url: str, **kwargs
) -> httpx.Response:
    """Issue one HTTP request with limited retry+backoff for 429/5xx and
    network errors, respecting Retry-After. Returns the raw response
    (callers still inspect status_code/body themselves) so each call
    site's own success-condition logic is unchanged.
    """
    last_exc: Exception | None = None
    for attempt in range(_MAX_RETRIES + 1):
        try:
            resp = await client.request(method, url, **kwargs)
        except httpx.RequestError as e:
            last_exc = e
            if attempt < _MAX_RETRIES:
                await asyncio.sleep(min(2**attempt, _MAX_BACKOFF_SECONDS))
                continue
            raise CheckPointError(0, f"{e or type(e).__name__} (url={url})") from e

        if resp.status_code in _RETRYABLE_STATUS and attempt < _MAX_RETRIES:
            await asyncio.sleep(_retry_delay(resp, attempt))
            continue
        return resp

    # Unreachable in practice (loop always returns or raises above), but
    # keeps type checkers happy and guards against future edits.
    if last_exc:
        raise CheckPointError(0, f"{last_exc}") from last_exc
    raise CheckPointError(0, "request failed with no response")


class CheckPointClient:
    """Async httpx client wrapping the Check Point Harmony Endpoint Web
    Management API.

    Auth is a 2-step exchange, both steps required on every call to stay
    stateless (the resulting apiToken is valid only ~6 minutes, far too
    short to cache across MCP requests anyway):

      1. POST {region}/auth/external {clientId, accessKey}
         -> a portal-wide bearer token (data.token), ~30 min TTL.
      2. POST {region}/app/endpoint-web-mgmt/harmony/endpoint/api/v1/session/login/cloud
         with "Authorization: Bearer <portal token>"
         -> a management-service apiToken (apiToken), ~6 min TTL.

    Every real endpoint-web-mgmt call then requires BOTH
    "Authorization: Bearer <portal token>" AND "x-mgmt-api-token: <apiToken>"
    together, plus "x-mgmt-run-as-job: on" — every method MSPbots uses on
    this integration is asynchronous: the initial call returns only a
    {"jobId": ...}, and the real result must be fetched by polling
    GET .../jobs/{jobId} until the job's status leaves an in-progress state.

    All HTTP calls go through the shared module-level connection pool
    (_get_http_client) with retry+backoff for 429/5xx (see
    _request_with_retry), rather than opening a new client per call.
    """

    def __init__(self, client_id: str, access_key: str, region: str):
        self._client_id = client_id
        self._access_key = access_key
        self._region = region.rstrip("/")

    async def _login(self, client: httpx.AsyncClient) -> tuple[str, str]:
        auth_resp = await _request_with_retry(
            client,
            "POST",
            f"{self._region}/auth/external",
            json={"clientId": self._client_id, "accessKey": self._access_key},
        )
        if auth_resp.status_code >= 400:
            raise CheckPointError(auth_resp.status_code, f"auth/external: {auth_resp.text}")
        auth_data = auth_resp.json()
        if not auth_data.get("success"):
            raise CheckPointError(auth_resp.status_code, f"auth/external failed: {auth_resp.text}")
        portal_token = auth_data["data"]["token"]

        session_resp = await _request_with_retry(
            client,
            "POST",
            f"{self._region}/app/endpoint-web-mgmt/harmony/endpoint/api/v1/session/login/cloud",
            headers={"Authorization": f"Bearer {portal_token}"},
        )
        if session_resp.status_code >= 400:
            raise CheckPointError(
                session_resp.status_code, f"session/login/cloud: {session_resp.text}"
            )
        api_token = session_resp.json().get("apiToken")
        if not api_token:
            raise CheckPointError(
                session_resp.status_code,
                f"session/login/cloud did not return an apiToken: {session_resp.text}",
            )
        return portal_token, api_token

    def _clean(self, params: dict | None) -> dict:
        if not params:
            return {}
        return {k: v for k, v in params.items() if v is not None}

    async def _submit(
        self,
        client: httpx.AsyncClient,
        portal_token: str,
        api_token: str,
        method: str,
        path: str,
        params: dict | None,
        json_body: dict | None,
    ) -> str:
        headers = {
            "Authorization": f"Bearer {portal_token}",
            "x-mgmt-api-token": api_token,
            "x-mgmt-run-as-job": "on",
        }
        resp = await _request_with_retry(
            client,
            method,
            f"{self._region}/app/endpoint-web-mgmt/harmony/endpoint/api/v1/{path}",
            headers=headers,
            params=self._clean(params),
            json=json_body,
        )
        if resp.status_code >= 400:
            raise CheckPointError(resp.status_code, f"calling {path}: {resp.text}")
        job_id = resp.json().get("jobId")
        if not job_id:
            raise CheckPointError(resp.status_code, f"{path} did not return a jobId: {resp.text}")
        return job_id

    async def _poll(
        self,
        client: httpx.AsyncClient,
        portal_token: str,
        api_token: str,
        job_id: str,
        timeout: float = 30.0,
        interval: float = 1.0,
    ) -> dict:
        headers = {
            "Authorization": f"Bearer {portal_token}",
            "x-mgmt-api-token": api_token,
        }
        elapsed = 0.0
        while True:
            resp = await _request_with_retry(
                client,
                "GET",
                f"{self._region}/app/endpoint-web-mgmt/harmony/endpoint/api/v1/jobs/{job_id}",
                headers=headers,
            )
            if resp.status_code >= 400:
                raise CheckPointError(resp.status_code, f"polling job {job_id}: {resp.text}")
            result = resp.json()
            if result.get("status") not in _IN_PROGRESS_STATUSES:
                return result
            if elapsed >= timeout:
                raise CheckPointError(
                    0, f"job {job_id} did not finish within {timeout}s: {json.dumps(result)}"
                )
            await asyncio.sleep(interval)
            elapsed += interval

    async def call(
        self,
        method: str,
        path: str,
        params: dict | None = None,
        json_body: dict | None = None,
    ) -> dict:
        client = _get_http_client()
        portal_token, api_token = await self._login(client)
        job_id = await self._submit(client, portal_token, api_token, method, path, params, json_body)
        return await self._poll(client, portal_token, api_token, job_id)
