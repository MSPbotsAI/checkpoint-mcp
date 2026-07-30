import asyncio
import json

import httpx

_IN_PROGRESS_STATUSES = {"IN_PROGRESS", "PENDING", "RUNNING", "PROCESSING"}


class CheckPointError(Exception):
    def __init__(self, message: str):
        super().__init__(f"Check Point Harmony Endpoint API error: {message}")


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
    """

    def __init__(self, client_id: str, access_key: str, region: str):
        self._client_id = client_id
        self._access_key = access_key
        self._region = region.rstrip("/")

    async def _login(self, client: httpx.AsyncClient) -> tuple[str, str]:
        try:
            auth_resp = await client.post(
                f"{self._region}/auth/external",
                json={"clientId": self._client_id, "accessKey": self._access_key},
            )
        except httpx.RequestError as e:
            raise CheckPointError(f"{e or type(e).__name__} (auth/external)") from e
        if auth_resp.status_code >= 400:
            raise CheckPointError(f"HTTP {auth_resp.status_code} during auth/external: {auth_resp.text}")
        auth_data = auth_resp.json()
        if not auth_data.get("success"):
            raise CheckPointError(f"auth/external failed: {auth_resp.text}")
        portal_token = auth_data["data"]["token"]

        try:
            session_resp = await client.post(
                f"{self._region}/app/endpoint-web-mgmt/harmony/endpoint/api/v1/session/login/cloud",
                headers={"Authorization": f"Bearer {portal_token}"},
            )
        except httpx.RequestError as e:
            raise CheckPointError(f"{e or type(e).__name__} (session/login/cloud)") from e
        if session_resp.status_code >= 400:
            raise CheckPointError(
                f"HTTP {session_resp.status_code} during session/login/cloud: {session_resp.text}"
            )
        api_token = session_resp.json().get("apiToken")
        if not api_token:
            raise CheckPointError(f"session/login/cloud did not return an apiToken: {session_resp.text}")
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
        try:
            resp = await client.request(
                method,
                f"{self._region}/app/endpoint-web-mgmt/harmony/endpoint/api/v1/{path}",
                headers=headers,
                params=self._clean(params),
                json=json_body,
            )
        except httpx.RequestError as e:
            raise CheckPointError(f"{e or type(e).__name__} (path={path})") from e
        if resp.status_code >= 400:
            raise CheckPointError(f"HTTP {resp.status_code} calling {path}: {resp.text}")
        job_id = resp.json().get("jobId")
        if not job_id:
            raise CheckPointError(f"{path} did not return a jobId: {resp.text}")
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
            try:
                resp = await client.get(
                    f"{self._region}/app/endpoint-web-mgmt/harmony/endpoint/api/v1/jobs/{job_id}",
                    headers=headers,
                )
            except httpx.RequestError as e:
                raise CheckPointError(f"{e or type(e).__name__} (jobs/{job_id})") from e
            if resp.status_code >= 400:
                raise CheckPointError(f"HTTP {resp.status_code} polling job {job_id}: {resp.text}")
            result = resp.json()
            if result.get("status") not in _IN_PROGRESS_STATUSES:
                return result
            if elapsed >= timeout:
                raise CheckPointError(f"job {job_id} did not finish within {timeout}s: {json.dumps(result)}")
            await asyncio.sleep(interval)
            elapsed += interval

    async def call(
        self,
        method: str,
        path: str,
        params: dict | None = None,
        json_body: dict | None = None,
    ) -> dict:
        async with httpx.AsyncClient(timeout=30.0) as client:
            portal_token, api_token = await self._login(client)
            job_id = await self._submit(client, portal_token, api_token, method, path, params, json_body)
            return await self._poll(client, portal_token, api_token, job_id)
