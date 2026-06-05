"""HTTP primitives shared by all section clients.

Maps httpx errors at the boundary into the ThreatrayError hierarchy so callers
never see raw httpx exceptions.
"""

from typing import Any

import httpx

from ..config import settings
from ..errors import (
    ThreatrayAuthError,
    ThreatrayBadRequest,
    ThreatrayConnectionError,
    ThreatrayError,
    ThreatrayForbiddenError,
    ThreatrayNotFound,
    ThreatrayRateLimitError,
    ThreatrayServerError,
    ThreatrayTimeoutError,
)


def _map_status_error(e: httpx.HTTPStatusError) -> ThreatrayError:  # noqa: PLR0911 — dispatch table by status code
    """Translate an httpx.HTTPStatusError into the matching ThreatrayError subclass."""
    status = e.response.status_code
    body = e.response.text[:200] if e.response.text else ""
    if status == 400:
        return ThreatrayBadRequest(f"Invalid request: {body}".rstrip(": "), status)
    if status == 401:
        return ThreatrayAuthError(
            "Authentication failed. Confirm THREATRAY_API_KEY is correct and that "
            f"THREATRAY_API_URL ({settings.api_url}) points at the realm your key belongs to.",
            status,
        )
    if status == 403:
        return ThreatrayForbiddenError("Access denied for this resource.", status)
    if status == 404:
        return ThreatrayNotFound("Resource not found.", status)
    if status == 429:
        return ThreatrayRateLimitError("Rate limit exceeded; back off and retry.", status)
    if 500 <= status < 600:
        return ThreatrayServerError(f"Server error {status}: {body}".rstrip(": "), status)
    return ThreatrayError(f"HTTP {status}: {body}".rstrip(": "), status)


_DEFAULT_TIMEOUT = httpx.Timeout(60.0, connect=10.0)

# Per-endpoint client-side timeouts. Values are sized to comfortably exceed
# the typical Threatray API response time for the corresponding route so the
# client doesn't abort prematurely.
TIMEOUT_LONG = httpx.Timeout(200.0, connect=10.0)             # /v1/search, retrohunt
TIMEOUT_CODE_DETECTIONS = httpx.Timeout(210.0, connect=10.0)
TIMEOUT_FUNCTIONS_DIFF = httpx.Timeout(920.0, connect=10.0)   # /v1/functions/diff
TIMEOUT_DOWNLOAD = httpx.Timeout(120.0, connect=10.0)         # /v1/files/{hash}/data — variable size
TIMEOUT_SUBMIT_SHORT = httpx.Timeout(60.0, connect=10.0)      # /v1/submissions, /v1/submissions/urls
TIMEOUT_SUBMIT_LONG = httpx.Timeout(320.0, connect=10.0)      # /v1/submissions/samples, minidump, mans-file
TIMEOUT_SUBMIT_MEDIUM = httpx.Timeout(140.0, connect=10.0)    # endpoint-scan-archive


class HttpClient:
    """Wraps an httpx.AsyncClient with Threatray base URL, auth, content-type plumbing,
    and httpx-to-ThreatrayError mapping at the boundary.

    Production callers pass a shared httpx.AsyncClient configured in the server
    lifespan; that client's `timeout` is the default for every request. Section
    clients can override on a per-request basis by passing a `timeout` argument.
    """

    def __init__(self, http_client: httpx.AsyncClient | None = None):
        self.base_url = settings.api_url
        self.headers = settings.get_headers()
        self._external_client = http_client

    async def request(
        self,
        method: str,
        path: str,
        params: dict[str, Any] | None = None,
        json: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
        timeout: httpx.Timeout | float | None = None,
    ) -> httpx.Response:
        url = f"{self.base_url}{path}"
        request_headers = {**self.headers, **(headers or {})}
        try:
            if self._external_client:
                kwargs: dict[str, Any] = {"headers": request_headers, "params": params, "json": json}
                if timeout is not None:
                    kwargs["timeout"] = timeout
                response = await self._external_client.request(method, url, **kwargs)
            else:
                async with httpx.AsyncClient(timeout=timeout or _DEFAULT_TIMEOUT) as client:
                    response = await client.request(method, url, headers=request_headers, params=params, json=json)
        except httpx.TimeoutException as e:
            raise ThreatrayTimeoutError("Request timed out.", None) from e
        except httpx.ConnectError as e:
            raise ThreatrayConnectionError(
                f"Could not connect to Threatray API at {self.base_url}. "
                "Check network connectivity and THREATRAY_API_URL.",
                None,
            ) from e
        try:
            response.raise_for_status()
        except httpx.HTTPStatusError as e:
            raise _map_status_error(e) from e
        return response

    async def get(
        self,
        path: str,
        params: dict[str, Any] | None = None,
        timeout: httpx.Timeout | float | None = None,
    ) -> dict[str, Any]:
        response = await self.request("GET", path, params=params, timeout=timeout)
        result: dict[str, Any] = response.json()
        return result

    async def get_binary(
        self,
        path: str,
        params: dict[str, Any] | None = None,
        timeout: httpx.Timeout | float | None = None,
    ) -> bytes:
        response = await self.request(
            "GET", path, params=params, headers={"Accept": "application/octet-stream"}, timeout=timeout
        )
        return response.content

    async def post(
        self,
        path: str,
        data: dict[str, Any],
        timeout: httpx.Timeout | float | None = None,
    ) -> dict[str, Any]:
        response = await self.request("POST", path, json=data, timeout=timeout)
        result: dict[str, Any] = response.json()
        return result

    async def post_multipart(  # noqa: PLR0912 — multipart form prep + transport-error mapping is inherently branchy
        self,
        path: str,
        files: dict[str, tuple[str, bytes, str]] | None = None,
        fields: dict[str, Any] | None = None,
        timeout: httpx.Timeout | float | None = None,
    ) -> dict[str, Any]:
        """POST a multipart/form-data request.

        `files` maps field name → (filename, bytes, content_type). `fields` maps
        form field name → value. Lists are flattened into repeated form fields.
        """
        url = f"{self.base_url}{path}"
        # Don't send our default Content-Type: application/json — httpx sets the right
        # multipart boundary header when `files` is provided.
        request_headers = {k: v for k, v in self.headers.items() if k.lower() != "content-type"}
        # httpx 0.28 requires data to be a dict (not list-of-tuples) when used with
        # AsyncClient — the list form builds a SyncByteStream that AsyncClient rejects.
        # Dict-with-list-values handles repeated fields (environments=[a,b] → environments=a&environments=b).
        form_data: dict[str, Any] = {}
        for key, value in (fields or {}).items():
            if value is None:
                continue
            if isinstance(value, list):
                form_data[key] = [str(item) for item in value]
            elif isinstance(value, bool):
                form_data[key] = "true" if value else "false"
            else:
                form_data[key] = str(value)
        try:
            if self._external_client:
                kwargs: dict[str, Any] = {"headers": request_headers, "data": form_data}
                if files:
                    kwargs["files"] = files
                if timeout is not None:
                    kwargs["timeout"] = timeout
                response = await self._external_client.request("POST", url, **kwargs)
            else:
                kwargs2: dict[str, Any] = {"headers": request_headers, "data": form_data}
                if files:
                    kwargs2["files"] = files
                async with httpx.AsyncClient(timeout=timeout or _DEFAULT_TIMEOUT) as client:
                    response = await client.request("POST", url, **kwargs2)
        except httpx.TimeoutException as e:
            raise ThreatrayTimeoutError("Submission request timed out.", None) from e
        except httpx.ConnectError as e:
            raise ThreatrayConnectionError(
                f"Could not connect to Threatray API at {self.base_url}. "
                "Check network connectivity and THREATRAY_API_URL.",
                None,
            ) from e
        try:
            response.raise_for_status()
        except httpx.HTTPStatusError as e:
            raise _map_status_error(e) from e
        result: dict[str, Any] = response.json()
        return result
