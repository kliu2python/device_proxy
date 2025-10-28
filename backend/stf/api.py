"""Helpers for interacting with the STF REST API."""

from __future__ import annotations

from typing import Any, Dict, Optional

import httpx

DEFAULT_ACTIONS: Dict[str, Dict[str, Any]] = {
    "use": {
        "method": "POST",
        "path": "/api/v1/user/devices/{serial}/use",
        "expect_json": True,
    },
    "stop": {
        "method": "DELETE",
        "path": "/api/v1/user/devices/{serial}/use",
        "expect_json": True,
    },
    "install": {
        "method": "POST",
        "path": "/api/v1/user/devices/{serial}/install",
        "expect_json": True,
    },
    "screenshot": {
        "method": "POST",
        "path": "/api/v1/user/devices/{serial}/screenshot",
        "expect_json": True,
    },
    "device": {
        "method": "GET",
        "path": "/api/v1/devices/{serial}",
        "expect_json": True,
    },
}


class StfApiError(RuntimeError):
    """Raised when the STF API responds with an error status."""

    def __init__(self, message: str, *, status_code: Optional[int] = None):
        super().__init__(message)
        self.status_code = status_code


class StfApiClient:
    """Minimal async HTTP client for the STF REST API."""

    def __init__(
        self,
        *,
        base_url: str,
        token: Optional[str] = None,
        timeout: Optional[float] = None,
        verify_ssl: bool = True,
    ) -> None:
        if not isinstance(base_url, str) or not base_url.strip():
            raise ValueError("STF API base_url must be a non-empty string")

        self.base_url = base_url.rstrip("/")
        self.token = token.strip() if isinstance(token, str) else None
        self.timeout = float(timeout) if timeout else 15.0
        self.verify_ssl = bool(verify_ssl)

    def _build_headers(self, extra: Optional[Dict[str, str]] = None) -> Dict[str, str]:
        headers: Dict[str, str] = {"Accept": "application/json"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        if extra:
            for key, value in extra.items():
                if isinstance(key, str) and value is not None:
                    headers[key] = str(value)
        return headers

    async def request(
        self,
        method: str,
        path: str,
        *,
        params: Optional[Dict[str, Any]] = None,
        json: Optional[Any] = None,
        data: Optional[Any] = None,
        files: Optional[Any] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> httpx.Response:
        if not isinstance(method, str) or not method.strip():
            raise ValueError("HTTP method must be provided for STF API request")

        method = method.strip().upper()
        url = path
        if not (url.startswith("http://") or url.startswith("https://")):
            prefix = "" if path.startswith("/") else "/"
            url = f"{self.base_url}{prefix}{path}"

        request_headers = self._build_headers(headers)

        async with httpx.AsyncClient(timeout=self.timeout, verify=self.verify_ssl) as client:
            response = await client.request(
                method,
                url,
                params=params,
                json=json,
                data=data,
                files=files,
                headers=request_headers,
            )

        if response.is_error:
            message = f"STF API request failed with status {response.status_code}"
            try:
                payload = response.json()
            except Exception:  # pragma: no cover - defensive decode guard
                payload = None

            if isinstance(payload, dict):
                detail = payload.get("detail") or payload.get("error") or payload.get("message")
                if isinstance(detail, str) and detail.strip():
                    message = detail.strip()

            raise StfApiError(message, status_code=response.status_code)

        return response


__all__ = ["DEFAULT_ACTIONS", "StfApiClient", "StfApiError"]
