import base64
import csv
import hmac
import io
import json
import logging
import os
import secrets
import time
import uuid
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set

import redis.asyncio as aioredis
from fastapi import APIRouter, Depends, Header, HTTPException
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, Field

from backend.session_state import (
    cache_stf_jwt,
    create_stf_reservation,
    get_cached_stf_jwt,
    release_stf_reservation,
)
from backend.stf import DEFAULT_ACTIONS as DEFAULT_STF_ACTIONS, StfApiClient, StfApiError

router = APIRouter()
redis_client = aioredis.from_url("redis://10.160.13.16:6379/0", decode_responses=True)

logger = logging.getLogger(__name__)

NODE_RESOURCES_CSV = Path(__file__).resolve().parent / "node_resources.csv"
NODE_SESSION_COUNTS_KEY = "node_session_counts"
ADMIN_USERNAME_ENV_VAR = "ADMIN_USERNAME"
ADMIN_PASSWORD_ENV_VAR = "ADMIN_PASSWORD"

JWT_EMAIL = "proxy@abc.com"
JWT_NAME = "proxy"
JWT_SECRET = "fortinet"
CSV_TEMPLATE_HEADERS = [
    "id",
    "type",
    "udid",
    "host",
    "port",
    "protocol",
    "path",
    "max_sessions",
    "active_sessions",
    "status",
    "platform",
    "platform_version",
    "device_name",
    "resources",
]

SUPPORTED_DEVICE_POOLS = {"ios", "android", "android-emulator", "web"}

DEFAULT_STF_SESSION_TTL_SECONDS = 15 * 60
DEFAULT_STF_MAX_TTL_SECONDS = 60 * 60


def _coerce_positive_int(value, *, minimum: int = 1) -> Optional[int]:
    if value is None:
        return None
    try:
        result = int(value)
    except (TypeError, ValueError):
        return None

    if result < minimum:
        return None
    return result


def _normalise_bool_flag(value) -> Optional[bool]:
    if isinstance(value, bool):
        return value
    if value is None:
        return None
    if isinstance(value, str):
        lowered = value.strip().lower()
        if not lowered:
            return None
        if lowered in {"true", "1", "yes", "y", "on"}:
            return True
        if lowered in {"false", "0", "no", "n", "off"}:
            return False
    return None


def _strip_or_none(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    value = value.strip()
    return value or None


def _load_global_stf_config() -> Dict:
    config: Dict[str, Optional[str]] = {}

    base_url = _strip_or_none(os.getenv("STF_BASE_URL") or os.getenv("STF_URL"))
    if base_url:
        config["base_url"] = base_url

    template = _strip_or_none(
        os.getenv("STF_CONTROL_URL_TEMPLATE")
        or os.getenv("STF_CONTROL_URL")
        or os.getenv("STF_CONTROL_PATH_TEMPLATE")
        or os.getenv("STF_CONTROL_PATH")
    )
    if template:
        config["control_url_template"] = template

    ttl = _coerce_positive_int(
        os.getenv("STF_SESSION_TTL_SECONDS") or os.getenv("STF_SESSION_TTL")
    )
    if ttl:
        config["session_ttl_seconds"] = ttl

    max_ttl = _coerce_positive_int(
        os.getenv("STF_MAX_SESSION_TTL_SECONDS")
        or os.getenv("STF_MAX_SESSION_TTL")
    )
    if max_ttl:
        config["max_session_ttl_seconds"] = max_ttl

    enabled = _normalise_bool_flag(os.getenv("STF_ENABLED"))
    if enabled is not None:
        config["enabled"] = enabled

    api_base_url = _strip_or_none(os.getenv("STF_API_BASE_URL") or os.getenv("STF_API_URL"))
    if api_base_url:
        config["api_base_url"] = api_base_url

    api_token = _strip_or_none(
        os.getenv("STF_API_TOKEN")
        or os.getenv("STF_API_KEY")
        or os.getenv("STF_TOKEN")
    )
    if api_token:
        config["api_token"] = api_token

    verify_ssl = _normalise_bool_flag(
        os.getenv("STF_API_VERIFY_SSL") or os.getenv("STF_VERIFY_SSL")
    )
    if verify_ssl is not None:
        config["verify_ssl"] = verify_ssl

    api_timeout = _coerce_positive_int(
        os.getenv("STF_API_TIMEOUT_SECONDS") or os.getenv("STF_API_TIMEOUT")
    )
    if api_timeout:
        config["api_timeout_seconds"] = api_timeout

    return config


_GLOBAL_STF_CONFIG = _load_global_stf_config()

_ADMIN_USERNAME = os.getenv(ADMIN_USERNAME_ENV_VAR, "admin")
_ADMIN_PASSWORD = os.getenv(ADMIN_PASSWORD_ENV_VAR, "Fortinet01!")
_ACTIVE_ADMIN_TOKENS: Set[str] = set()


class AdminCredentials(BaseModel):
    username: str
    password: str


class AdminLogoutRequest(BaseModel):
    token: Optional[str] = None


class NodeRegistrationError(Exception):
    """Raised when a node cannot be registered."""


class StfSessionRequest(BaseModel):
    ttl_seconds: Optional[int] = None


class StfUseRequest(BaseModel):
    options: Dict[str, Any] = Field(default_factory=dict)


class StfActionRequest(BaseModel):
    options: Dict[str, Any] = Field(default_factory=dict)


class StfInstallRequest(BaseModel):
    url: Optional[str] = None
    app_url: Optional[str] = None
    package_url: Optional[str] = None
    title: Optional[str] = None
    options: Dict[str, Any] = Field(default_factory=dict)

    def resolve_payload(self) -> Dict[str, Any]:
        payload: Dict[str, Any] = {}

        for candidate in (self.url, self.app_url, self.package_url):
            value = _strip_or_none(candidate) if isinstance(candidate, str) else None
            if value:
                payload["url"] = value
                break

        if "url" not in payload:
            raise HTTPException(
                status_code=400,
                detail="An app URL must be provided to install an application via STF.",
            )

        title = _strip_or_none(self.title)
        if title:
            payload["title"] = title

        for key, value in (self.options or {}).items():
            if key not in payload:
                payload[key] = value

        return payload


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _generate_jwt(*, expires_at: int, udid: Optional[str]) -> str:
    issued_at = int(time.time())
    payload: Dict[str, object] = {
        "email": JWT_EMAIL,
        "name": JWT_NAME,
        "iat": issued_at,
        "exp": int(expires_at),
    }

    if udid:
        payload["udid"] = udid
        payload["scope"] = f"/control/{udid}"

    header = {"alg": "HS256", "typ": "JWT"}

    header_segment = _b64url_encode(
        json.dumps(header, separators=(",", ":"), sort_keys=True).encode("utf-8")
    )
    payload_segment = _b64url_encode(
        json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    )
    signing_input = f"{header_segment}.{payload_segment}".encode("ascii")
    signature = hmac.new(JWT_SECRET.encode("utf-8"), signing_input, sha256).digest()
    signature_segment = _b64url_encode(signature)
    return f"{header_segment}.{payload_segment}.{signature_segment}"


async def _fetch_node(node_id: str) -> Dict:
    node_json = await redis_client.hget("nodes", node_id)
    if not node_json:
        raise HTTPException(status_code=404, detail="Node not found")

    try:
        node = json.loads(node_json)
    except json.JSONDecodeError as exc:
        raise HTTPException(
            status_code=500, detail="Stored node metadata is invalid JSON"
        ) from exc

    return node


def _merge_stf_config(node: Dict) -> Optional[Dict]:
    merged: Dict[str, object] = {}

    if _GLOBAL_STF_CONFIG:
        merged.update(_GLOBAL_STF_CONFIG)

    resources = node.get("resources")
    if isinstance(resources, dict):
        stf_config = resources.get("stf")
        if isinstance(stf_config, dict):
            merged.update(stf_config)

    cleaned: Dict[str, object] = {}
    for key, value in merged.items():
        if value is None:
            continue
        if isinstance(value, str):
            stripped = value.strip()
            if not stripped:
                continue
            cleaned[key] = stripped
        else:
            cleaned[key] = value

    if not cleaned:
        return None

    enabled_flag = _normalise_bool_flag(cleaned.get("enabled"))
    if enabled_flag is False:
        return None
    if enabled_flag is True:
        cleaned["enabled"] = True
    else:
        cleaned.pop("enabled", None)

    base_url = cleaned.get("base_url") or cleaned.get("url")
    if isinstance(base_url, str):
        cleaned["base_url"] = base_url.strip()
    if cleaned.get("base_url") == "":
        cleaned.pop("base_url", None)
    if "url" in cleaned and cleaned.get("url") == cleaned.get("base_url"):
        cleaned.pop("url", None)

    return cleaned


def _ensure_stf_config(node: Dict) -> Dict:
    stf_config = _merge_stf_config(node)
    if not stf_config:
        raise HTTPException(
            status_code=404, detail="Node is not configured for STF access"
        )

    return dict(stf_config)


def _resolve_stf_device_serial(node: Dict, stf_config: Dict) -> str:
    for key in ("serial", "device_serial", "stf_serial"):
        value = stf_config.get(key)
        if isinstance(value, str):
            stripped = value.strip()
            if stripped:
                return stripped

    for source in (node.get("udid"), stf_config.get("udid"), node.get("serial")):
        if isinstance(source, str):
            stripped = source.strip()
            if stripped:
                return stripped

    raise HTTPException(
        status_code=400,
        detail="STF device serial/UDID is not configured for this node.",
    )


def _create_stf_api_client(stf_config: Dict) -> StfApiClient:
    api_base = stf_config.get("api_base_url") or stf_config.get("api_url")
    if not isinstance(api_base, str) or not api_base.strip():
        base_candidate = stf_config.get("base_url") or stf_config.get("url")
        if isinstance(base_candidate, str) and base_candidate.strip():
            api_base = f"{base_candidate.rstrip('/')}/api/v1"

    if not isinstance(api_base, str) or not api_base.strip():
        raise HTTPException(
            status_code=400,
            detail="STF API base URL is not configured for this node.",
        )

    api_base = api_base.strip()

    token: Optional[str] = None
    for key in ("api_token", "apiKey", "api_key", "token", "auth_token"):
        value = stf_config.get(key)
        if isinstance(value, str):
            stripped = value.strip()
            if stripped:
                token = stripped
                break

    verify_setting = stf_config.get("verify_ssl")
    if isinstance(verify_setting, bool):
        verify_ssl = verify_setting
    elif isinstance(verify_setting, str):
        normalised = _normalise_bool_flag(verify_setting)
        verify_ssl = True if normalised is None else normalised
    else:
        verify_ssl = True

    timeout_seconds = (
        _coerce_positive_int(stf_config.get("api_timeout_seconds"))
        or _coerce_positive_int(stf_config.get("api_timeout"))
    )
    timeout = float(timeout_seconds) if timeout_seconds else None

    return StfApiClient(
        base_url=api_base,
        token=token,
        timeout=timeout,
        verify_ssl=verify_ssl,
    )


def _resolve_stf_action_config(stf_config: Dict, action_name: str) -> Dict[str, Any]:
    action = dict(DEFAULT_STF_ACTIONS.get(action_name, {}))

    overrides = stf_config.get("actions")
    if isinstance(overrides, dict):
        override = overrides.get(action_name)
        if isinstance(override, dict):
            for key, value in override.items():
                if value is not None:
                    action[key] = value

    return action


async def _perform_stf_action(
    node: Dict,
    stf_config: Dict,
    action_name: str,
    *,
    payload: Optional[Dict[str, Any]] = None,
):
    action_config = _resolve_stf_action_config(stf_config, action_name)
    if not action_config:
        raise HTTPException(
            status_code=400,
            detail=f"STF action '{action_name}' is not configured for this node.",
        )

    method = action_config.get("method") or action_config.get("http_method") or "POST"
    method = str(method).strip().upper() or "POST"

    path_template = action_config.get("path") or action_config.get("url")
    if not isinstance(path_template, str) or not path_template.strip():
        raise HTTPException(
            status_code=400,
            detail=f"STF action '{action_name}' does not define a valid path template.",
        )

    serial = _resolve_stf_device_serial(node, stf_config)

    try:
        path = path_template.format(
            serial=serial,
            udid=serial,
            node_id=node.get("id"),
            id=node.get("id"),
        )
    except KeyError as exc:
        raise HTTPException(
            status_code=500,
            detail=(
                f"STF action '{action_name}' path references unknown placeholder "
                f"'{exc.args[0]}'"
            ),
        ) from exc

    payload_mode = str(action_config.get("payload_mode") or "json").lower()
    request_kwargs: Dict[str, Any] = {}
    if payload is not None:
        if payload_mode == "json":
            request_kwargs["json"] = payload
        elif payload_mode in {"form", "data"}:
            request_kwargs["data"] = payload
        else:
            request_kwargs["json"] = payload

    headers: Dict[str, str] = {}
    action_headers = action_config.get("headers")
    if isinstance(action_headers, dict):
        for key, value in action_headers.items():
            if isinstance(key, str) and value is not None:
                headers[key] = str(value)

    client = _create_stf_api_client(stf_config)

    try:
        response = await client.request(
            method,
            path,
            headers=headers or None,
            **request_kwargs,
        )
    except StfApiError as exc:
        status = exc.status_code or 502
        detail = str(exc) or f"STF action '{action_name}' failed"
        raise HTTPException(
            status_code=status if 400 <= status <= 599 else 502,
            detail=detail,
        ) from exc

    return response, action_config


def _stf_response_to_fastapi(
    response,
    action_name: str,
    action_config: Dict[str, Any],
):
    expect_json = bool(action_config.get("expect_json", True))
    status_code = response.status_code or 200

    if expect_json:
        if status_code == 204 or not response.content:
            if status_code == 200 and not response.content:
                status_code = 204
            return Response(status_code=status_code)

        try:
            payload = response.json()
        except json.JSONDecodeError as exc:
            raise HTTPException(
                status_code=502,
                detail=f"STF action '{action_name}' returned invalid JSON response.",
            ) from exc

        return JSONResponse(content=payload, status_code=status_code)

    media_type = response.headers.get("Content-Type") or "application/octet-stream"
    return Response(content=response.content, media_type=media_type, status_code=status_code)


def _node_supports_stf(node: Dict) -> bool:
    config = _merge_stf_config(node)
    if not config:
        return False

    try:
        _build_stf_control_url(node, dict(config))
    except HTTPException:
        return False

    return True


def _resolve_stf_session_ttl(stf_config: Dict, request: StfSessionRequest) -> int:
    default_ttl = (
        _coerce_positive_int(stf_config.get("session_ttl_seconds"))
        or _coerce_positive_int(stf_config.get("session_ttl"))
        or DEFAULT_STF_SESSION_TTL_SECONDS
    )

    configured_max = (
        _coerce_positive_int(stf_config.get("max_session_ttl_seconds"))
        or _coerce_positive_int(stf_config.get("max_session_ttl"))
        or DEFAULT_STF_MAX_TTL_SECONDS
    )
    max_ttl = max(configured_max, default_ttl, 1)

    requested = (
        _coerce_positive_int(request.ttl_seconds)
        if request and request.ttl_seconds is not None
        else None
    )

    ttl = requested or default_ttl
    ttl = max(ttl, 1)
    if ttl > max_ttl:
        ttl = max_ttl
    return ttl


def _resolve_stf_control_template(stf_config: Dict) -> Optional[str]:
    for key in (
        "control_url_template",
        "control_url",
        "control_path_template",
        "control_path",
    ):
        value = stf_config.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def _build_stf_control_url(node: Dict, stf_config: Dict) -> str:
    base_url = stf_config.get("base_url") or stf_config.get("url")
    template = _resolve_stf_control_template(stf_config)

    if template is None:
        template = "/#!/control/{udid}"

    udid = node.get("udid") or stf_config.get("udid")
    if "{udid}" in template:
        if not udid:
            raise HTTPException(
                status_code=400,
                detail="STF control URL template requires a UDID but none is configured for this node.",
            )
        template = template.format(udid=udid)

    if template.startswith("http://") or template.startswith("https://"):
        return template

    if not isinstance(base_url, str) or not base_url.strip():
        raise HTTPException(status_code=400, detail="STF configuration missing base_url")

    base_url = base_url.rstrip("/")
    if template.startswith("#"):
        return f"{base_url}/{template}"
    if template.startswith("/"):
        return f"{base_url}{template}"
    if not template:
        return base_url
    return f"{base_url}/{template}"


def _verify_admin_token(admin_token: Optional[str]) -> None:
    if not admin_token:
        raise HTTPException(status_code=403, detail="Admin access required")

    if admin_token not in _ACTIVE_ADMIN_TOKENS:
        raise HTTPException(status_code=403, detail="Admin access required")


def require_admin(
    admin_token: Optional[str] = Header(None, alias="X-Admin-Token")
) -> None:
    """FastAPI dependency used to guard admin-only endpoints."""

    _verify_admin_token(admin_token)


@router.post("/admin/login")
async def admin_login(credentials: AdminCredentials):
    if (
        credentials.username != _ADMIN_USERNAME
        or credentials.password != _ADMIN_PASSWORD
    ):
        raise HTTPException(status_code=403, detail="Invalid credentials")

    token = secrets.token_urlsafe(32)
    _ACTIVE_ADMIN_TOKENS.add(token)
    return {"token": token}


@router.post("/admin/logout")
async def admin_logout(request: AdminLogoutRequest):
    token = request.token
    if token:
        _ACTIVE_ADMIN_TOKENS.discard(token)

    return Response(status_code=204)


async def _physical_udid_exists(udid: str, *, exclude_node_id: Optional[str] = None) -> bool:
    nodes = await redis_client.hgetall("nodes")
    for existing_id, data in nodes.items():
        if exclude_node_id and existing_id == exclude_node_id:
            continue

        try:
            stored = json.loads(data)
        except json.JSONDecodeError:
            logger.warning("Skipping malformed node data for %s during UDID check", existing_id)
            continue

        if (stored.get("type") or "").lower() != "physical":
            continue

        if _strip_or_none(stored.get("udid")) == udid:
            return True

    return False


def _normalise_numeric(value: Optional[str], default: int) -> int:
    if value in (None, ""):
        return default
    try:
        return int(value)
    except (TypeError, ValueError) as exc:
        raise NodeRegistrationError(f"Invalid numeric value '{value}'") from exc


def _normalise_node_payload(raw_node: Dict) -> Dict:
    node = dict(raw_node)
    node_id = node.get("id") or str(uuid.uuid4())
    node["id"] = node_id

    node["max_sessions"] = _normalise_numeric(node.get("max_sessions"), 1)
    node["active_sessions"] = _normalise_numeric(node.get("active_sessions"), 0)
    node.setdefault("status", "online")

    node_type = (node.get("type") or "").lower()
    if node_type == "physical":
        udid = _strip_or_none(node.get("udid"))
        if not udid:
            raise NodeRegistrationError("Physical nodes must include a UDID.")
        node["udid"] = udid

    resources = node.get("resources")
    if isinstance(resources, str):
        try:
            node["resources"] = json.loads(resources)
        except json.JSONDecodeError:
            logger.warning("Failed to decode resources JSON for node %s", node_id)
            node.pop("resources", None)

    return node


async def _store_node(node: Dict) -> Dict:
    node = _normalise_node_payload(node)

    node_type = (node.get("type") or "").lower()
    if node_type == "physical" and await _physical_udid_exists(node["udid"], exclude_node_id=node["id"]):
        raise NodeRegistrationError(f"Physical device with UDID '{node['udid']}' is already registered.")

    await redis_client.hset("nodes", node["id"], json.dumps(node))
    await redis_client.hset(NODE_SESSION_COUNTS_KEY, node["id"], node["active_sessions"])
    logger.info(
        "Registered/updated node %s at %s:%s with max_sessions=%s",
        node["id"],
        node.get("host"),
        node.get("port"),
        node.get("max_sessions"),
    )
    return node


def _normalise_str(value: Optional[str]) -> Optional[str]:
    if not isinstance(value, str):
        return None
    value = value.strip().lower()
    return value or None


def _node_is_available(node: Dict) -> bool:
    status = _normalise_str(node.get("status")) or "offline"
    if status != "online":
        return False

    try:
        max_sessions = int(node.get("max_sessions", 1) or 1)
    except (TypeError, ValueError):
        max_sessions = 1

    try:
        active_sessions = int(node.get("active_sessions", 0) or 0)
    except (TypeError, ValueError):
        active_sessions = 0

    if max_sessions <= 0:
        return False

    if active_sessions >= max_sessions:
        return False

    return True


def _classify_device_pools(node: Dict) -> Set[str]:
    values: List[str] = []
    for key in ("type", "platform", "id"):
        normalised = _normalise_str(node.get(key))
        if normalised:
            values.append(normalised)

    resources = node.get("resources")
    if isinstance(resources, dict):
        tags = resources.get("tags")
        if isinstance(tags, list):
            for tag in tags:
                normalised = _normalise_str(tag)
                if normalised:
                    values.append(normalised)

    matched: Set[str] = set()

    for pool in SUPPORTED_DEVICE_POOLS:
        if pool in values:
            matched.add(pool)

    if any(value == "ios" for value in values):
        matched.add("ios")
    if any(value == "android" for value in values):
        matched.add("android")
    if any(value and "emulator" in value for value in values):
        matched.add("android-emulator")
    if any(value in {"web", "browser", "selenium"} for value in values if value):
        matched.add("web")

    return matched


def _build_connection_payload(node: Dict) -> Dict:
    resources = node.get("resources")
    session_data = {}
    if isinstance(resources, dict):
        session_data = resources.get("session_data") or {}
        if not isinstance(session_data, dict):
            session_data = {}

    return dict(session_data)


def _rows_from_csv(csv_path: Path) -> Iterable[Dict[str, str]]:
    with csv_path.open(newline="", encoding="utf-8") as csv_file:
        reader = csv.DictReader(csv_file)
        for row in reader:
            if not row:
                continue
            # Skip completely empty rows
            if all(value is None or value.strip() == "" for value in row.values()):
                continue
            yield row


def _csv_row_to_node(row: Dict[str, str]) -> Dict:
    node: Dict[str, Optional[str]] = {}
    for key, value in row.items():
        if value is None:
            continue
        value = value.strip()
        if value == "":
            continue
        node[key] = value
    return node


async def load_nodes_from_csv(csv_path: Optional[Path] = None) -> Dict[str, int]:
    """Register nodes from a CSV file.

    Parameters
    ----------
    csv_path:
        Optional path to the CSV file.  When omitted the default
        ``backend/node_resources.csv`` file is used.

    Returns
    -------
    dict
        Summary containing ``registered`` and ``skipped`` counters.
    """

    path = csv_path or NODE_RESOURCES_CSV
    summary = {"registered": 0, "skipped": 0}

    if not path.exists():
        logger.info("Node resources CSV %s not found; skipping auto-registration", path)
        return summary

    logger.info("Loading node resources from %s", path)

    for index, row in enumerate(_rows_from_csv(path), start=2):
        try:
            node = _csv_row_to_node(row)
            await _store_node(node)
        except NodeRegistrationError as exc:
            summary["skipped"] += 1
            logger.warning("Skipping row %s in %s: %s", index, path, exc)
        except Exception:
            summary["skipped"] += 1
            logger.exception("Unexpected error registering node from row %s in %s", index, path)
        else:
            summary["registered"] += 1

    logger.info(
        "Completed CSV load from %s: %s registered, %s skipped",
        path,
        summary["registered"],
        summary["skipped"],
    )
    return summary


def generate_csv_template() -> str:
    """Return a CSV template with the expected headers and example data."""

    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=CSV_TEMPLATE_HEADERS)
    writer.writeheader()
    writer.writerow(
        {
            "id": "example-node-id",
            "type": "physical",
            "udid": "00008020-001C2D113C88002E",
            "host": "127.0.0.1",
            "port": "4723",
            "protocol": "http",
            "path": "/wd/hub",
            "max_sessions": "1",
            "active_sessions": "0",
            "status": "online",
            "platform": "iOS",
            "platform_version": "17.4",
            "device_name": "Example Device",
            "resources": json.dumps(
                {
                    "session_data": {"device": "metadata"},
                    "stf": {
                        "base_url": "https://stf.example.com",
                        "control_path_template": "/#!/control/{udid}",
                        "enabled": True,
                    },
                }
            ),
        }
    )
    return output.getvalue()

@router.post("/register")
async def register_node(node: Dict, _: None = Depends(require_admin)):
    try:
        stored_node = await _store_node(node)
    except NodeRegistrationError as exc:
        raise HTTPException(status_code=409, detail=str(exc))

    return {"message": "Node registered", "id": stored_node["id"]}


@router.post("/register/from-csv")
async def register_nodes_from_csv(_: None = Depends(require_admin)):
    summary = await load_nodes_from_csv()
    return {"message": "Nodes processed from CSV", **summary}


@router.get("/nodes/template")
async def get_nodes_template():
    content = generate_csv_template()
    headers = {
        "Content-Disposition": "attachment; filename=node_resources_template.csv"
    }
    return Response(content=content, media_type="text/csv", headers=headers)

@router.delete("/unregister/{node_id}")
async def unregister_node(node_id: str, _: None = Depends(require_admin)):
    deleted = await redis_client.hdel("nodes", node_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Node not found")
    await redis_client.hdel(NODE_SESSION_COUNTS_KEY, node_id)
    logger.info("Unregistered node %s", node_id)
    return {"message": f"Node {node_id} unregistered"}


@router.get("/admin/ping")
async def admin_ping(_: None = Depends(require_admin)):
    return {"message": "Admin access confirmed"}

@router.get("/nodes")
async def list_nodes():
    nodes = await redis_client.hgetall("nodes")
    logger.debug("Listing %d nodes", len(nodes))
    result: Dict[str, Dict] = {}

    for node_id, data in nodes.items():
        try:
            node = json.loads(data)
        except json.JSONDecodeError:
            logger.warning("Skipping malformed node data for %s", node_id)
            continue

        node["stf_enabled"] = _node_supports_stf(node)
        result[node_id] = node

    return result


@router.get("/nodes/available")
async def list_available_nodes(device_type: Optional[str] = None):
    nodes = await redis_client.hgetall("nodes")
    logger.debug("Listing available nodes; total cached nodes=%d", len(nodes))

    available: Dict[str, List[Dict]] = {pool: [] for pool in SUPPORTED_DEVICE_POOLS}

    for node_id, node_data in nodes.items():
        try:
            node = json.loads(node_data)
        except json.JSONDecodeError:
            logger.warning("Skipping malformed node data for %s while listing availability", node_id)
            continue

        if not _node_is_available(node):
            continue

        pools = _classify_device_pools(node)
        if not pools:
            continue

        payload = _build_connection_payload(node)

        for pool in pools:
            if pool in available:
                available[pool].append(dict(payload))

    if device_type is not None:
        requested = _normalise_str(device_type)
        if not requested or requested not in SUPPORTED_DEVICE_POOLS:
            raise HTTPException(status_code=400, detail="Unsupported device type requested")
        return {requested: available.get(requested, [])}

    return available

@router.get("/status/{node_id}")
async def node_status(node_id: str):
    node_data = await redis_client.hget("nodes", node_id)
    if not node_data:
        raise HTTPException(status_code=404, detail="Node not found")
    logger.debug("Retrieved status for node %s", node_id)
    node = json.loads(node_data)
    node["stf_enabled"] = _node_supports_stf(node)
    return node


@router.post("/nodes/{node_id}/stf/use")
async def stf_use_device(node_id: str, request: Optional[StfUseRequest] = None):
    node = await _fetch_node(node_id)
    stf_config = _ensure_stf_config(node)

    options = request.options if request else {}
    payload = options or None

    response, action_config = await _perform_stf_action(
        node,
        stf_config,
        "use",
        payload=payload,
    )

    logger.info("Requested STF use action for node %s", node_id)

    return _stf_response_to_fastapi(response, "use", action_config)


@router.delete("/nodes/{node_id}/stf/use")
async def stf_stop_using_device(node_id: str):
    node = await _fetch_node(node_id)
    stf_config = _ensure_stf_config(node)

    response, action_config = await _perform_stf_action(
        node,
        stf_config,
        "stop",
    )

    logger.info("Requested STF stop action for node %s", node_id)

    return _stf_response_to_fastapi(response, "stop", action_config)


@router.post("/nodes/{node_id}/stf/install")
async def stf_install_app(node_id: str, request: StfInstallRequest):
    node = await _fetch_node(node_id)
    stf_config = _ensure_stf_config(node)

    payload = request.resolve_payload()

    response, action_config = await _perform_stf_action(
        node,
        stf_config,
        "install",
        payload=payload,
    )

    logger.info("Requested STF install action for node %s", node_id)

    return _stf_response_to_fastapi(response, "install", action_config)


@router.post("/nodes/{node_id}/stf/screenshot")
async def stf_capture_screenshot(
    node_id: str, request: Optional[StfActionRequest] = None
):
    node = await _fetch_node(node_id)
    stf_config = _ensure_stf_config(node)

    options = request.options if request else {}
    payload = options or None

    response, action_config = await _perform_stf_action(
        node,
        stf_config,
        "screenshot",
        payload=payload,
    )

    logger.info("Requested STF screenshot action for node %s", node_id)

    return _stf_response_to_fastapi(response, "screenshot", action_config)


@router.get("/nodes/{node_id}/stf/device")
async def stf_device_details(node_id: str):
    node = await _fetch_node(node_id)
    stf_config = _ensure_stf_config(node)

    response, action_config = await _perform_stf_action(
        node,
        stf_config,
        "device",
    )

    logger.debug("Retrieved STF device details for node %s", node_id)

    return _stf_response_to_fastapi(response, "device", action_config)


@router.post("/nodes/{node_id}/stf/session")
async def open_stf_session(node_id: str, request: StfSessionRequest):
    node = await _fetch_node(node_id)
    stf_config = _ensure_stf_config(node)

    if not _node_is_available(node):
        raise HTTPException(status_code=409, detail="Node is not available for STF access")

    ttl_seconds = _resolve_stf_session_ttl(stf_config, request)

    expires_at = await create_stf_reservation(redis_client, node_id, node, ttl_seconds)
    if expires_at is None:
        raise HTTPException(status_code=409, detail="Node is already busy")

    launch_url = _build_stf_control_url(node, stf_config)

    expires_at_dt = datetime.fromtimestamp(expires_at, tz=timezone.utc)
    udid = node.get("udid")
    default_cookie_path = "/"
    if isinstance(udid, str) and udid.strip():
        default_cookie_path = f"/control/{udid.strip()}"

    cached_jwt = await get_cached_stf_jwt(redis_client, node_id)
    jwt_token: Optional[str] = None
    jwt_cookie_path = default_cookie_path
    if cached_jwt and cached_jwt.get("token"):
        cached_expiry = cached_jwt.get("expires_at")
        if isinstance(cached_expiry, int) and cached_expiry >= int(expires_at_dt.timestamp()):
            jwt_token = cached_jwt["token"]
            cached_path = cached_jwt.get("cookie_path")
            if isinstance(cached_path, str) and cached_path.strip():
                jwt_cookie_path = cached_path.strip()

    if not jwt_token:
        jwt_token = _generate_jwt(
            expires_at=int(expires_at_dt.timestamp()),
            udid=udid if isinstance(udid, str) else None,
        )
        jwt_cookie_path = default_cookie_path
        await cache_stf_jwt(
            redis_client,
            node_id,
            token=jwt_token,
            expires_at=int(expires_at_dt.timestamp()),
            cookie_path=jwt_cookie_path,
        )

    logger.info(
        "Reserved node %s for STF via API (ttl=%s, launch_url=%s)",
        node_id,
        ttl_seconds,
        launch_url,
    )

    return {
        "launch_url": launch_url,
        "jwt": jwt_token,
        "jwt_query_param": None,
        "jwt_cookie_name": "jwt",
        "jwt_cookie_path": jwt_cookie_path,
        "ttl_seconds": ttl_seconds,
        "expires_at": expires_at_dt.isoformat(),
    }


@router.delete("/nodes/{node_id}/stf/session")
async def close_stf_session(node_id: str):
    await _fetch_node(node_id)

    released = await release_stf_reservation(redis_client, node_id)
    if not released:
        raise HTTPException(status_code=404, detail="No STF reservation active for this node")

    logger.info("Released STF reservation for node %s via API", node_id)
    return Response(status_code=204)


@router.get("/summary")
async def summary():
    nodes = await redis_client.hgetall("nodes")
    total = len(nodes)
    online = sum(1 for data in nodes.values() if json.loads(data).get("status") == "online")
    logger.debug("Summary calculated: total=%d, online=%d", total, online)
    return {"total": total, "online": online, "offline": total - online}
