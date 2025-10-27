import csv
import io
import json
import logging
import os
import secrets
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set

import redis.asyncio as aioredis
from fastapi import APIRouter, Depends, Header, HTTPException
from fastapi.responses import Response
from pydantic import BaseModel

from backend.session_state import create_stf_reservation, release_stf_reservation

router = APIRouter()
redis_client = aioredis.from_url("redis://10.160.13.16:6379/0", decode_responses=True)

logger = logging.getLogger(__name__)

NODE_RESOURCES_CSV = Path(__file__).resolve().parent / "node_resources.csv"
NODE_SESSION_COUNTS_KEY = "node_session_counts"
ADMIN_USERNAME_ENV_VAR = "ADMIN_USERNAME"
ADMIN_PASSWORD_ENV_VAR = "ADMIN_PASSWORD"
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


def _strip_or_none(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    value = value.strip()
    return value or None


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


def _ensure_stf_config(node: Dict) -> Dict:
    resources = node.get("resources")
    if not isinstance(resources, dict):
        raise HTTPException(
            status_code=404, detail="Node is not configured for STF access"
        )

    stf_config = resources.get("stf")
    if not isinstance(stf_config, dict):
        raise HTTPException(
            status_code=404, detail="Node is not configured for STF access"
        )

    return stf_config


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
            "resources": json.dumps({"session_data": {"device": "metadata"}}),
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
    return {node_id: json.loads(data) for node_id, data in nodes.items()}


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
    return json.loads(node_data)


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
    jwt_token = stf_config.get("jwt") or stf_config.get("token")
    jwt_query_param = stf_config.get("jwt_query_param")
    if isinstance(jwt_query_param, str):
        jwt_query_param = jwt_query_param.strip() or None
    else:
        jwt_query_param = None

    logger.info(
        "Reserved node %s for STF via API (ttl=%s, launch_url=%s)",
        node_id,
        ttl_seconds,
        launch_url,
    )

    return {
        "launch_url": launch_url,
        "jwt": jwt_token,
        "jwt_query_param": jwt_query_param,
        "ttl_seconds": ttl_seconds,
        "expires_at": datetime.fromtimestamp(expires_at, tz=timezone.utc).isoformat(),
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
