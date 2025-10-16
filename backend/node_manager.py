import csv
import io
import json
import logging
import uuid
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set

import redis.asyncio as aioredis
from fastapi import APIRouter, HTTPException
from fastapi.responses import Response

router = APIRouter()
redis_client = aioredis.from_url("redis://10.160.13.16:6379/0", decode_responses=True)

logger = logging.getLogger(__name__)

NODE_RESOURCES_CSV = Path(__file__).resolve().parent / "node_resources.csv"
NODE_SESSION_COUNTS_KEY = "node_session_counts"
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


class NodeRegistrationError(Exception):
    """Raised when a node cannot be registered."""


def _strip_or_none(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    value = value.strip()
    return value or None


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
async def register_node(node: Dict):
    try:
        stored_node = await _store_node(node)
    except NodeRegistrationError as exc:
        raise HTTPException(status_code=409, detail=str(exc))

    return {"message": "Node registered", "id": stored_node["id"]}


@router.post("/register/from-csv")
async def register_nodes_from_csv():
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
async def unregister_node(node_id: str):
    deleted = await redis_client.hdel("nodes", node_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Node not found")
    await redis_client.hdel(NODE_SESSION_COUNTS_KEY, node_id)
    logger.info("Unregistered node %s", node_id)
    return {"message": f"Node {node_id} unregistered"}

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

@router.get("/summary")
async def summary():
    nodes = await redis_client.hgetall("nodes")
    total = len(nodes)
    online = sum(1 for data in nodes.values() if json.loads(data).get("status") == "online")
    logger.debug("Summary calculated: total=%d, online=%d", total, online)
    return {"total": total, "online": online, "offline": total - online}
