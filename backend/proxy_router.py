import json
import logging
from typing import Dict, Optional, Tuple

import httpx
import redis.asyncio as aioredis
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import Response

router = APIRouter()
redis_client = aioredis.from_url("redis://10.160.13.16:6379/0", decode_responses=True)

SESSION_MAP_KEY = "session_map"

logger = logging.getLogger(__name__)


def _extract_session_id_from_path(path: str) -> Optional[str]:
    parts = [part for part in path.split("/") if part]
    if len(parts) >= 2 and parts[0] == "session":
        return parts[1]
    return None


def _extract_session_id_from_response(content: bytes) -> Optional[str]:
    try:
        payload = json.loads(content.decode())
    except Exception:
        return None

    if not isinstance(payload, dict):
        return None

    if "sessionId" in payload:
        return payload.get("sessionId")

    value = payload.get("value")
    if isinstance(value, dict):
        return value.get("sessionId") or value.get("session_id")

    return None


async def _update_node_session_count(node_id: str, delta: int):
    node_json = await redis_client.hget("nodes", node_id)
    if not node_json:
        logger.warning("Node %s not found while updating session count", node_id)
        return

    node = json.loads(node_json)
    active_sessions = int(node.get("active_sessions", 0)) + delta
    if active_sessions < 0:
        active_sessions = 0

    node["active_sessions"] = active_sessions

    max_sessions = int(node.get("max_sessions", 1))
    if active_sessions >= max_sessions:
        node["status"] = "busy"
    elif node.get("status") == "busy":
        node["status"] = "online"

    await redis_client.hset("nodes", node_id, json.dumps(node))


async def _cleanup_session(session_id: str, node_id: Optional[str]):
    logger.info("Cleaning up session %s for node %s", session_id, node_id)
    await redis_client.hdel(SESSION_MAP_KEY, session_id)
    if node_id:
        await _update_node_session_count(node_id, -1)


def _merge_session_capabilities(
    body: bytes, headers: Dict[str, str], session_data: Dict
) -> Tuple[bytes, Dict[str, str]]:
    """Merge node session defaults into the request payload.

    The proxy stores per-node ``session_data`` in Redis so that device specific
    capabilities (e.g. UDID, automation name, SDK paths) can be applied
    automatically.  When a create session request is routed through the proxy we
    merge those defaults into both W3C ``capabilities`` payloads and legacy
    ``desiredCapabilities`` dictionaries.  Headers are returned alongside the
    (potentially) mutated body so the ``Content-Length`` can be recalculated by
    the downstream HTTP client.
    """

    try:
        payload = json.loads(body.decode() or "{}") if body else {}
    except json.JSONDecodeError:
        logger.warning("Failed to decode session payload for capability merge")
        return body, headers

    def _merge(target: Dict) -> bool:
        changed = False
        for key, value in session_data.items():
            if key not in target or target[key] != value:
                target[key] = value
                changed = True
        return changed

    changed = False

    capabilities = payload.get("capabilities")
    if isinstance(capabilities, dict):
        always_match = capabilities.setdefault("alwaysMatch", {})
        if isinstance(always_match, dict):
            changed = _merge(always_match) or changed

        first_match = capabilities.get("firstMatch")
        if isinstance(first_match, list):
            for item in first_match:
                if isinstance(item, dict):
                    changed = _merge(item) or changed

    desired_caps = payload.get("desiredCapabilities")
    if isinstance(desired_caps, dict):
        changed = _merge(desired_caps) or changed

    if not changed:
        return body, headers

    new_body = json.dumps(payload).encode()
    headers = dict(headers)
    headers.pop("content-length", None)
    return new_body, headers


async def forward_request(request: Request, path: str):
    body = await request.body()
    headers = dict(request.headers)

    session_id = _extract_session_id_from_path(path)

    target_node = None
    target_node_id = None

    if session_id:
        target_node_id = await redis_client.hget(SESSION_MAP_KEY, session_id)
        if not target_node_id:
            logger.warning("Session %s not found for path %s", session_id, path)
            raise HTTPException(status_code=404, detail="Session not found")

        node_json = await redis_client.hget("nodes", target_node_id)
        if not node_json:
            await redis_client.hdel(SESSION_MAP_KEY, session_id)
            logger.warning(
                "Node %s not available for session %s; removed stale mapping",
                target_node_id,
                session_id,
            )
            raise HTTPException(status_code=503, detail="Node unavailable for session")

        target_node = json.loads(node_json)
    else:
        nodes = await redis_client.hgetall("nodes")
        if not nodes:
            logger.error("No nodes available to process request %s %s", request.method, path)
            raise HTTPException(status_code=503, detail="No nodes available")

        for node_id, node_data in nodes.items():
            node = json.loads(node_data)
            status = node.get("status")
            max_sessions = int(node.get("max_sessions", 1))
            active_sessions = int(node.get("active_sessions", 0))

            if request.method == "DELETE" or (status == "online" and active_sessions < max_sessions):
                target_node = node
                target_node_id = node_id
                break

        if not target_node:
            logger.info("All nodes busy when processing %s %s", request.method, path)
            raise HTTPException(status_code=503, detail="No nodes available for new session")

    target_url = f"http://{target_node['host']}:{target_node['port']}/wd/hub/{path}"
    logger.debug(
        "Forwarding %s request to %s via node %s",
        request.method,
        target_url,
        target_node_id or target_node.get("id"),
    )

    if not session_id:
        resources = target_node.get("resources")
        session_data = None
        if isinstance(resources, dict):
            session_data = resources.get("session_data")
        if isinstance(session_data, dict):
            body, headers = _merge_session_capabilities(body, headers, session_data)

    async with httpx.AsyncClient(timeout=None) as client:
        resp = await client.request(
            request.method, target_url, headers=headers, content=body
        )

    return resp.content, resp.status_code, resp.headers, target_node_id or target_node.get("id"), session_id


@router.api_route("/wd/hub/session", methods=["POST", "OPTIONS"])
async def create_session(request: Request):
    content, status, headers, node_id, _ = await forward_request(request, "session")

    if node_id and 200 <= status < 300:
        session_id = _extract_session_id_from_response(content)
        if session_id:
            await redis_client.hset(SESSION_MAP_KEY, session_id, node_id)
            await _update_node_session_count(node_id, 1)
            logger.info("Created session %s on node %s", session_id, node_id)

    return Response(content=content, status_code=status, headers=dict(headers))


@router.api_route("/wd/hub/{path:path}", methods=["GET", "POST", "DELETE", "PUT", "PATCH", "OPTIONS"])
async def proxy_generic(request: Request, path: str):
    content, status, headers, node_id, session_id = await forward_request(request, path)
    if request.method == "DELETE" and session_id and 200 <= status < 405 :
        await _cleanup_session(session_id, node_id)
        logger.info("Session %s terminated with status %s", session_id, status)

    return Response(content=content, status_code=status, headers=dict(headers))


@router.api_route("/session", methods=["POST", "OPTIONS"])
async def selenium_create_session(request: Request):
    content, status, headers, node_id, _ = await forward_request(request, "session")

    if node_id and 200 <= status < 300:
        session_id = _extract_session_id_from_response(content)
        if session_id:
            await redis_client.hset(SESSION_MAP_KEY, session_id, node_id)
            await _update_node_session_count(node_id, 1)

    return Response(content=content, status_code=status, headers=dict(headers))
