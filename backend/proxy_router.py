from fastapi import APIRouter, Request, HTTPException
from fastapi.responses import Response
import httpx
import redis.asyncio as aioredis
import json
from typing import Optional

router = APIRouter()
redis_client = aioredis.from_url("redis://10.160.13.16:6379/0", decode_responses=True)

SESSION_MAP_KEY = "session_map"


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
    await redis_client.hdel(SESSION_MAP_KEY, session_id)
    if node_id:
        await _update_node_session_count(node_id, -1)


async def forward_request(request: Request, path: str):
    body = await request.body()
    headers = dict(request.headers)

    session_id = _extract_session_id_from_path(path)

    target_node = None
    target_node_id = None

    if session_id:
        target_node_id = await redis_client.hget(SESSION_MAP_KEY, session_id)
        if not target_node_id:
            raise HTTPException(status_code=404, detail="Session not found")

        node_json = await redis_client.hget("nodes", target_node_id)
        if not node_json:
            await redis_client.hdel(SESSION_MAP_KEY, session_id)
            raise HTTPException(status_code=503, detail="Node unavailable for session")

        target_node = json.loads(node_json)
    else:
        nodes = await redis_client.hgetall("nodes")
        if not nodes:
            raise HTTPException(status_code=503, detail="No nodes available")

        for node_id, node_data in nodes.items():
            node = json.loads(node_data)
            status = node.get("status")
            max_sessions = int(node.get("max_sessions", 1))
            active_sessions = int(node.get("active_sessions", 0))

            if status == "online" and active_sessions < max_sessions:
                target_node = node
                target_node_id = node_id
                break

        if not target_node:
            raise HTTPException(status_code=503, detail="No nodes available for new session")

    target_url = f"http://{target_node['host']}:{target_node['port']}/wd/hub/{path}"

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

    return Response(content=content, status_code=status, headers=dict(headers))


@router.api_route("/wd/hub/{path:path}", methods=["GET", "POST", "DELETE", "PUT", "PATCH", "OPTIONS"])
async def proxy_generic(request: Request, path: str):
    content, status, headers, node_id, session_id = await forward_request(request, path)

    if request.method == "DELETE" and session_id and 200 <= status < 300:
        await _cleanup_session(session_id, node_id)

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
