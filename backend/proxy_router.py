from fastapi import APIRouter, Request, HTTPException
import httpx
import redis.asyncio as aioredis
import json

router = APIRouter()
redis_client = aioredis.from_url("redis://10.160.13.16:6379/0", decode_responses=True)

async def forward_request(request: Request, path: str):
    body = await request.body()
    headers = dict(request.headers)

    nodes = await redis_client.hgetall("nodes")
    if not nodes:
        raise HTTPException(status_code=503, detail="No nodes available")

    # Pick first available online node
    target_node = None
    for node_data in nodes.values():
        node = json.loads(node_data)
        if node.get("status") == "online":
            target_node = node
            break

    if not target_node:
        raise HTTPException(status_code=503, detail="No online nodes available")

    target_url = f"http://{target_node['host']}:{target_node['port']}/wd/hub/{path}"

    async with httpx.AsyncClient(timeout=None) as client:
        resp = await client.request(
            request.method, target_url, headers=headers, content=body
        )

    return resp.text, resp.status_code, resp.headers

# ✅ Add explicit route for session creation
@router.api_route("/wd/hub/session", methods=["POST"])
async def create_session(request: Request):
    content, status, headers = await forward_request(request, "session")
    return Response(content=content, status_code=status, headers=dict(headers))

# ✅ Add route for generic proxy handling (any other Appium path)
@router.api_route("/wd/hub/{path:path}", methods=["GET", "POST", "DELETE", "PUT", "PATCH"])
async def proxy_generic(request: Request, path: str):
    content, status, headers = await forward_request(request, path)
    return Response(content=content, status_code=status, headers=dict(headers))

# ✅ Add Selenium-style root route (no wd/hub prefix)
@router.api_route("/session", methods=["POST"])
async def selenium_create_session(request: Request):
    content, status, headers = await forward_request(request, "session")
    return Response(content=content, status_code=status, headers=dict(headers))
