from fastapi import APIRouter, HTTPException
from typing import Dict
import uuid
import redis.asyncio as aioredis
import json

router = APIRouter()
redis_client = aioredis.from_url("redis://10.160.13.16:6379/0", decode_responses=True)

@router.post("/register")
async def register_node(node: Dict):
    node_id = node.get("id", str(uuid.uuid4()))
    node["id"] = node_id
    await redis_client.hset("nodes", node_id, json.dumps(node))
    return {"message": "Node registered", "id": node_id}

@router.delete("/unregister/{node_id}")
async def unregister_node(node_id: str):
    deleted = await redis_client.hdel("nodes", node_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Node not found")
    return {"message": f"Node {node_id} unregistered"}

@router.get("/nodes")
async def list_nodes():
    nodes = await redis_client.hgetall("nodes")
    return {node_id: json.loads(data) for node_id, data in nodes.items()}

@router.get("/status/{node_id}")
async def node_status(node_id: str):
    node_data = await redis_client.hget("nodes", node_id)
    if not node_data:
        raise HTTPException(status_code=404, detail="Node not found")
    return json.loads(node_data)

@router.get("/summary")
async def summary():
    nodes = await redis_client.hgetall("nodes")
    total = len(nodes)
    online = sum(1 for data in nodes.values() if json.loads(data).get("status") == "online")
    return {"total": total, "online": online, "offline": total - online}
