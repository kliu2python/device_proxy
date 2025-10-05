import asyncio
import redis.asyncio as aioredis
import json
import httpx

async def check_node_status(node_id: str, node: dict, redis_client):
    url = f"http://{node['host']}:{node['port']}/status"
    try:
        async with httpx.AsyncClient(timeout=3) as client:
            resp = await client.get(url)
            if resp.status_code == 200:
                node_json = await redis_client.hget("nodes", node_id)
                if not node_json:
                    return
                data = json.loads(node_json)
                if data.get("status") != "busy":
                    data["status"] = "online"
                await redis_client.hset("nodes", node_id, json.dumps(data))
            else:
                raise Exception()
    except Exception:
        node_json = await redis_client.hget("nodes", node_id)
        if not node_json:
            return
        data = json.loads(node_json)
        data["status"] = "offline"
        await redis_client.hset("nodes", node_id, json.dumps(data))

async def start_monitor():
    redis_client = aioredis.from_url("redis://10.160.13.16:6379/0", decode_responses=True)
    while True:
        nodes = await redis_client.hgetall("nodes")
        for node_id, node_data in nodes.items():
            node = json.loads(node_data)
            await check_node_status(node_id, node, redis_client)
        await asyncio.sleep(10)
