import asyncio
import copy
import json
import logging
import os
from typing import Dict, Optional
from urllib.parse import urlparse

import httpx
import redis.asyncio as aioredis

from backend.session_state import (
    release_expired_stf_reservations,
    release_inactive_sessions,
)

logger = logging.getLogger(__name__)

DEVICE_CAPS_URL = os.getenv("DEVICE_CAPS_URL", "http://10.160.13.110:8099/caps")
DEVICE_CAPS_TIMEOUT = float(os.getenv("DEVICE_CAPS_TIMEOUT", "5"))
SESSION_IDLE_TIMEOUT_SECONDS = int(os.getenv("SESSION_IDLE_TIMEOUT_SECONDS", "180"))


def _as_dict(value) -> Dict:
    if isinstance(value, dict):
        return dict(value)
    return {}


def _parse_appium_endpoint_url(value: Optional[str]) -> Optional[Dict[str, str]]:
    if not value or not isinstance(value, str):
        return None

    try:
        parsed = urlparse(value)
    except Exception:
        logger.debug("Failed to parse Appium endpoint URL %s", value)
        return None

    if not parsed.scheme or not parsed.hostname:
        return None

    port = parsed.port
    if port is None:
        port = 443 if parsed.scheme == "https" else 80

    path = parsed.path or "/wd/hub"
    return {
        "protocol": parsed.scheme,
        "host": parsed.hostname,
        "port": str(port),
        "path": path,
    }


def _apply_device_caps_to_node(node: Dict, caps_entry: Dict) -> Dict:
    updated = copy.deepcopy(node)

    resources = updated.get("resources")
    if not isinstance(resources, dict):
        resources = {}

    client_caps_local = _as_dict(caps_entry.get("clientCapsLocal"))
    client_caps_public = _as_dict(caps_entry.get("clientCapsPublic"))
    server_default_caps = _as_dict(caps_entry.get("serverDefaultCaps"))

    existing_session_data = resources.get("session_data")
    if not isinstance(existing_session_data, dict):
        existing_session_data = {}

    session_data = dict(existing_session_data)
    if server_default_caps:
        session_data.update(server_default_caps)
    if client_caps_public:
        session_data.update(client_caps_public)
    elif client_caps_local:
        session_data.update(client_caps_local)

    if session_data:
        resources["session_data"] = session_data

    resources["device_caps"] = {
        "clientCapsLocal": client_caps_local,
        "clientCapsPublic": client_caps_public,
        "serverDefaultCaps": server_default_caps,
    }

    mjpeg_urls = (
        _as_dict(client_caps_public.get("appium:mjpegUrls"))
        or _as_dict(client_caps_local.get("appium:mjpegUrls"))
        or _as_dict(server_default_caps.get("appium:mjpegUrls"))
    )
    if mjpeg_urls:
        resources["mjpeg_urls"] = mjpeg_urls

    wda_urls = (
        _as_dict(client_caps_public.get("appium:wdaUrls"))
        or _as_dict(client_caps_local.get("appium:wdaUrls"))
        or _as_dict(server_default_caps.get("appium:wdaUrls"))
    )
    if wda_urls:
        resources["wda_urls"] = wda_urls

    appium_urls = {}
    public_url = client_caps_public.get("appium:appiumUrlPublic") or client_caps_local.get(
        "appium:appiumUrlPublic"
    )
    if public_url:
        appium_urls["public"] = public_url

    local_url = client_caps_public.get("appium:appiumUrlLocal") or client_caps_local.get(
        "appium:appiumUrlLocal"
    )
    if local_url:
        appium_urls["local"] = local_url

    if appium_urls:
        resources["appium_urls"] = appium_urls

    device_type = caps_entry.get("type")
    if isinstance(device_type, str) and device_type:
        resources["device_type"] = device_type

    endpoint_details = _parse_appium_endpoint_url(
        public_url
        or client_caps_public.get("appium:appiumUrlLocal")
        or client_caps_local.get("appium:appiumUrlPublic")
        or client_caps_local.get("appium:appiumUrlLocal")
        or server_default_caps.get("appium:appiumUrlPublic")
        or server_default_caps.get("appium:appiumUrlLocal")
    )
    if endpoint_details:
        updated["host"] = endpoint_details["host"]
        updated["port"] = endpoint_details["port"]
        updated["protocol"] = endpoint_details["protocol"]
        updated["path"] = endpoint_details["path"]

    platform_name = (
        session_data.get("platformName")
        or session_data.get("appium:platformName")
        or updated.get("platform")
    )
    if isinstance(platform_name, str) and platform_name:
        updated["platform"] = platform_name

    device_name = (
        session_data.get("appium:deviceName")
        or session_data.get("deviceName")
        or session_data.get("device_name")
        or updated.get("device_name")
    )
    if isinstance(device_name, str) and device_name:
        updated["device_name"] = device_name

    udid = session_data.get("appium:udid") or session_data.get("udid") or updated.get("udid")
    if isinstance(udid, str) and udid:
        updated["udid"] = udid

    updated["resources"] = resources
    return updated


async def _fetch_device_caps() -> Optional[Dict[str, Dict]]:
    if not DEVICE_CAPS_URL:
        return None

    try:
        async with httpx.AsyncClient(timeout=DEVICE_CAPS_TIMEOUT) as client:
            response = await client.get(DEVICE_CAPS_URL)
    except Exception:
        logger.warning("Failed to fetch device capability data", exc_info=True)
        return None

    if response.status_code != 200:
        logger.warning(
            "Device capability endpoint returned unexpected status %s",
            response.status_code,
        )
        return None

    try:
        payload = response.json()
    except ValueError:
        logger.warning("Device capability endpoint returned invalid JSON")
        return None

    if not isinstance(payload, dict):
        logger.warning("Device capability endpoint returned unexpected payload format")
        return None

    normalised: Dict[str, Dict] = {}
    for key, value in payload.items():
        if not isinstance(key, str) or not isinstance(value, dict):
            continue
        normalised[key.lower()] = value

    if not normalised:
        return None

    logger.debug(
        "Fetched device capability data for %d devices from %s",
        len(normalised),
        DEVICE_CAPS_URL,
    )
    return normalised


async def _sync_device_caps(redis_client):
    caps_data = await _fetch_device_caps()
    if not caps_data:
        return

    nodes = await redis_client.hgetall("nodes")
    updated_nodes = 0

    for node_id, node_json in nodes.items():
        try:
            node = json.loads(node_json)
        except json.JSONDecodeError:
            logger.warning("Skipping malformed node data for %s during caps sync", node_id)
            continue

        udid = node.get("udid")
        lookup_key = udid.lower() if isinstance(udid, str) else None

        if not lookup_key:
            resources = node.get("resources")
            if isinstance(resources, dict):
                session_data = resources.get("session_data")
                if isinstance(session_data, dict):
                    inferred_udid = session_data.get("appium:udid") or session_data.get("udid")
                    if isinstance(inferred_udid, str):
                        lookup_key = inferred_udid.lower()

        if not lookup_key:
            continue

        caps_entry = caps_data.get(lookup_key)
        if not caps_entry:
            continue

        updated_node = _apply_device_caps_to_node(node, caps_entry)
        if updated_node != node:
            await redis_client.hset("nodes", node_id, json.dumps(updated_node))
            updated_nodes += 1
            logger.info(
                "Updated node %s metadata from device capability service", node_id
            )

    if updated_nodes:
        logger.info("Synchronized device capability data for %d nodes", updated_nodes)


async def check_node_status(node_id: str, node: dict, redis_client):
    url = f"http://{node['host']}:{node['port']}/wd/hub/status"
    try:
        async with httpx.AsyncClient(timeout=3) as client:
            resp = await client.get(url)
            if resp.status_code == 200:
                node_json = await redis_client.hget("nodes", node_id)
                if not node_json:
                    logger.debug("Node %s removed before status update", node_id)
                    return
                data = json.loads(node_json)
                if data.get("status") != "busy":
                    data["status"] = "online"
                await redis_client.hset("nodes", node_id, json.dumps(data))
                logger.debug("Node %s is online", node_id)
            else:
                raise Exception()
    except Exception:
        node_json = await redis_client.hget("nodes", node_id)
        if not node_json:
            return
        data = json.loads(node_json)
        data["status"] = "offline"
        await redis_client.hset("nodes", node_id, json.dumps(data))
        logger.warning("Node %s is offline", node_id)


async def start_monitor():
    redis_client = aioredis.from_url("redis://10.160.13.16:6379/0", decode_responses=True)
    logger.info("Monitor started")
    while True:
        await release_expired_stf_reservations(redis_client)

        try:
            await _sync_device_caps(redis_client)
        except Exception:
            logger.exception("Device capability synchronization failed")

        nodes = await redis_client.hgetall("nodes")
        for node_id, node_data in nodes.items():
            node = json.loads(node_data)
            await check_node_status(node_id, node, redis_client)
        logger.debug("Completed monitor cycle for %d nodes", len(nodes))

        try:
            reclaimed = await release_inactive_sessions(
                redis_client, idle_timeout=SESSION_IDLE_TIMEOUT_SECONDS
            )
            if reclaimed:
                logger.info("Released %d inactive sessions", reclaimed)
        except Exception:
            logger.exception("Failed to release inactive sessions")

        await asyncio.sleep(10)
