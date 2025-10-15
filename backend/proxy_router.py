import json
import logging
from typing import Any, Dict, Optional, Tuple

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


def _parse_session_payload(body: bytes) -> Optional[Dict]:
    """Best-effort JSON decode of an Appium session payload."""

    if not body:
        return {}

    try:
        payload = json.loads(body.decode() or "{}")
    except json.JSONDecodeError:
        logger.warning("Failed to decode session payload for capability merge")
        return None

    if not isinstance(payload, dict):
        return None

    return payload


def _extract_capability_value(payload: Dict, capability_keys: Tuple[str, ...]) -> Optional[str]:
    """Return the first matching capability value from a session payload."""

    def _value_from_caps(caps: Optional[Dict]) -> Optional[str]:
        if not isinstance(caps, dict):
            return None
        for key in capability_keys:
            value = caps.get(key)
            if isinstance(value, str):
                value = value.strip()
                if value:
                    return value
        return None

    capabilities = payload.get("capabilities")
    if isinstance(capabilities, dict):
        value = _value_from_caps(capabilities.get("alwaysMatch"))
        if value:
            return value

        first_match = capabilities.get("firstMatch")
        if isinstance(first_match, list):
            for item in first_match:
                value = _value_from_caps(item)
                if value:
                    return value

    desired_caps = payload.get("desiredCapabilities")
    if isinstance(desired_caps, dict):
        value = _value_from_caps(desired_caps)
        if value:
            return value

    return None


def _extract_requested_platform(payload: Dict) -> Optional[str]:
    """Return the requested platform name from a session payload if present."""

    return _extract_capability_value(payload, ("platformName", "appium:platformName"))


def _normalise_str(value: Optional[str]) -> Optional[str]:
    if isinstance(value, str):
        value = value.strip()
        if value:
            return value
    return None


def _collect_requested_capabilities(payload: Optional[Dict]) -> Dict[str, Any]:
    """Flattens requested capabilities from a session payload into a single dict."""

    collected: Dict[str, Any] = {}
    if not isinstance(payload, dict):
        return collected

    capabilities = payload.get("capabilities")
    if isinstance(capabilities, dict):
        always_match = capabilities.get("alwaysMatch")
        if isinstance(always_match, dict):
            collected.update(always_match)

        first_match = capabilities.get("firstMatch")
        if isinstance(first_match, list):
            for item in first_match:
                if isinstance(item, dict):
                    for key, value in item.items():
                        collected.setdefault(key, value)

    desired_caps = payload.get("desiredCapabilities")
    if isinstance(desired_caps, dict):
        for key, value in desired_caps.items():
            collected.setdefault(key, value)

    return collected


def _normalise_capability_value(value: Any) -> Optional[str]:
    if isinstance(value, str):
        value = value.strip()
        return value.lower() or None
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, bool):
        return "true" if value else "false"
    return None


def _node_is_likely_emulator(node: Dict, session_data: Optional[Dict]) -> bool:
    """Best-effort heuristic to identify emulator nodes.

    A node is considered an emulator when one of the following is true:
    - Its ``type`` metadata explicitly marks it as an emulator.
    - It contains tags mentioning emulator usage.
    - It advertises an AVD value but no UDID (common for Android emulators).
    """

    node_type = (node.get("type") or "").strip().lower()
    if "emulator" in node_type:
        return True

    resources = node.get("resources")
    if isinstance(resources, dict):
        tags = resources.get("tags")
        if isinstance(tags, list):
            for tag in tags:
                if isinstance(tag, str) and "emulator" in tag.lower():
                    return True

    session_data = session_data or {}

    has_avd = any(
        _normalise_str(session_data.get(key))
        for key in ("appium:avd", "avd")
    )
    has_udid = any(
        _normalise_str(source)
        for source in (
            node.get("udid"),
            session_data.get("appium:udid"),
            session_data.get("udid"),
        )
    )

    return bool(has_avd and not has_udid)


def _node_value_for_capability(
    node: Dict, session_data: Dict, key: str
) -> Optional[Any]:
    if key in session_data:
        return session_data[key]

    if key == "udid":
        return node.get("udid")

    if key in {"deviceName", "device_name"}:
        return node.get("deviceName") or node.get("device_name")

    if key in {"appium:deviceName"}:
        return (
            session_data.get("appium:deviceName")
            or session_data.get("deviceName")
            or session_data.get("device_name")
        )

    if key in {"appium:avd", "avd"}:
        # Session data takes priority, but some nodes may expose the AVD as
        # top-level metadata or via resource hints.
        resources = node.get("resources")
        if isinstance(resources, dict):
            direct_avd = resources.get("avd")
            if direct_avd is not None:
                return direct_avd
        return node.get("avd")

    return None


def _node_matches_session_requirements(
    node: Dict, session_data: Optional[Dict], requested_caps: Dict[str, Any]
) -> bool:
    """Ensure node session data aligns with explicit capability requests."""

    if not requested_caps:
        return True

    session_data = session_data or {}

    key_groups = [
        ("appium:udid", "udid"),
        ("appium:deviceName", "deviceName", "device_name"),
        ("appium:avd", "avd"),
    ]

    emulator_requested = any(
        requested_caps.get(key) not in (None, "")
        for key in ("appium:avd", "avd")
    )
    if emulator_requested and not _node_is_likely_emulator(node, session_data):
        return False

    for group in key_groups:
        requested_value: Optional[Any] = None
        for key in group:
            if key in requested_caps and requested_caps[key] not in (None, ""):
                requested_value = requested_caps[key]
                break

        if requested_value is None:
            continue

        normalised_requested = _normalise_capability_value(requested_value)
        if not normalised_requested:
            continue

        match_found = False
        for key in group:
            node_value = _node_value_for_capability(node, session_data, key)
            if node_value is None:
                continue

            normalised_node = _normalise_capability_value(node_value)
            if normalised_node == normalised_requested:
                match_found = True
                break

        if not match_found:
            return False

    return True


def _merge_session_capabilities(
    body: bytes,
    headers: Dict[str, str],
    session_data: Dict,
    *,
    payload: Optional[Dict] = None,
    requested_caps: Optional[Dict[str, Any]] = None,
) -> Tuple[bytes, Dict[str, str], Optional[Dict]]:
    """
    Merge node session defaults into W3C/legacy capabilities safely.

    - Merges node-level defaults (e.g., UDID, automationName, etc.) into W3C payloads.
    - Avoids duplicate keys between alwaysMatch and firstMatch.
    - Updates Content-Length automatically after mutation.
    """

    parsed_payload: Optional[Dict] = payload if isinstance(payload, dict) else _parse_session_payload(body)
    if parsed_payload is None:
        return body, headers, payload

    session_data_for_merge = dict(session_data)
    if requested_caps:
        # When an explicit emulator AVD is requested, restrict merging to overlapping keys.
        if any(key in requested_caps for key in ("appium:avd", "avd")):
            session_data_for_merge = {
                key: value
                for key, value in session_data_for_merge.items()
                if key in requested_caps
            }

    if not session_data_for_merge:
        return body, headers, parsed_payload

    def _merge(target: Dict, allowed_keys: Optional[set] = None) -> bool:
        """Merge session_data into target dictionary with optional key whitelist."""
        changed = False
        for key, value in session_data_for_merge.items():
            if allowed_keys and key not in allowed_keys:
                continue
            # Never overwrite existing platformName keys (or appium:platformName)
            if key in ("platformName", "appium:platformName") and key in target:
                continue
            if key not in target or target[key] != value:
                target[key] = value
                changed = True
        return changed

    changed = False
    capabilities = parsed_payload.get("capabilities")

    if isinstance(capabilities, dict):
        # Merge node defaults into alwaysMatch first
        always_match = capabilities.setdefault("alwaysMatch", {})
        if isinstance(always_match, dict):
            changed = _merge(always_match) or changed

        # Merge into firstMatch but skip keys already in alwaysMatch
        first_match = capabilities.get("firstMatch")
        if isinstance(first_match, list):
            existing_keys = set(always_match.keys())
            for item in first_match:
                if isinstance(item, dict):
                    changed = _merge(item, allowed_keys=set(session_data.keys()) - existing_keys) or changed

        # 🔧 Deduplicate overlapping keys between alwaysMatch and firstMatch
        if isinstance(always_match, dict) and isinstance(first_match, list):
            for item in first_match:
                if not isinstance(item, dict):
                    continue
                for key in list(item.keys()):
                    plain_key = key.replace("appium:", "")
                    if plain_key in always_match or key in always_match:
                        item.pop(key, None)
                        logger.debug(f"Removed duplicate key '{key}' from firstMatch to avoid W3C conflict")

    # Legacy desiredCapabilities support (Appium JSONWP mode)
    desired_caps = parsed_payload.get("desiredCapabilities")
    if isinstance(desired_caps, dict):
        changed = _merge(desired_caps) or changed

    # If nothing changed, return early
    if not changed:
        return body, headers, parsed_payload

    # Log final state for debugging
    try:
        logger.debug("Final merged capabilities: %s", json.dumps(parsed_payload.get("capabilities"), indent=2))
    except Exception:
        logger.debug("Final merged capabilities (non-JSON-serializable)")

    # Recalculate body and headers
    new_body = json.dumps(parsed_payload).encode()
    headers = dict(headers)
    headers.pop("content-length", None)

    return new_body, headers, parsed_payload


async def forward_request(request: Request, path: str):
    body = await request.body()
    headers = dict(request.headers)

    session_id = _extract_session_id_from_path(path)

    target_node = None
    target_node_id = None

    payload: Optional[Dict] = None
    requested_platform: Optional[str] = None
    requested_device_name: Optional[str] = None
    requested_udid: Optional[str] = None
    requested_caps: Dict[str, Any] = {}

    if not session_id and request.method == "POST":
        payload = _parse_session_payload(body)
        if payload is not None:
            requested_caps = _collect_requested_capabilities(payload)
            platform_name = _extract_requested_platform(payload)
            if platform_name:
                requested_platform = platform_name.lower()
            device_name = _extract_capability_value(payload, ("appium:deviceName", "deviceName"))
            if device_name:
                requested_device_name = device_name.lower()
            udid = _extract_capability_value(payload, ("appium:udid", "udid"))
            if udid:
                requested_udid = udid.lower()

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

            resources = node.get("resources")
            session_data = None
            if isinstance(resources, dict):
                session_data = resources.get("session_data")
                if not isinstance(session_data, dict):
                    session_data = None

            if not _node_matches_session_requirements(node, session_data, requested_caps):
                continue

            if requested_platform:
                node_platform = (node.get("platform") or "").strip()
                if not node_platform:
                    continue
                if node_platform.lower() != requested_platform:
                    continue

            if requested_udid:
                node_udid = _normalise_str(node.get("udid"))
                if not node_udid and session_data:
                    node_udid = _normalise_str(
                        session_data.get("appium:udid") or session_data.get("udid")
                    )
                if not node_udid or node_udid.lower() != requested_udid:
                    continue

            if requested_device_name:
                node_device_name = _normalise_str(
                    node.get("deviceName") or node.get("device_name")
                )
                if not node_device_name and session_data:
                    node_device_name = _normalise_str(
                        session_data.get("appium:deviceName")
                        or session_data.get("deviceName")
                        or session_data.get("device_name")
                    )
                if not node_device_name or node_device_name.lower() != requested_device_name:
                    continue

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
        logger.info(f"resources is {resources}")
        if isinstance(resources, dict):
            session_data = resources.get("session_data")
        logger.info(f"session_data is {session_data}")
        if isinstance(session_data, dict):
            body, headers, payload = _merge_session_capabilities(
                body,
                headers,
                session_data,
                payload=payload,
                requested_caps=requested_caps,
            )
        logger.info(f"body is {body}")

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
