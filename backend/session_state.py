"""Shared helpers for tracking node reservation state.

This module centralises the logic for keeping node session metadata in sync
across the various routers.  Historically the proxy router owned bespoke
helpers to increment/decrement Redis counters whenever a session started or
finished.  The STF integration introduced another way for a node to be
reserved, which made the ad-hoc helpers cumbersome to share.  Extracting them
here keeps all reservation bookkeeping in one place while avoiding tight
coupling between routers.

All helpers expect a :mod:`redis.asyncio` client instance to be provided by the
caller.  This avoids creating additional connection pools for each import site
while preserving the original modules' ability to configure the client.
"""

from __future__ import annotations

import json
import logging
import time
from typing import Dict, Optional

logger = logging.getLogger(__name__)

SESSION_MAP_KEY = "session_map"
SESSION_ACTIVITY_KEY = "session_last_activity"
NODE_SESSION_COUNTS_KEY = "node_session_counts"
STF_RESERVATIONS_KEY = "stf_reservations"
STF_JWT_CACHE_PREFIX = "stf_jwt:"
STF_OWNERS_KEY = "stf_owners"  # node_id -> username for STF reservations
SESSION_OWNERS_KEY = "session_owners"  # session_id -> username
USER_SESSIONS_KEY = "user_sessions"  # username -> set of session_ids


async def sync_node_session_metadata(
    redis_client,
    node_id: str,
    active_sessions: int,
    *,
    max_sessions: Optional[int] = None,
) -> None:
    """Persist the latest session counters and derive the node status."""

    node_json = await redis_client.hget("nodes", node_id)
    if not node_json:
        logger.warning("Node %s not found while syncing session metadata", node_id)
        return

    try:
        node = json.loads(node_json)
    except json.JSONDecodeError:
        logger.warning("Node %s stored metadata is invalid JSON", node_id)
        return

    if max_sessions is None:
        try:
            max_sessions = int(node.get("max_sessions", 1))
        except (TypeError, ValueError):
            max_sessions = 1

    node["active_sessions"] = max(active_sessions, 0)

    if node["active_sessions"] >= max_sessions:
        node["status"] = "busy"
    elif node.get("status") == "busy":
        node["status"] = "online"

    await redis_client.hset("nodes", node_id, json.dumps(node))


async def reserve_node_session(redis_client, node_id: str, node: Dict) -> Optional[int]:
    """Attempt to reserve a slot on ``node`` and return the new count."""

    try:
        max_sessions = int(node.get("max_sessions", 1))
    except (TypeError, ValueError):
        max_sessions = 1

    new_count = await redis_client.hincrby(NODE_SESSION_COUNTS_KEY, node_id, 1)
    if new_count > max_sessions:
        await redis_client.hincrby(NODE_SESSION_COUNTS_KEY, node_id, -1)
        return None

    await sync_node_session_metadata(
        redis_client, node_id, new_count, max_sessions=max_sessions
    )
    return new_count


async def release_node_session(redis_client, node_id: str) -> int:
    """Release a reservation and return the updated session count."""

    new_count = await redis_client.hincrby(NODE_SESSION_COUNTS_KEY, node_id, -1)
    if new_count < 0:
        new_count = 0
        await redis_client.hset(NODE_SESSION_COUNTS_KEY, node_id, 0)

    await sync_node_session_metadata(redis_client, node_id, new_count)
    return new_count


async def set_session_owner(redis_client, session_id: str, username: str) -> None:
    """Associate a session with its owner username."""

    if not session_id or not username:
        return

    # Store session -> username mapping
    await redis_client.hset(SESSION_OWNERS_KEY, session_id, username)

    # Add session to user's session set
    user_sessions_key = f"{USER_SESSIONS_KEY}:{username}"
    await redis_client.sadd(user_sessions_key, session_id)

    logger.info("Set session %s owner to %s", session_id, username)


async def get_session_owner(redis_client, session_id: str) -> Optional[str]:
    """Get the username that owns a given session."""

    if not session_id:
        return None

    username = await redis_client.hget(SESSION_OWNERS_KEY, session_id)
    return username.decode() if isinstance(username, bytes) else username


async def get_user_sessions(redis_client, username: str) -> list[str]:
    """Get all active session IDs for a given username."""

    if not username:
        return []

    user_sessions_key = f"{USER_SESSIONS_KEY}:{username}"
    session_ids = await redis_client.smembers(user_sessions_key)

    # Convert bytes to strings if needed
    return [
        sid.decode() if isinstance(sid, bytes) else sid
        for sid in session_ids
    ]


async def get_all_sessions(redis_client) -> dict[str, dict]:
    """Get all active sessions with their metadata."""

    all_sessions = {}
    session_map = await redis_client.hgetall(SESSION_MAP_KEY)

    for session_id_raw, node_id_raw in session_map.items():
        session_id = session_id_raw.decode() if isinstance(session_id_raw, bytes) else session_id_raw
        node_id = node_id_raw.decode() if isinstance(node_id_raw, bytes) else node_id_raw

        # Get owner
        owner = await get_session_owner(redis_client, session_id)

        # Get last activity
        last_activity_raw = await redis_client.hget(SESSION_ACTIVITY_KEY, session_id)
        try:
            last_activity = int(last_activity_raw) if last_activity_raw else None
        except (TypeError, ValueError):
            last_activity = None

        all_sessions[session_id] = {
            "session_id": session_id,
            "node_id": node_id,
            "owner": owner or "unknown",
            "last_activity": last_activity,
        }

    return all_sessions


async def cleanup_session(redis_client, session_id: str, node_id: Optional[str]):
    """Remove session metadata and release any associated reservation."""

    logger.info("Cleaning up session %s for node %s", session_id, node_id)

    # Get owner before cleanup for proper user sessions removal
    owner = await get_session_owner(redis_client, session_id)

    await redis_client.hdel(SESSION_MAP_KEY, session_id)
    await redis_client.hdel(SESSION_ACTIVITY_KEY, session_id)
    await redis_client.hdel(SESSION_OWNERS_KEY, session_id)

    # Remove from user's session set
    if owner:
        user_sessions_key = f"{USER_SESSIONS_KEY}:{owner}"
        await redis_client.srem(user_sessions_key, session_id)

    if node_id:
        await release_node_session(redis_client, node_id)


async def touch_session_activity(redis_client, session_id: str) -> None:
    """Record the most recent activity timestamp for ``session_id``."""

    if not session_id:
        return

    await redis_client.hset(
        SESSION_ACTIVITY_KEY, session_id, int(time.time())
    )


async def release_inactive_sessions(redis_client, *, idle_timeout: int) -> int:
    """Release sessions that have been idle for longer than ``idle_timeout``."""

    if idle_timeout <= 0:
        return 0

    last_activity = await redis_client.hgetall(SESSION_ACTIVITY_KEY)
    if not last_activity:
        return 0

    now = int(time.time())
    cleaned = 0
    for session_id, last_seen_raw in last_activity.items():
        try:
            last_seen = int(last_seen_raw)
        except (TypeError, ValueError):
            await redis_client.hdel(SESSION_ACTIVITY_KEY, session_id)
            continue

        if now - last_seen < idle_timeout:
            continue

        node_id = await redis_client.hget(SESSION_MAP_KEY, session_id)
        logger.warning(
            "Session %s idle for %ds; releasing reservation", session_id, now - last_seen
        )
        await cleanup_session(redis_client, session_id, node_id)
        cleaned += 1

    return cleaned


async def _remove_stf_reservation(redis_client, node_id: str) -> bool:
    """Remove an STF reservation marker without touching the session count."""

    removed = await redis_client.hdel(STF_RESERVATIONS_KEY, node_id)
    return bool(removed)


def _stf_jwt_cache_key(node_id: str) -> str:
    return f"{STF_JWT_CACHE_PREFIX}{node_id}"


async def cache_stf_jwt(
    redis_client,
    node_id: str,
    *,
    token: str,
    expires_at: int,
    cookie_path: str,
) -> None:
    """Persist the generated STF JWT for ``node_id`` until ``expires_at``."""

    payload = {
        "token": token,
        "expires_at": int(expires_at),
        "cookie_path": cookie_path,
    }
    ttl_seconds = max(int(int(expires_at) - time.time()), 1)
    await redis_client.set(
        _stf_jwt_cache_key(node_id), json.dumps(payload), ex=ttl_seconds
    )


async def get_cached_stf_jwt(redis_client, node_id: str) -> Optional[Dict]:
    """Return the cached STF JWT for ``node_id`` if it remains valid."""

    cached = await redis_client.get(_stf_jwt_cache_key(node_id))
    if not cached:
        return None

    try:
        payload = json.loads(cached)
    except json.JSONDecodeError:
        logger.warning("Cached STF JWT payload for %s is invalid JSON", node_id)
        await redis_client.delete(_stf_jwt_cache_key(node_id))
        return None

    token = payload.get("token")
    expires_at_raw = payload.get("expires_at")
    cookie_path = payload.get("cookie_path")

    try:
        expires_at = int(expires_at_raw)
    except (TypeError, ValueError):
        logger.warning("Cached STF JWT for %s has invalid expiry", node_id)
        await redis_client.delete(_stf_jwt_cache_key(node_id))
        return None

    if not token or expires_at <= int(time.time()):
        await redis_client.delete(_stf_jwt_cache_key(node_id))
        return None

    return {
        "token": token,
        "expires_at": expires_at,
        "cookie_path": cookie_path if isinstance(cookie_path, str) else None,
    }


async def clear_cached_stf_jwt(redis_client, node_id: str) -> None:
    """Remove any cached STF JWT for ``node_id``."""

    await redis_client.delete(_stf_jwt_cache_key(node_id))


async def set_stf_owner(redis_client, node_id: str, username: str) -> None:
    """Associate an STF reservation with its owner username."""

    if not node_id or not username:
        return

    await redis_client.hset(STF_OWNERS_KEY, node_id, username)
    logger.info("Set STF reservation %s owner to %s", node_id, username)


async def get_stf_owner(redis_client, node_id: str) -> Optional[str]:
    """Get the username that owns an STF reservation."""

    if not node_id:
        return None

    username = await redis_client.hget(STF_OWNERS_KEY, node_id)
    return username.decode() if isinstance(username, bytes) else username


async def get_user_stf_reservations(redis_client, username: str) -> list[dict]:
    """Get all active STF reservations for a given username."""

    if not username:
        return []

    all_reservations = await redis_client.hgetall(STF_RESERVATIONS_KEY)
    user_reservations = []

    for node_id_raw, expires_at_raw in all_reservations.items():
        node_id = node_id_raw.decode() if isinstance(node_id_raw, bytes) else node_id_raw
        owner = await get_stf_owner(redis_client, node_id)

        if owner == username:
            try:
                expires_at = int(expires_at_raw)
            except (TypeError, ValueError):
                expires_at = None

            user_reservations.append({
                "node_id": node_id,
                "expires_at": expires_at,
            })

    return user_reservations


async def get_all_stf_reservations(redis_client) -> list[dict]:
    """Get all active STF reservations with owner information."""

    all_reservations = await redis_client.hgetall(STF_RESERVATIONS_KEY)
    result = []

    for node_id_raw, expires_at_raw in all_reservations.items():
        node_id = node_id_raw.decode() if isinstance(node_id_raw, bytes) else node_id_raw
        owner = await get_stf_owner(redis_client, node_id)

        try:
            expires_at = int(expires_at_raw)
        except (TypeError, ValueError):
            expires_at = None

        result.append({
            "node_id": node_id,
            "expires_at": expires_at,
            "owner": owner or "unknown",
        })

    return result


async def create_stf_reservation(
    redis_client,
    node_id: str,
    node: Dict,
    ttl_seconds: int,
    username: Optional[str] = None,
) -> Optional[int]:
    """Reserve ``node`` for manual STF usage for ``ttl_seconds`` seconds.

    Returns the absolute UNIX timestamp when the reservation expires or ``None``
    when the node is already at capacity.
    """

    now = int(time.time())

    expiry_raw = await redis_client.hget(STF_RESERVATIONS_KEY, node_id)
    if expiry_raw:
        try:
            expiry = int(expiry_raw)
        except (TypeError, ValueError):
            expiry = 0
        if expiry <= now:
            # Reservation expired but was never cleaned up. Release it before
            # attempting to create a new one.
            await _remove_stf_reservation(redis_client, node_id)
            await release_node_session(redis_client, node_id)
            await clear_cached_stf_jwt(redis_client, node_id)

    reservation = await reserve_node_session(redis_client, node_id, node)
    if reservation is None:
        return None

    ttl = max(int(ttl_seconds or 0), 1)
    expires_at = now + ttl
    await redis_client.hset(STF_RESERVATIONS_KEY, node_id, expires_at)

    # Set owner if provided
    if username:
        await set_stf_owner(redis_client, node_id, username)

    logger.info(
        "Reserved node %s for STF usage until %s (ttl=%s, owner=%s)",
        node_id, expires_at, ttl, username or "unknown"
    )
    return expires_at


async def release_stf_reservation(redis_client, node_id: str) -> bool:
    """Release a manual STF reservation if one is active."""

    removed = await _remove_stf_reservation(redis_client, node_id)
    if not removed:
        return False

    await release_node_session(redis_client, node_id)
    await clear_cached_stf_jwt(redis_client, node_id)
    await redis_client.hdel(STF_OWNERS_KEY, node_id)
    logger.info("Released STF reservation for node %s", node_id)
    return True


async def release_expired_stf_reservations(redis_client, *, now: Optional[int] = None) -> None:
    """Background task helper to release expired STF reservations."""

    current_ts = int(now if now is not None else time.time())
    reservations = await redis_client.hgetall(STF_RESERVATIONS_KEY)
    if not reservations:
        return

    expired_nodes = []
    for node_id, expiry_raw in reservations.items():
        try:
            expiry = int(expiry_raw)
        except (TypeError, ValueError):
            expiry = 0
        if expiry <= current_ts:
            expired_nodes.append(node_id)

    if not expired_nodes:
        return

    for node_id in expired_nodes:
        await _remove_stf_reservation(redis_client, node_id)
        await release_node_session(redis_client, node_id)
        await clear_cached_stf_jwt(redis_client, node_id)
        await redis_client.hdel(STF_OWNERS_KEY, node_id)
        logger.info(
            "Automatically released expired STF reservation for node %s", node_id
        )

