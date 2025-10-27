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
NODE_SESSION_COUNTS_KEY = "node_session_counts"
STF_RESERVATIONS_KEY = "stf_reservations"


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


async def cleanup_session(redis_client, session_id: str, node_id: Optional[str]):
    """Remove session metadata and release any associated reservation."""

    logger.info("Cleaning up session %s for node %s", session_id, node_id)
    await redis_client.hdel(SESSION_MAP_KEY, session_id)
    if node_id:
        await release_node_session(redis_client, node_id)


async def _remove_stf_reservation(redis_client, node_id: str) -> bool:
    """Remove an STF reservation marker without touching the session count."""

    removed = await redis_client.hdel(STF_RESERVATIONS_KEY, node_id)
    return bool(removed)


async def create_stf_reservation(
    redis_client,
    node_id: str,
    node: Dict,
    ttl_seconds: int,
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

    reservation = await reserve_node_session(redis_client, node_id, node)
    if reservation is None:
        return None

    ttl = max(int(ttl_seconds or 0), 1)
    expires_at = now + ttl
    await redis_client.hset(STF_RESERVATIONS_KEY, node_id, expires_at)
    logger.info(
        "Reserved node %s for STF usage until %s (ttl=%s)", node_id, expires_at, ttl
    )
    return expires_at


async def release_stf_reservation(redis_client, node_id: str) -> bool:
    """Release a manual STF reservation if one is active."""

    removed = await _remove_stf_reservation(redis_client, node_id)
    if not removed:
        return False

    await release_node_session(redis_client, node_id)
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
        logger.info(
            "Automatically released expired STF reservation for node %s", node_id
        )

