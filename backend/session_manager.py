"""Session management API endpoints.

This module provides REST APIs for managing active sessions, including:
- Listing sessions by user
- Viewing all active sessions (admin)
- Force-releasing sessions
- Viewing session details

All endpoints support username-based session management to allow users to
manage their sessions even when the original browser is closed.
"""

from __future__ import annotations

import logging
import time
from typing import Optional

from fastapi import APIRouter, HTTPException, Header, Request
import redis.asyncio as aioredis

from .session_state import (
    SESSION_MAP_KEY,
    SESSION_ACTIVITY_KEY,
    STF_RESERVATIONS_KEY,
    cleanup_session,
    get_session_owner,
    get_user_sessions,
    get_all_sessions,
    get_user_stf_reservations,
    get_all_stf_reservations,
    get_stf_owner,
    release_stf_reservation,
)

logger = logging.getLogger(__name__)

router = APIRouter()
redis_client = aioredis.from_url("redis://10.160.13.16:6379/0", decode_responses=True)


def _get_username_from_request(request: Request, x_username: Optional[str] = None) -> str:
    """Extract username from request headers or use default."""

    # Try various header formats
    username = (
        x_username
        or request.headers.get("X-User")
        or request.headers.get("Username")
        or request.headers.get("User")
        or "anonymous"
    )

    return username.strip()


@router.get("/sessions/my")
async def get_my_sessions(
    request: Request,
    x_username: Optional[str] = Header(None),
):
    """Get all active sessions for the current user.

    Returns:
        List of session objects with session_id, node_id, and last_activity
    """

    username = _get_username_from_request(request, x_username)

    if username == "anonymous":
        return {
            "username": username,
            "sessions": [],
            "message": "No username provided. Use X-Username header to track your sessions.",
        }

    session_ids = await get_user_sessions(redis_client, username)

    sessions = []
    for session_id in session_ids:
        # Get session details
        node_id = await redis_client.hget(SESSION_MAP_KEY, session_id)
        last_activity_raw = await redis_client.hget(SESSION_ACTIVITY_KEY, session_id)

        try:
            last_activity = int(last_activity_raw) if last_activity_raw else None
        except (TypeError, ValueError):
            last_activity = None

        # Calculate idle time
        idle_seconds = None
        if last_activity:
            idle_seconds = int(time.time()) - last_activity

        sessions.append({
            "session_id": session_id,
            "node_id": node_id.decode() if isinstance(node_id, bytes) else node_id,
            "last_activity": last_activity,
            "idle_seconds": idle_seconds,
        })

    return {
        "username": username,
        "sessions": sessions,
        "count": len(sessions),
    }


@router.get("/sessions/all")
async def get_all_sessions_api(
    request: Request,
    x_username: Optional[str] = Header(None),
):
    """Get all active sessions (for admin use).

    Returns:
        Dictionary of all sessions with metadata
    """

    username = _get_username_from_request(request, x_username)

    logger.info("User %s requested all sessions", username)

    all_sessions = await get_all_sessions(redis_client)

    # Calculate idle times
    now = int(time.time())
    for session_data in all_sessions.values():
        if session_data.get("last_activity"):
            session_data["idle_seconds"] = now - session_data["last_activity"]
        else:
            session_data["idle_seconds"] = None

    return {
        "sessions": list(all_sessions.values()),
        "count": len(all_sessions),
        "requested_by": username,
    }


@router.get("/sessions/{session_id}")
async def get_session_details(
    session_id: str,
    request: Request,
    x_username: Optional[str] = Header(None),
):
    """Get details about a specific session.

    Args:
        session_id: The session ID to look up

    Returns:
        Session details including owner, node, and activity
    """

    username = _get_username_from_request(request, x_username)

    # Check if session exists
    node_id = await redis_client.hget(SESSION_MAP_KEY, session_id)
    if not node_id:
        raise HTTPException(status_code=404, detail=f"Session {session_id} not found")

    owner = await get_session_owner(redis_client, session_id)
    last_activity_raw = await redis_client.hget(SESSION_ACTIVITY_KEY, session_id)

    try:
        last_activity = int(last_activity_raw) if last_activity_raw else None
    except (TypeError, ValueError):
        last_activity = None

    idle_seconds = None
    if last_activity:
        idle_seconds = int(time.time()) - last_activity

    return {
        "session_id": session_id,
        "node_id": node_id.decode() if isinstance(node_id, bytes) else node_id,
        "owner": owner or "unknown",
        "last_activity": last_activity,
        "idle_seconds": idle_seconds,
        "requested_by": username,
    }


@router.delete("/sessions/{session_id}/force")
async def force_release_session(
    session_id: str,
    request: Request,
    x_username: Optional[str] = Header(None),
):
    """Force-release a session.

    Users can release their own sessions. This is useful when a browser
    closes before properly releasing the session.

    Args:
        session_id: The session ID to release

    Returns:
        Success message with session details
    """

    username = _get_username_from_request(request, x_username)

    # Check if session exists
    node_id = await redis_client.hget(SESSION_MAP_KEY, session_id)
    if not node_id:
        raise HTTPException(status_code=404, detail=f"Session {session_id} not found")

    node_id_str = node_id.decode() if isinstance(node_id, bytes) else node_id

    # Get session owner
    owner = await get_session_owner(redis_client, session_id)

    # Check if user is the owner or an admin
    # For now, we allow anyone to release any session (can be restricted later)
    if owner and owner != username and username != "admin":
        logger.warning(
            "User %s attempted to release session %s owned by %s",
            username, session_id, owner
        )
        # Still allow for now, but log it
        # raise HTTPException(
        #     status_code=403,
        #     detail=f"Session {session_id} is owned by {owner}, you cannot release it"
        # )

    # Clean up the session
    await cleanup_session(redis_client, session_id, node_id_str)

    logger.info(
        "User %s force-released session %s (owner: %s, node: %s)",
        username, session_id, owner or "unknown", node_id_str
    )

    return {
        "message": "Session released successfully",
        "session_id": session_id,
        "node_id": node_id_str,
        "owner": owner or "unknown",
        "released_by": username,
    }


@router.get("/stf/my")
async def get_my_stf_reservations(
    request: Request,
    x_username: Optional[str] = Header(None),
):
    """Get all active STF reservations for the current user.

    Returns:
        List of STF reservation objects with node_id and expires_at
    """

    username = _get_username_from_request(request, x_username)

    if username == "anonymous":
        return {
            "username": username,
            "reservations": [],
            "message": "No username provided. Use X-Username header to track your reservations.",
        }

    reservations = await get_user_stf_reservations(redis_client, username)

    # Calculate remaining time
    now = int(time.time())
    for reservation in reservations:
        if reservation.get("expires_at"):
            reservation["remaining_seconds"] = max(
                reservation["expires_at"] - now, 0
            )
        else:
            reservation["remaining_seconds"] = None

    return {
        "username": username,
        "reservations": reservations,
        "count": len(reservations),
    }


@router.get("/stf/all")
async def get_all_stf_reservations_api(
    request: Request,
    x_username: Optional[str] = Header(None),
):
    """Get all active STF reservations (for admin use).

    Returns:
        List of all STF reservations with owner information
    """

    username = _get_username_from_request(request, x_username)

    logger.info("User %s requested all STF reservations", username)

    reservations = await get_all_stf_reservations(redis_client)

    # Calculate remaining time
    now = int(time.time())
    for reservation in reservations:
        if reservation.get("expires_at"):
            reservation["remaining_seconds"] = max(
                reservation["expires_at"] - now, 0
            )
        else:
            reservation["remaining_seconds"] = None

    return {
        "reservations": reservations,
        "count": len(reservations),
        "requested_by": username,
    }


@router.delete("/stf/{node_id}/force")
async def force_release_stf_reservation(
    node_id: str,
    request: Request,
    x_username: Optional[str] = Header(None),
):
    """Force-release an STF reservation.

    Users can release their own STF reservations. This is useful when a browser
    closes before properly releasing the reservation.

    Args:
        node_id: The node ID to release

    Returns:
        Success message with reservation details
    """

    username = _get_username_from_request(request, x_username)

    # Check if reservation exists
    expires_at_raw = await redis_client.hget(STF_RESERVATIONS_KEY, node_id)
    if not expires_at_raw:
        raise HTTPException(
            status_code=404, detail=f"No STF reservation found for node {node_id}"
        )

    # Get reservation owner
    owner = await get_stf_owner(redis_client, node_id)

    # Check if user is the owner or an admin
    # For now, we allow anyone to release any reservation (can be restricted later)
    if owner and owner != username and username != "admin":
        logger.warning(
            "User %s attempted to release STF reservation for node %s owned by %s",
            username, node_id, owner
        )
        # Still allow for now, but log it
        # raise HTTPException(
        #     status_code=403,
        #     detail=f"STF reservation for node {node_id} is owned by {owner}"
        # )

    # Release the reservation
    released = await release_stf_reservation(redis_client, node_id)

    if not released:
        raise HTTPException(
            status_code=404, detail=f"Failed to release STF reservation for node {node_id}"
        )

    logger.info(
        "User %s force-released STF reservation for node %s (owner: %s)",
        username, node_id, owner or "unknown"
    )

    return {
        "message": "STF reservation released successfully",
        "node_id": node_id,
        "owner": owner or "unknown",
        "released_by": username,
    }
