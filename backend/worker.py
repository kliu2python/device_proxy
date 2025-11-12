"""Standalone background worker entry point.

This module is intended to be executed via ``python -m backend.worker``.  It
boots logging, optionally loads node definitions from the CSV file, and then
runs the long-lived monitor loop defined in :mod:`backend.monitor`.
"""

import asyncio
import logging
import os

from typing import Optional

from backend.logging_config import setup_logging
from backend.monitor import start_monitor
from backend.node_manager import load_nodes_from_csv


def _flag_enabled(value: Optional[str], *, default: bool = True) -> bool:
    if value is None:
        return default

    value = value.strip().lower()
    if not value:
        return default
    if value in {"1", "true", "yes", "y", "on"}:
        return True
    if value in {"0", "false", "no", "n", "off"}:
        return False
    return default


async def _run_worker() -> None:
    setup_logging()
    logger = logging.getLogger(__name__)

    preload = _flag_enabled(os.getenv("WORKER_PRELOAD_CSV"), default=True)
    if preload:
        logger.info("Loading node resources before starting monitor loop")
        await load_nodes_from_csv()
    else:
        logger.info("Skipping CSV preload; assuming nodes already registered in Redis")

    logger.info("Starting monitor loop")
    await start_monitor()


def main() -> None:
    try:
        asyncio.run(_run_worker())
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
