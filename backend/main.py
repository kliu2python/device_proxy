import asyncio
import logging
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from backend.logging_config import setup_logging
from backend.proxy_router import router as proxy_router
from backend.node_manager import router as node_router
from backend.monitor import start_monitor

setup_logging()
logger = logging.getLogger(__name__)

app = FastAPI(title="Appium/Selenium Proxy Server")

frontend_dir = Path(__file__).resolve().parent.parent / "frontend"

if frontend_dir.exists():
    app.mount("/static", StaticFiles(directory=frontend_dir), name="static")

app.include_router(proxy_router)
app.include_router(node_router)


@app.get("/", response_class=FileResponse)
async def serve_frontend():
    index_path = frontend_dir / "index.html"
    if not index_path.exists():
        raise HTTPException(status_code=404, detail="Frontend not configured")
    return FileResponse(index_path)

@app.on_event("startup")
async def startup_event():
    logger.info("Starting background monitor task")
    asyncio.create_task(start_monitor())
