import asyncio
import logging
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from backend.logging_config import setup_logging
from backend.proxy_router import router as proxy_router
from backend.node_manager import load_nodes_from_csv, router as node_router
from backend.monitor import start_monitor

setup_logging()
logger = logging.getLogger(__name__)

app = FastAPI(title="Appium/Selenium Proxy Server")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

frontend_dir = Path(__file__).resolve().parent.parent / "frontend"

if frontend_dir.exists():
    app.mount("/static", StaticFiles(directory=frontend_dir), name="static")

app.include_router(proxy_router)
app.include_router(node_router)


def _get_index_path() -> Path:
    index_path = frontend_dir / "index.html"
    if not index_path.exists():
        raise HTTPException(status_code=404, detail="Frontend not configured")
    return index_path


def _get_embed_path() -> Path:
    embed_path = frontend_dir / "embed.html"
    if not embed_path.exists():
        raise HTTPException(status_code=404, detail="Embed view not configured")
    return embed_path


@app.get("/", response_class=FileResponse)
async def serve_frontend():
    return FileResponse(_get_index_path())


@app.get("/admin", response_class=FileResponse)
async def serve_admin_frontend():
    return FileResponse(_get_index_path())


@app.get("/stream/embed", response_class=FileResponse)
async def serve_stream_embed():
    return FileResponse(_get_embed_path())


@app.on_event("startup")
async def startup_event():
    await load_nodes_from_csv()
    logger.info("Starting background monitor task")
    asyncio.create_task(start_monitor())
