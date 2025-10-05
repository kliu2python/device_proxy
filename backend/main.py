from fastapi import FastAPI
from backend.proxy_router import router as proxy_router
from backend.node_manager import router as node_router
from backend.monitor import start_monitor
import asyncio

app = FastAPI(title="Appium/Selenium Proxy Server")

app.include_router(proxy_router)
app.include_router(node_router)

@app.on_event("startup")
async def startup_event():
    asyncio.create_task(start_monitor())
