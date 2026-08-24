from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.admin import router as admin_router
from app.audit import configure_logging
from app.correlation.router_api import router as correlation_router
from app.decision.api import router as decision_router
from app.ssf.push_receiver import router as push_router

configure_logging()
logger = logging.getLogger("ssf_bridge")


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("ssf_apm_bridge_starting")
    yield


app = FastAPI(
    title="SSF-APM Bridge",
    description="OpenID Shared Signals Framework receiver that drives BIG-IP APM enforcement.",
    version="0.1.0",
    lifespan=lifespan,
)

app.include_router(push_router)
app.include_router(admin_router)
app.include_router(correlation_router)
app.include_router(decision_router)


@app.get("/health")
async def health() -> dict:
    return {"status": "ok"}


@app.get("/readyz")
async def readyz() -> dict:
    # Deliberately minimal for the MVP: process is up and routes are
    # mounted. Extend this to check Redis connectivity once STORE_BACKEND=redis
    # is your production default rather than a demo option.
    return {"status": "ready"}
