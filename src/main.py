"""
AI Security Gateway - Main Application
A centralized defense layer for securing AI-driven interactions
"""

from contextlib import asynccontextmanager
import asyncio
from fastapi import FastAPI
from fastapi import Request
from fastapi.middleware.cors import CORSMiddleware
from .gateway.router import router as gateway_router
from .monitoring.logger import setup_logging, set_request_id
from .config.settings import settings

# Setup logging
setup_logging()

# Initialize database
from .monitoring.database import init_db
init_db()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup/shutdown lifecycle for the notification outbox."""
    from .queue.outbox import run_notification_outbox
    outbox_stop = asyncio.Event()
    outbox_task = asyncio.create_task(run_notification_outbox(outbox_stop), name="notification-outbox")
    yield
    outbox_stop.set()
    await outbox_task


app = FastAPI(
    title="AI Security Gateway",
    description="Enterprise-grade AI Security Gateway for monitoring and securing AI interactions",
    version="2.0.0",
    lifespan=lifespan,
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=settings.CORS_ALLOW_CREDENTIALS,
    allow_methods=settings.ALLOWED_METHODS,
    allow_headers=settings.ALLOWED_HEADERS,
)

@app.middleware("http")
async def request_id_middleware(request: Request, call_next):
    """Inject a unique request ID into every request context and response headers."""
    incoming_id = request.headers.get("X-Request-ID")
    request_id = set_request_id(incoming_id)
    response = await call_next(request)
    response.headers["X-Request-ID"] = request_id
    return response

@app.middleware("http")
async def limit_body_size(request: Request, call_next):
    """Reject oversized request bodies before they are buffered."""
    content_length = request.headers.get("content-length")
    if content_length and content_length.isdigit() and int(content_length) > settings.MAX_BODY_BYTES:
        from fastapi.responses import JSONResponse
        return JSONResponse(status_code=413, content={"detail": "Request body too large"})
    # ponytail: Content-Length header only; chunked bodies are not measured — cap at the reverse proxy
    return await call_next(request)

@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    if not settings.ENABLE_SECURITY_HEADERS:
        return response

    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
    if request.url.scheme == "https":
        response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
    return response

# Include routers
app.include_router(gateway_router, prefix="/api/v1", tags=["gateway"])

# Mount static files and serve dashboard
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
import os

static_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
os.makedirs(static_dir, exist_ok=True)
app.mount("/static", StaticFiles(directory=static_dir), name="static")

@app.get("/")
async def root():
    return FileResponse(os.path.join(static_dir, "index.html"))

@app.get("/health")
async def health_check():
    return {"status": "healthy", "version": "2.0.0"}


@app.get("/ready")
async def readiness_check():
    """Readiness probe for traffic routing; liveness remains available at /health."""
    from fastapi import HTTPException, status
    from sqlalchemy import text
    from .monitoring.database import SessionLocal, check_migrations_current

    if not check_migrations_current():
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Database migrations are not current")

    session = SessionLocal()
    try:
        session.execute(text("SELECT 1"))
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Database is unavailable") from exc
    finally:
        session.close()

    return {"status": "ready", "version": "2.0.0"}

