import logging
import os
import json
from contextlib import asynccontextmanager
from urllib.parse import urlsplit
from pathlib import Path

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from starlette.concurrency import run_in_threadpool

from netlens.capture import CaptureError, CaptureService
from netlens.models import CaptureRequest, CaptureStatus

class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        entry = {"time": self.formatTime(record), "level": record.levelname,
                 "logger": record.name, "message": record.getMessage()}
        if record.exc_info:
            entry["exception"] = self.formatException(record.exc_info)
        return json.dumps(entry)


handler = logging.StreamHandler()
handler.setFormatter(JsonFormatter())
logging.basicConfig(level=logging.INFO, handlers=[handler])


def create_app(service: CaptureService | None = None) -> FastAPI:
    if service is None:
        allowed = {item.strip() for item in os.getenv("NETLENS_ALLOWED_INTERFACES", "").split(",") if item.strip()}
        service = CaptureService(allowed)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        yield
        try:
            await run_in_threadpool(service.stop)
        except CaptureError:
            logging.getLogger(__name__).exception("capture_shutdown_failed")

    app = FastAPI(title="NetLens", version="0.1.0", lifespan=lifespan)
    app.state.capture = service
    static_dir = Path(__file__).parent / "static"
    app.mount("/static", StaticFiles(directory=static_dir), name="static")

    @app.get("/", include_in_schema=False)
    def workspace():
        return FileResponse(static_dir / "index.html")

    @app.middleware("http")
    async def local_only(request: Request, call_next):
        client = request.client.host if request.client else ""
        host = request.headers.get("host", "").split(":")[0].lower()
        origin = request.headers.get("origin")
        # Restrict both network peers and browser origins; do not treat Host as authentication.
        if client not in {"127.0.0.1", "::1"} or host not in {"127.0.0.1", "localhost"}:
            return JSONResponse(status_code=403, content={"detail": "NetLens is available only locally."})
        if origin and (urlsplit(origin).scheme not in {"http", "https"} or urlsplit(origin).hostname not in {"localhost", "127.0.0.1"}):
            return JSONResponse(status_code=403, content={"detail": "Origin is not allowed."})
        return await call_next(request)

    @app.get("/api/health")
    def health():
        return {"status": "ok"}

    @app.get("/api/interfaces")
    def interfaces():
        return {"interfaces": service.interfaces()}

    @app.post("/api/capture/start", response_model=CaptureStatus)
    def start_capture(body: CaptureRequest):
        try:
            return service.start(body.interface)
        except CaptureError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

    @app.post("/api/capture/stop", response_model=CaptureStatus)
    def stop_capture():
        try:
            return service.stop()
        except CaptureError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

    @app.get("/api/capture/status", response_model=CaptureStatus)
    def capture_status():
        return service.status()

    @app.get("/api/packets")
    def packets(offset: int = Query(0, ge=0), limit: int = Query(100, ge=1, le=500), protocol: str | None = Query(None, max_length=32)):
        items, total = service.packets(offset, limit, protocol)
        return {"items": items, "total": total, "offset": offset, "limit": limit}

    return app


app = create_app()
