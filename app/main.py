"""FastAPI server: analyse the bundled dataset or an uploaded one, then ask follow-up questions."""
from __future__ import annotations

import io
import os
import shutil
import tempfile
import threading
import uuid
import zipfile
from pathlib import Path

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from triage import llm
from triage.pipeline import Analysis, analyse
from triage.qa import Index, answer

ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = Path(os.getenv("DATA_DIR", ROOT / "data"))
STATIC = Path(__file__).resolve().parent / "static"
MAX_UPLOAD = 30 * 1024 * 1024

app = FastAPI(title="Orbit Logistics - Security Incident Triage Assistant", version="1.0")
_lock = threading.Lock()
_sessions: dict[str, tuple[Analysis, Index]] = {}


def _load(sid: str, path: Path) -> tuple[Analysis, Index]:
    an = analyse(path)
    with _lock:
        if len(_sessions) > 20:
            _sessions.pop(next(iter(_sessions)))
        _sessions[sid] = (an, Index(an))
    return _sessions[sid]


def _get(sid: str) -> tuple[Analysis, Index]:
    if sid not in _sessions:
        if sid == "default":
            return _load("default", DATA_DIR)
        raise HTTPException(404, "Unknown dataset id. Upload the files again.")
    return _sessions[sid]


class Ask(BaseModel):
    question: str = Field(min_length=1, max_length=1000)
    dataset: str = "default"
    history: list[dict] = []


@app.get("/api/health")
def health() -> dict:
    return {"ok": True, "llm": [f"{p.name}/{p.model}" for p in llm.providers()] or "none (deterministic mode)"}


@app.get("/api/analyze")
def analyze(dataset: str = "default", refresh: bool = False) -> JSONResponse:
    if refresh and dataset == "default":
        _load("default", DATA_DIR)
    an, _ = _get(dataset)
    return JSONResponse({"dataset_id": dataset, **an.to_json(), "report_markdown": an.report_md})


@app.get("/api/report.md")
def report(dataset: str = "default") -> PlainTextResponse:
    an, _ = _get(dataset)
    return PlainTextResponse(an.report_md, media_type="text/markdown",
                             headers={"Content-Disposition": "attachment; filename=incident_report.md"})


@app.post("/api/upload")
async def upload(files: list[UploadFile] = File(...)) -> JSONResponse:
    """Upload a .zip of the dataset, or many individual files (folder structure from the file names is kept)."""
    tmp = Path(tempfile.mkdtemp(prefix="orbit_"))
    total = 0
    try:
        for uf in files:
            data = await uf.read()
            total += len(data)
            if total > MAX_UPLOAD:
                raise HTTPException(413, "Upload too large (30 MB max)")
            name = (uf.filename or "file").replace("\\", "/")
            if name.lower().endswith(".zip"):
                with zipfile.ZipFile(io.BytesIO(data)) as z:
                    for m in z.infolist():
                        target = (tmp / m.filename).resolve()
                        if m.is_dir() or not str(target).startswith(str(tmp.resolve())):
                            continue          # zip-slip guard
                        target.parent.mkdir(parents=True, exist_ok=True)
                        target.write_bytes(z.read(m))
            else:
                target = (tmp / name.lstrip("/")).resolve()
                if not str(target).startswith(str(tmp.resolve())):
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(data)
        sid = uuid.uuid4().hex[:12]
        an, _ = _load(sid, tmp)
        return JSONResponse({"dataset_id": sid, **an.to_json(), "report_markdown": an.report_md})
    except zipfile.BadZipFile:
        raise HTTPException(400, "That .zip file could not be opened")
    except FileNotFoundError as e:
        raise HTTPException(400, str(e))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


@app.post("/api/ask")
def ask(q: Ask) -> dict:
    an, idx = _get(q.dataset)
    return answer(an, idx, q.question, q.history)


@app.get("/")
def index() -> FileResponse:
    return FileResponse(STATIC / "index.html")


app.mount("/static", StaticFiles(directory=STATIC), name="static")
