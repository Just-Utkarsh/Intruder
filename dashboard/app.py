"""
Lightweight FastAPI dashboard for intrusion history.

Decrypts images only in memory for response; never writes plaintext to disk.
Password submitted per-request (consider HTTPS reverse proxy in production).
"""

from __future__ import annotations

import base64
import json
import sys
from datetime import datetime
from io import BytesIO
from pathlib import Path
from typing import Any, Optional

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from fastapi import FastAPI, HTTPException, Form
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel

from intruder_detector.config import load_config
from database.models import init_db
from database.repository import IncidentRepository
from security.encryption.crypto import CryptoManager
from security.password.manager import PasswordManager
from security.secure_storage.storage import SecureStorage

app = FastAPI(title="Intruder Detector", docs_url="/api/docs")
_config = load_config()
_storage = SecureStorage(Path(_config["storage"]["data_dir"]))
_crypto = CryptoManager(iterations=_config["security"]["kdf_iterations"])
_salt_path = _storage.data_dir / "auth" / "master.salt"
if _salt_path.exists():
    _crypto.set_master_salt(_salt_path.read_bytes())
init_db(_storage.data_dir / "events.db")


class IncidentSummary(BaseModel):
    id: str
    timestamp: datetime
    confidence: float
    image_count: int


def _session():
    from database.models import _SessionLocal
    return _SessionLocal()


def _verify(password: str) -> None:
    pm = PasswordManager(_storage)
    if not pm.verify(password):
        raise HTTPException(401, "Invalid password")


@app.get("/", response_class=HTMLResponse)
def index() -> str:
    return """
    <!DOCTYPE html>
    <html><head><title>Intruder Detector</title>
    <style>
      body{font-family:system-ui;max-width:900px;margin:2rem auto;padding:0 1rem;background:#0f1419;color:#e7e9ea}
      input,button{padding:0.5rem;margin:0.25rem}
      .card{border:1px solid #38444d;border-radius:8px;padding:1rem;margin:1rem 0}
      img{max-width:100%;border-radius:4px}
    </style></head><body>
    <h1>Intruder Detector</h1>
    <p>Local intrusion history viewer. Data never leaves this machine.</p>
    <div class="card">
      <label>Vault password: <input type="password" id="pw"/></label>
      <button onclick="load()">Load events</button>
    </div>
    <div id="events"></div>
    <script>
    async function load(){
      const pw=document.getElementById('pw').value;
      const r=await fetch('/api/events?password='+encodeURIComponent(pw));
      const data=await r.json();
      const el=document.getElementById('events');
      if(!r.ok){el.innerHTML='<p style=color:#f4212e>'+data.detail+'</p>';return;}
      el.innerHTML=data.map(e=>`
        <div class="card">
          <b>${e.id}</b> — ${e.timestamp}<br/>
          Confidence: ${(e.confidence*100).toFixed(1)}% — ${e.image_count} images
          <button onclick="view('${e.id}')">View images</button>
          <div id="imgs-${e.id}"></div>
        </div>`).join('');
    }
    async function view(id){
      const pw=document.getElementById('pw').value;
      const r=await fetch(`/api/events/${id}/images?password=`+encodeURIComponent(pw));
      const imgs=await r.json();
      document.getElementById('imgs-'+id).innerHTML=imgs.map(u=>`<img src="${u}"/>`).join('');
    }
    </script></body></html>
    """


@app.get("/api/events", response_model=list[IncidentSummary])
def list_events(password: str, limit: int = 50) -> list[IncidentSummary]:
    _verify(password)
    session = _session()
    try:
        repo = IncidentRepository(session)
        records = repo.list_all(limit=limit)
        return [
            IncidentSummary(
                id=r.id,
                timestamp=r.timestamp,
                confidence=r.confidence,
                image_count=r.image_count,
            )
            for r in records
        ]
    finally:
        session.close()


@app.get("/api/events/{incident_id}/images")
def view_images(incident_id: str, password: str) -> list[str]:
    _verify(password)
    session = _session()
    try:
        repo = IncidentRepository(session)
        record = repo.get(incident_id)
        if not record:
            raise HTTPException(404, "Not found")
    finally:
        session.close()

    incident_dir = Path(record.storage_path)
    meta_raw = _storage.read_encrypted(incident_dir / "meta.enc", _crypto, password)
    meta = json.loads(meta_raw.decode("utf-8"))
    urls: list[str] = []
    for img_name in meta.get("images", []):
        data = _storage.read_encrypted(incident_dir / img_name, _crypto, password)
        b64 = base64.b64encode(data).decode("ascii")
        urls.append(f"data:image/jpeg;base64,{b64}")
    return urls


def run_dashboard(host: str = "127.0.0.1", port: int = 8765) -> None:
    import uvicorn
    uvicorn.run(app, host=host, port=port)
