import os, json
from pathlib import Path
from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from fastapi.middleware.gzip import GZipMiddleware

app = FastAPI(title="Wesla Admin Portal")
app.add_middleware(GZipMiddleware, minimum_size=1000, compresslevel=5)

@app.get("/")
def admin_home():
    html=Path("app/static/control.html").read_text(encoding="utf-8")
    api_base=json.dumps(os.getenv("WESLA_API_BASE","").rstrip("/"))
    public_url=json.dumps(os.getenv("WESLA_PUBLIC_URL","").rstrip("/"))
    html=html.replace("<script>", f"<script>window.WESLA_API_BASE={api_base};window.WESLA_PUBLIC_URL={public_url};", 1)
    return HTMLResponse(html, headers={"Cache-Control": "no-store"})

@app.get("/health")
def health():
    return {"ok": True, "service": "wesla-admin-portal"}
