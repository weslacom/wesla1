from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.middleware.gzip import GZipMiddleware

app = FastAPI(title="Wesla Admin Portal")
app.add_middleware(GZipMiddleware, minimum_size=1000, compresslevel=5)

@app.get("/")
def admin_home():
    return FileResponse("app/static/control.html", headers={"Cache-Control": "no-store"})

@app.get("/health")
def health():
    return {"ok": True, "service": "wesla-admin-portal"}
