import os, json
from pathlib import Path
import httpx
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse, Response
from fastapi.middleware.gzip import GZipMiddleware

app = FastAPI(title="Wesla Admin Portal")
app.add_middleware(GZipMiddleware, minimum_size=1000, compresslevel=5)

DEFAULT_WESLA_API_BASE = "https://wesla-web-production.up.railway.app"

def upstream_base():
    # Keep the admin portal usable even if the optional Railway variable was
    # omitted. An explicit value still takes precedence for custom domains.
    value = os.getenv("WESLA_API_BASE", "").strip() or DEFAULT_WESLA_API_BASE
    value = value.rstrip("/")
    if not value.startswith(("https://", "http://")):
        raise HTTPException(status_code=503, detail="إعداد رابط الخادم غير صالح؛ يجب أن يبدأ بـ https:// أو http://.")
    return value

@app.get("/")
def admin_home():
    html=Path("app/static/control.html").read_text(encoding="utf-8")
    # Admin API calls are same-origin and proxied below. This avoids browser
    # CORS and cross-site cookie restrictions between the two Railway services.
    html=html.replace("<script>", f"<script>window.WESLA_API_BASE='';window.WESLA_PUBLIC_URL={json.dumps(os.getenv('WESLA_PUBLIC_URL','').rstrip('/'))};", 1)
    return HTMLResponse(html, headers={"Cache-Control": "no-store"})

@app.get("/health")
async def health():
    base=upstream_base()
    try:
        async with httpx.AsyncClient(timeout=8.0) as client:
            r=await client.get(base+"/health")
        return {"ok":r.status_code==200,"service":"wesla-admin-portal","api_status":r.status_code}
    except httpx.HTTPError:
        return Response(content='{"ok":false,"service":"wesla-admin-portal","api_status":"unreachable"}',media_type="application/json",status_code=503)

@app.api_route("/api/{path:path}", methods=["GET","POST","PUT","PATCH","DELETE","OPTIONS"])
async def proxy_api(path:str, request:Request):
    target=upstream_base()+"/api/"+path
    headers={}
    for name in ("accept","content-type","cookie","authorization","user-agent"):
        value=request.headers.get(name)
        if value: headers[name]=value
    try:
        async with httpx.AsyncClient(timeout=45.0, follow_redirects=False) as client:
            upstream=await client.request(
                request.method, target, params=request.query_params,
                content=await request.body(), headers=headers
            )
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=502, detail="تعذر الاتصال بخادم وصلة الأساسي: "+str(exc))
    out_headers={}
    for name in ("content-type","content-disposition","cache-control","set-cookie","location"):
        value=upstream.headers.get(name)
        if value: out_headers[name]=value
    return Response(content=upstream.content,status_code=upstream.status_code,headers=out_headers)
