import os, json
from pathlib import Path
from urllib.parse import urlsplit
import httpx
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse, Response, StreamingResponse
from fastapi.middleware.gzip import GZipMiddleware

app = FastAPI(title="Wesla Admin Portal")
app.add_middleware(GZipMiddleware, minimum_size=1000, compresslevel=5)

DEFAULT_WESLA_API_BASE = "https://wesla-web-production.up.railway.app"
DEFAULT_ADMIN_PORTAL_URL = "https://wesla-admin-production.up.railway.app"


def upstream_base(request: Request | None = None) -> str:
    """Resolve the one authoritative API host; never proxy back into this portal."""
    value = os.getenv("WESLA_API_BASE", "").strip().rstrip("/") or DEFAULT_WESLA_API_BASE
    admin_url = os.getenv("ADMIN_PORTAL_URL", DEFAULT_ADMIN_PORTAL_URL).strip().rstrip("/")
    # Common misconfiguration: the API base points to the admin service itself,
    # which would create a recursive proxy loop and end in a timeout.
    request_host = request.url.netloc.lower() if request is not None else ""
    value_host = urlsplit(value).netloc.lower()
    admin_host = urlsplit(admin_url).netloc.lower()
    if (request_host and value_host == request_host) or (admin_host and value_host == admin_host):
        value = DEFAULT_WESLA_API_BASE
    if value.endswith("/api"):
        value = value[:-4]
    parsed = urlsplit(value)
    # Prefer Railway private networking when configured. Plain HTTP is accepted
    # only for Railway's private DNS suffix; public upstreams must always use HTTPS.
    private_railway = parsed.scheme == "http" and bool(parsed.hostname) and parsed.hostname.endswith(".railway.internal")
    public_https = parsed.scheme == "https" and bool(parsed.hostname)
    if not (private_railway or public_https) or parsed.username or parsed.password or parsed.path not in ("", "/") or parsed.query or parsed.fragment:
        raise HTTPException(status_code=503, detail="إعداد رابط خادم وصلة الأساسي غير صحيح. استخدم HTTPS أو عنوان Railway داخلي.")

    return value


@app.get("/")
def admin_home():
    html = Path("app/static/control.html").read_text(encoding="utf-8")
    # API calls stay same-origin and are securely proxied by this service.
    html = html.replace(
        "<script>",
        f"<script>window.WESLA_API_BASE='';window.WESLA_PUBLIC_URL={json.dumps(os.getenv('WESLA_PUBLIC_URL', '').rstrip('/'))};",
        1,
    )
    return HTMLResponse(
        html,
        headers={"Cache-Control": "no-store, no-cache, must-revalidate, max-age=0", "Pragma": "no-cache"},
    )


@app.get("/health")
async def health(request: Request):
    base = upstream_base(request)
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(8.0, connect=4.0), follow_redirects=False) as client:
            upstream = await client.get(base + "/health")
        ok = upstream.status_code == 200
        return Response(
            content=json.dumps({"ok": ok, "service": "wesla-admin-portal", "api_status": upstream.status_code}),
            media_type="application/json",
            status_code=200 if ok else 503,
        )
    except httpx.HTTPError:
        return Response(
            content='{"ok":false,"service":"wesla-admin-portal","api_status":"unreachable"}',
            media_type="application/json",
            status_code=503,
        )


@app.api_route("/api/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"])
async def proxy_api(path: str, request: Request):
    target = upstream_base(request) + "/api/" + path
    headers = {}
    for name in (
        "accept", "content-type", "cookie", "authorization", "user-agent",
        "x-forwarded-for", "x-real-ip", "origin", "referer",
    ):
        value = request.headers.get(name)
        if value:
            headers[name] = value
    # SSE must be streamed end-to-end; buffering it in the normal JSON proxy
    # would prevent the independent admin portal from receiving live events.
    if path == "admin/events" and request.method == "GET":
        client = httpx.AsyncClient(timeout=httpx.Timeout(None, connect=8.0), follow_redirects=False)
        context = client.stream("GET", target, params=request.query_params, headers=headers)
        try:
            upstream = await context.__aenter__()
        except httpx.HTTPError:
            await client.aclose()
            raise HTTPException(status_code=502, detail="تعذر فتح قناة التحديثات المباشرة.")
        if upstream.status_code >= 400:
            body = await upstream.aread()
            content_type = upstream.headers.get("content-type", "application/json")
            await context.__aexit__(None, None, None)
            await client.aclose()
            return Response(content=body, status_code=upstream.status_code, headers={"content-type": content_type, "cache-control": "no-store"})
        async def stream_upstream():
            try:
                async for chunk in upstream.aiter_raw():
                    yield chunk
            finally:
                await context.__aexit__(None, None, None)
                await client.aclose()
        return StreamingResponse(stream_upstream(), status_code=upstream.status_code, media_type="text/event-stream", headers={"cache-control": "no-cache, no-store", "x-accel-buffering": "no", "content-encoding": "identity"})
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(45.0, connect=8.0), follow_redirects=False) as client:
            upstream = await client.request(
                request.method,
                target,
                params=request.query_params,
                content=await request.body(),
                headers=headers,
            )
    except httpx.HTTPError:
        raise HTTPException(status_code=502, detail="تعذر الاتصال بخادم وصلة الرئيسي. تحقق من حالة خدمة الموقع الرئيسي.")
    out_headers = {}
    for name in ("content-type", "content-disposition", "cache-control", "location"):
        value = upstream.headers.get(name)
        if value:
            out_headers[name] = value
    # Admin data is always live data; do not let browser/proxy caches serve stale
    # dashboards after a successful write from either application.
    out_headers.setdefault("cache-control", "no-store, no-cache, must-revalidate, max-age=0")
    response = Response(content=upstream.content, status_code=upstream.status_code, headers=out_headers)
    for cookie in upstream.headers.get_list("set-cookie"):
        response.headers.append("set-cookie", cookie)
    return response
