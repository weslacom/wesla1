import json
import os
from pathlib import Path
from urllib.parse import urlsplit

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import HTMLResponse, Response

app = FastAPI(title="Wesla Admin Portal")
app.add_middleware(GZipMiddleware, minimum_size=1000, compresslevel=5)

DEFAULT_WESLA_API_BASE = "https://wesla-web-production.up.railway.app"
DEFAULT_ADMIN_PORTAL_URL = "https://wesla-admin-production.up.railway.app"
ADMIN_REQUIRED_ROUTES = ["/api/admin/password-login","/api/admin/overview","/api/admin/contracts","/api/admin/contract-requests","/api/admin/negotiations","/api/admin/termination-requests","/api/admin/accounts","/api/admin/visitors","/api/admin/pages","/api/admin/referrals","/api/admin/rewards/offers","/api/advanced/rewards/offers","/api/public/merchants","/api/public/pages"]


def upstream_base(request: Request | None = None) -> str:
    """Resolve the authoritative API host and reject recursive or unsafe URLs."""
    value = os.getenv("WESLA_API_BASE", "").strip().rstrip("/") or DEFAULT_WESLA_API_BASE
    admin_url = os.getenv("ADMIN_PORTAL_URL", DEFAULT_ADMIN_PORTAL_URL).strip().rstrip("/")
    request_host = request.url.netloc.lower() if request is not None else ""
    value_host = urlsplit(value).netloc.lower()
    admin_host = urlsplit(admin_url).netloc.lower()
    if (request_host and value_host == request_host) or (admin_host and value_host == admin_host):
        value = DEFAULT_WESLA_API_BASE
    if value.endswith("/api"):
        value = value[:-4]
    parsed = urlsplit(value)
    private_railway = parsed.scheme == "http" and bool(parsed.hostname) and parsed.hostname.endswith(".railway.internal")
    public_https = parsed.scheme == "https" and bool(parsed.hostname)
    if not (private_railway or public_https) or parsed.username or parsed.password or parsed.path not in ("", "/") or parsed.query or parsed.fragment:
        raise HTTPException(status_code=503, detail="إعداد رابط خادم وصلة الأساسي غير صحيح. استخدم HTTPS أو عنوان Railway داخلي.")
    return value


async def probe_upstream(request: Request) -> dict:
    base = upstream_base(request)
    result = {"ok": False, "api_reachable": False, "database_ready": False,
              "api_status": None, "database_status": "unknown", "admin_routes": {}}
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(8.0, connect=4.0), follow_redirects=False) as client:
            health = await client.get(base + "/health")
            result["api_status"] = health.status_code
            result["api_reachable"] = health.status_code < 500
            try:
                health_data = health.json()
            except ValueError:
                health_data = {}
            result["database_status"] = health_data.get("database", "unknown")
            result["database_ready"] = health.status_code == 200 and result["database_status"] == "ok"
            schema = await client.get(base + "/openapi.json")
            if schema.status_code == 200:
                paths = schema.json().get("paths", {})
                result["admin_routes"] = {route: route in paths for route in ADMIN_REQUIRED_ROUTES}
        result["ok"] = result["database_ready"] and all(result["admin_routes"].get(route, False) for route in ADMIN_REQUIRED_ROUTES)
        return result
    except (httpx.HTTPError, ValueError):
        return result


@app.get("/")
def admin_home():
    html = Path("app/static/control.html").read_text(encoding="utf-8")
    html = html.replace("<script>", f"<script>window.WESLA_API_BASE='';window.WESLA_PUBLIC_URL={json.dumps(os.getenv('WESLA_PUBLIC_URL', '').rstrip('/'))};", 1)
    return HTMLResponse(html, headers={"Cache-Control": "no-store, no-cache, must-revalidate, max-age=0", "Pragma": "no-cache"})


@app.get("/health")
async def health(request: Request):
    upstream = await probe_upstream(request)
    body = {"ok": upstream["ok"], "service": "wesla-admin-portal",
            "api_reachable": upstream["api_reachable"], "api_status": upstream["api_status"],
            "database_ready": upstream["database_ready"],
            "admin_routes_ready": len(upstream["admin_routes"]) == len(ADMIN_REQUIRED_ROUTES) and all(upstream["admin_routes"].values())}
    return Response(content=json.dumps(body, ensure_ascii=False), media_type="application/json",
                    status_code=200 if body["ok"] else 503, headers={"Cache-Control": "no-store"})


@app.get("/api/_portal/diagnostics")
async def portal_diagnostics(request: Request):
    result = await probe_upstream(request)
    return Response(content=json.dumps(result, ensure_ascii=False), media_type="application/json",
                    status_code=200, headers={"Cache-Control": "no-store"})


@app.api_route("/api/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"])
async def proxy_api(path: str, request: Request):
    target = upstream_base(request) + "/api/" + path
    headers = {}
    for name in ("accept", "content-type", "cookie", "authorization", "user-agent", "x-forwarded-for", "x-real-ip", "origin", "referer"):
        value = request.headers.get(name)
        if value:
            headers[name] = value
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(45.0, connect=8.0), follow_redirects=False) as client:
            upstream = await client.request(request.method, target, params=request.query_params,
                                            content=await request.body(), headers=headers)
    except httpx.TimeoutException:
        raise HTTPException(status_code=504, detail="انتهت مهلة الاتصال بخادم وصلة الرئيسي.")
    except httpx.HTTPError:
        raise HTTPException(status_code=502, detail="تعذر الاتصال بخادم وصلة الرئيسي.")
    response_headers = {name: upstream.headers[name] for name in ("content-type", "content-disposition", "location") if name in upstream.headers}
    response_headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response = Response(content=upstream.content, status_code=upstream.status_code, headers=response_headers)
    for cookie in upstream.headers.get_list("set-cookie"):
        response.headers.append("set-cookie", cookie)
    return response
