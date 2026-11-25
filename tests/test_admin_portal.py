from types import SimpleNamespace
import pytest
from fastapi import HTTPException
from app.admin_portal import ADMIN_REQUIRED_ROUTES, app, upstream_base

def req(host):
    return SimpleNamespace(url=SimpleNamespace(netloc=host))

def test_default_upstream(monkeypatch):
    monkeypatch.delenv("WESLA_API_BASE", raising=False)
    monkeypatch.delenv("ADMIN_PORTAL_URL", raising=False)
    assert upstream_base(req("wesla-admin-production.up.railway.app")) == "https://wesla-web-production.up.railway.app"

def test_normalizes_api_suffix(monkeypatch):
    monkeypatch.setenv("WESLA_API_BASE", "https://api.example.com/api/")
    monkeypatch.setenv("ADMIN_PORTAL_URL", "https://admin.example.com")
    assert upstream_base(req("admin.example.com")) == "https://api.example.com"

def test_private_railway_upstream(monkeypatch):
    monkeypatch.setenv("WESLA_API_BASE", "http://wesla-web.railway.internal")
    monkeypatch.setenv("ADMIN_PORTAL_URL", "https://wesla-admin-production.up.railway.app")
    assert upstream_base(req("wesla-admin-production.up.railway.app")) == "http://wesla-web.railway.internal"

@pytest.mark.parametrize("value", ["http://example.com", "https://user:pass@example.com", "https://example.com/path", "https://example.com?token=x", "file:///etc/passwd"])
def test_rejects_unsafe_upstream(monkeypatch, value):
    monkeypatch.setenv("WESLA_API_BASE", value)
    monkeypatch.setenv("ADMIN_PORTAL_URL", "https://wesla-admin-production.up.railway.app")
    with pytest.raises(HTTPException) as exc:
        upstream_base(req("wesla-admin-production.up.railway.app"))
    assert exc.value.status_code == 503

def test_diagnostics_and_proxy_routes_exist():
    paths = {route.path for route in app.routes}
    assert "/api/_portal/diagnostics" in paths
    assert "/api/{path:path}" in paths
    assert len(ADMIN_REQUIRED_ROUTES) == 6
