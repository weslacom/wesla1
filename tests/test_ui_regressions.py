from pathlib import Path

def test_public_page_features_are_present_and_product_loader_is_async():
    html = Path("app/static/index.html").read_text(encoding="utf-8")
    assert 'id="productSearch"' in html
    assert 'id="accountSettings"' in html
    assert 'id="accountActions"' in html
    assert 'async function loadProducts()' in html
    assert 'قرأت جميع بنود الاتفاقية' in html
    assert html.count('async function merchantProduct()') == 1
    assert "#tabs{position:fixed" in html

def test_admin_navigation_is_fixed_and_contains_required_sections():
    html = Path("app/static/control.html").read_text(encoding="utf-8")
    assert '.tabs{position:fixed!important' in html
    for label in ("العقود", "التفاوض", "الفسخ", "المنتجات", "الإعلانات"):
        assert label in html

def test_contract_document_uses_wesla_mark_and_compact_a4_layout():
    source = Path("app/main.py").read_text(encoding="utf-8")
    assert 'viewBox="0 0 520 195"' in source
    assert '@page{{size:A4 portrait;margin:5mm}}' in source
    assert 'أحكام التعامل والتسوية:' in source
    assert 'إقرار وموافقة الأطراف' in source
    assert 'والله شاهدٌ علينا، وهو خير الشاهدين' in source
    assert 'لا يُعد ختم وصلة البصري وحده شهادة تصديق أو توقيعًا رقميًا معتمدًا' in source


def test_admin_portal_supports_private_upstream_and_disables_dashboard_caching():
    source = Path("app/admin_portal.py").read_text(encoding="utf-8")
    assert 'parsed.hostname.endswith(".railway.internal")' in source
    assert 'out_headers.setdefault("cache-control", "no-store' in source

def test_public_and_admin_pages_refresh_read_only_views_without_overwriting_forms():
    public_html = Path("app/static/index.html").read_text(encoding="utf-8")
    admin_html = Path("app/static/control.html").read_text(encoding="utf-8")
    assert "refreshPublicContent" in public_html
    assert "Promise.allSettled(jobs)" in public_html
    assert "refreshActiveSection" in admin_html
    assert "content.querySelector('form, input, textarea, select')" in admin_html
    assert "lastActivity" in admin_html and "18000" in admin_html
    assert "lastActivity" in public_html and "18000" in public_html

def test_gitlab_pipeline_deploys_both_railway_services_after_tests():
    pipeline = Path(".gitlab-ci.yml").read_text(encoding="utf-8")
    assert "pytest -q" in pipeline
    assert "WESLA_WEB_SERVICE_ID" in pipeline
    assert "WESLA_ADMIN_SERVICE_ID" in pipeline
    assert pipeline.index('WESLA_WEB_SERVICE_ID') < pipeline.index('WESLA_ADMIN_SERVICE_ID')


def test_native_postgres_sse_sync_uses_sanitized_notifications():
    event_hub = Path("app/event_hub.py").read_text(encoding="utf-8")
    migration = Path("supabase/migrations/20261125120000_wesla_native_notify_events.sql").read_text(encoding="utf-8")
    main_source = Path("app/main.py").read_text(encoding="utf-8")
    admin_source = Path("app/admin_portal.py").read_text(encoding="utf-8")
    public_html = Path("app/static/index.html").read_text(encoding="utf-8")
    admin_html = Path("app/static/control.html").read_text(encoding="utf-8")
    assert 'LISTEN wesla_changes' in event_hub
    assert 'pg_notify' in migration
    assert 'json_build_object' in migration
    assert "'/api/public/events'" in main_source
    assert "'/api/admin/events'" in main_source
    assert 'text/event-stream' in admin_source
    assert 'new EventSource("/api/public/events")' in public_html
    assert "new EventSource('/api/admin/events')" in admin_html
    assert 'realtime.send' not in migration

