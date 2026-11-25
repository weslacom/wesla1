from pathlib import Path

def test_public_page_features_are_present_and_product_loader_is_async():
    html = Path("app/static/index.html").read_text(encoding="utf-8")
    assert 'id="productSearch"' in html
    assert 'id="accountSettings"' in html
    assert 'id="accountActions"' in html
    assert 'async function loadProducts()' in html
    assert "async function merchantProduct()" in html
    assert "function merchantProduct(){" not in html
    assert "#tabs{position:fixed" in html

def test_admin_navigation_is_fixed_and_contains_required_sections():
    html = Path("app/static/control.html").read_text(encoding="utf-8")
    assert '.tabs{position:fixed!important' in html
    for label in ("العقود", "التفاوض", "الفسخ", "المنتجات", "الإعلانات"):
        assert label in html
