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
