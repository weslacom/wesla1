"""Basic integration smoke test; run with: pytest -q"""
import os, tempfile
from fastapi.testclient import TestClient

def test_health_and_core_workflow(monkeypatch, tmp_path):
    dbfile=tmp_path/'test.db'
    monkeypatch.setenv('DATABASE_URL',f'sqlite:///{dbfile}')
    monkeypatch.setenv('ADMIN_EMAIL','root@wesla.test')
    monkeypatch.setenv('ADMIN_PASSWORD','StrongPassword123!')
    # Import after setting env; this test is intended to run in a fresh pytest process.
    from app.main import app
    client=TestClient(app)
    assert client.get('/health').json()['ok'] is True
    assert client.post('/api/login',json={'email':'root@wesla.test','password':'StrongPassword123!'}).status_code==200
    assert client.get('/api/admin/overview').status_code==200
    product=client.post('/api/merchant/products',json={'title':'اختبار','description':'منتج','price':125,'stock':4,'affiliate_rate':12,'platform_rate':5})
    assert product.status_code==200
    second_product=client.post('/api/merchant/products',json={'title':'اختبار ثانٍ','description':'منتج آخر','price':95,'stock':3,'affiliate_rate':10,'platform_rate':5})
    assert second_product.status_code==200
    assert client.get('/api/products').status_code==200
    first_page=client.get('/api/products?limit=1&offset=0')
    second_page=client.get('/api/products?limit=1&offset=1')
    assert first_page.status_code==200 and len(first_page.json())==1
    assert second_page.status_code==200 and len(second_page.json())==1
    assert first_page.json()[0]['id'] != second_page.json()[0]['id']
    assert 'affiliate_rate' not in first_page.json()[0]

    # Exercise the JSONB-backed contract event and termination evidence paths.
    merchant_client=TestClient(app)
    registration=merchant_client.post('/api/register',json={
        'name':'تاجر الاختبار','email':'merchant@wesla.test','password':'MerchantPass123!'
    })
    assert registration.status_code==200
    merchant_id=registration.json()['user']['id']

    from app.database import SessionLocal
    from app.models import User
    db=SessionLocal()
    try:
        merchant=db.get(User,merchant_id)
        merchant.role='merchant'
        db.commit()
    finally:
        db.close()

    created=client.post('/api/admin/contracts',json={
        'contract_type':'platform_merchant',
        'title':'اتفاقية اختبار JSONB',
        'body':'نص اتفاقية اختبار يتجاوز الحد الأدنى المطلوب.',
        'merchant_id':merchant_id,
        'commission_scope':'contract',
        'legal_entity_name':'طرف اختبار'
    })
    assert created.status_code==200, created.text
    contract=created.json()
    assert contract['events'][0]['details']['number']==contract['contract_number']
    assert client.get('/api/admin/contracts').status_code==200
    assert client.post(f"/api/admin/contracts/{contract['id']}/activate").status_code==200

    login=merchant_client.post('/api/login',json={
        'email':'merchant@wesla.test','password':'MerchantPass123!'
    })
    assert login.status_code==200
    accepted=merchant_client.post(f"/api/contracts/{contract['id']}/accept",json={
        'full_name':'تاجر الاختبار','accepted':True
    })
    assert accepted.status_code==200
    terminated=merchant_client.post(f"/api/contracts/{contract['id']}/termination",json={
        'reason':'طلب اختبار لمسار فسخ الاتفاقية.',
        'evidence_paths':['evidence/test-document.pdf']
    })
    assert terminated.status_code==200
    assert client.get('/api/admin/termination-requests').status_code==200
