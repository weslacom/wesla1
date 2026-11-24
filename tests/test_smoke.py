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

    # Public contact settings, merchant store page, and product share URL.
    contact=merchant_client.patch('/api/me/contact',json={
        'contact_phone':'01012345678','contact_whatsapp':'201012345678','contact_public':True
    })
    assert contact.status_code==200
    merchant_product=merchant_client.post('/api/merchant/products',json={
        'title':'منتج التاجر','description':'منتج لاختبار المتجر العام',
        'price':250,'stock':5,'affiliate_rate':10,'platform_rate':5
    })
    assert merchant_product.status_code==200, merchant_product.text
    product_id=merchant_product.json()['id']
    store=client.get(f'/api/public/stores/{merchant_id}')
    assert store.status_code==200 and store.json()['contact_phone']=='01012345678'
    assert any(p['id']==product_id for p in store.json()['products'])
    assert client.get(f'/p/{product_id}',follow_redirects=False).status_code==302

    # Merchant can request a platform contract; admin approval creates a draft.
    requested=merchant_client.post('/api/contracts/request',json={
        'title':'طلب اتفاقية تاجر','details':'أرغب في اتفاقية تاجر مع منصة وصلة وفق الشروط المقترحة.',
        'desired_commission':12
    })
    assert requested.status_code==200, requested.text
    requests=client.get('/api/admin/contract-requests')
    assert requests.status_code==200
    request_id=requested.json()['request_id']
    approved_request=client.post(f'/api/admin/contract-requests/{request_id}/decision',json={
        'decision':'approve','admin_note':'تمت الموافقة المبدئية'
    })
    assert approved_request.status_code==200, approved_request.text
    new_contract_id=approved_request.json()['contract_id']
    activated=client.post(f'/api/admin/contracts/{new_contract_id}/activate')
    assert activated.status_code==200

    # A party can negotiate; acceptance creates a new draft version without changing the old agreement.
    proposal=merchant_client.post(f'/api/contracts/{new_contract_id}/negotiations',json={
        'proposal_text':'تضاف مهلة معالجة الشكوى خلال خمسة أيام عمل.',
        'reason':'توضيح زمن الاستجابة لخدمة العملاء.'
    })
    assert proposal.status_code==200, proposal.text
    negotiation_id=proposal.json()['negotiation_id']
    accepted_proposal=client.post(f'/api/contract-negotiations/{negotiation_id}/respond',json={
        'decision':'accept','response_text':'مقبول'
    })
    assert accepted_proposal.status_code==200, accepted_proposal.text
    assert accepted_proposal.json()['new_contract_id']
    assert merchant_client.get('/api/contracts/negotiations/my').status_code==200
    assert merchant_client.get('/api/notifications/my').status_code==200

    # Affiliate removal is personal to that marketer; it does not delete the merchant's product.
    affiliate_client=TestClient(app)
    affiliate_registration=affiliate_client.post('/api/register',json={
        'name':'مسوق الاختبار','email':'affiliate@wesla.test','password':'AffiliatePass123!'
    })
    assert affiliate_registration.status_code==200
    affiliate_id=affiliate_registration.json()['user']['id']
    db=SessionLocal()
    try:
        db.get(User,affiliate_id).role='affiliate'
        db.commit()
    finally:
        db.close()
    assert affiliate_client.post('/api/login',json={
        'email':'affiliate@wesla.test','password':'AffiliatePass123!'
    }).status_code==200
    available=affiliate_client.get('/api/affiliate/products')
    assert any(p['id']==product_id for p in available.json())
    hidden=affiliate_client.delete(f'/api/affiliate/products/{product_id}')
    assert hidden.status_code==200
    assert all(p['id']!=product_id for p in affiliate_client.get('/api/affiliate/products').json())
    assert any(p['id']==product_id for p in client.get('/api/products').json())

    # Merchant soft-delete preserves the row and admin can restore it.
    deleted=merchant_client.delete(f'/api/merchant/products/{product_id}')
    assert deleted.status_code==200, deleted.text
    assert all(p['id']!=product_id for p in client.get('/api/products').json())
    admin_restore=client.post(f'/api/admin/products/{product_id}/restore')
    assert admin_restore.status_code==200, admin_restore.text
    assert any(p['id']==product_id for p in client.get('/api/products').json())

