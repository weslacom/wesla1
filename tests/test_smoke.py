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
    assert client.get('/api/products').status_code==200
