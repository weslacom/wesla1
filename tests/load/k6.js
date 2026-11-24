import http from 'k6/http';
import { check, sleep } from 'k6';

const BASE_URL = (__ENV.BASE_URL || '').replace(/\/$/, '');
const STORE_ID = __ENV.STORE_ID || '';

if (!BASE_URL) {
  throw new Error('Set BASE_URL to a staging environment before running this test.');
}

export const options = {
  stages: [
    { duration: '30s', target: 10 },
    { duration: '60s', target: 25 },
    { duration: '60s', target: 50 },
    { duration: '60s', target: 100 },
    { duration: '30s', target: 0 },
  ],
  thresholds: {
    http_req_failed: ['rate<0.01'],
    http_req_duration: ['p(95)<1500'],
  },
};

export default function () {
  const health = http.get(`${BASE_URL}/health`);
  check(health, { 'health responds 200': (r) => r.status === 200 });

  const catalogue = http.get(`${BASE_URL}/api/products?limit=48`);
  check(catalogue, {
    'catalogue responds 200': (r) => r.status === 200,
    'catalogue returns JSON': (r) => (r.headers['Content-Type'] || '').includes('application/json'),
  });

  if (STORE_ID) {
    const store = http.get(`${BASE_URL}/api/public/stores/${STORE_ID}`);
    check(store, { 'public store responds 200': (r) => r.status === 200 });
  }

  sleep(1);
}
