# Wesla load test

This k6 script exercises only public, read-only endpoints. It does not create accounts, orders, payouts, or other data.

Run it against a **staging** deployment first:

```bash
k6 run -e BASE_URL=https://YOUR-STAGING-DOMAIN -e STORE_ID=1 tests/load/k6.js
```

The staged ramp reaches 100 virtual users. Review p95 latency, error rate, CPU, memory, and database connections together. Do not run this script against production without an approved test window.
