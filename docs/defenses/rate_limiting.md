# Rate Limiting & Sensitive Flows Protection

Unrestricted Access to Sensitive Business Flows (API6:2023) highlights APIs exposed to automated abuse vectors over business process operations: checkout workflows, ticket purchasing bots, scraping, and OTP spraying.

## Defensive Strategy
Deploy granular rate limits that explicitly throttle distinct classes of API endpoints instead of generalized global IP quotas. Implement continuous validation steps across high-value flows (e.g., re-evaluating tokens on checkout, CAPTCHA integrations, or Proof-of-Work headers).

---

### Global API Gateway Definitions (e.g. Kong/Nginx/Envoy)
Apply differing tiers.
```nginx
# Map limits strictly according to the perceived endpoints sensitivity
limit_req_zone $binary_remote_addr zone=api_general:10m rate=10r/s;
limit_req_zone $binary_remote_addr zone=api_checkout:10m rate=2r/s;
limit_req_zone $binary_remote_addr zone=api_auth:10m rate=1r/s;
```

---

### Python (FastAPI + SlowAPI)

```python
from fastapi import FastAPI, Depends, Request
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

# Define limits using standard bucket algorithms over the remote IP
limiter = Limiter(key_func=get_remote_address)
app = FastAPI()
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

@app.post("/users/login")
@limiter.limit("5/minute")
async def login(request: Request):
    """
    Prevents automated brute-forcing or credential stuffing.
    """
    return {"status": "Processing auth."}

@app.get("/search")
@limiter.limit("100/minute")
async def search(request: Request):
    """
    Permissive limits for public interaction but caps severe enumeration loops.
    """
    return {"results": []}
```
