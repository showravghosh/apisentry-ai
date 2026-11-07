import os
import time
from collections import defaultdict, deque
import httpx
from fastapi import FastAPI, Request, Response

BACKEND = os.getenv("RL_BACKEND", "http://127.0.0.1:8000")
RATE = float(os.getenv("RL_RATE", "10"))
BURST = float(os.getenv("RL_BURST", "20"))
LOGIN_LIMIT = int(os.getenv("RL_LOGIN_LIMIT", "5"))
LOGIN_WINDOW = float(os.getenv("RL_LOGIN_WINDOW", "60"))
app = FastAPI(title="Rate-limit baseline")
buckets = {}
logins = defaultdict(deque)
client = None


@app.on_event("startup")
async def startup():
    global client
    client = httpx.AsyncClient(timeout=30.0)


@app.post("/__ratelimit/reset")
def reset():
    buckets.clear()
    logins.clear()
    return {"reset": True}


def allow(ip, now):
    tokens, last = buckets.get(ip, (BURST, now))
    tokens = min(BURST, tokens + (now - last) * RATE)
    if tokens < 1:
        buckets[ip] = (tokens, now)
        return False
    buckets[ip] = (tokens - 1, now)
    return True


@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
async def proxy(path: str, request: Request):
    now = time.time()
    ip = request.headers.get("x-forwarded-for", request.client.host if request.client else "unknown").split(",")[0].strip()
    if not allow(ip, now):
        return Response(status_code=429, content=b'{"error":"rate limited"}', media_type="application/json")
    if request.url.path == "/login":
        q = logins[ip]
        while q and now - q[0] > LOGIN_WINDOW:
            q.popleft()
        if len(q) >= LOGIN_LIMIT:
            return Response(status_code=429, content=b'{"error":"login rate limited"}', media_type="application/json")
        q.append(now)
    body = await request.body()
    url = BACKEND + request.url.path + ("?" + request.url.query if request.url.query else "")
    headers = {k: v for k, v in request.headers.items() if k.lower() not in ("host", "content-length")}
    r = await client.request(request.method, url, content=body, headers=headers)
    return Response(content=r.content, status_code=r.status_code, media_type=r.headers.get("content-type"))
