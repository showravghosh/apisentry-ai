import os
import random
import httpx
from fastapi import FastAPI, Request, Response

app = FastAPI()
CFG = {"target": os.getenv("RELAY_TARGET", "http://127.0.0.1:9000"), "mode": "fixed", "ip": "198.18.0.10", "label": "none"}
STATS = {}
RNG = random.Random(int(os.getenv("RELAY_SEED", "9401")))
client = None


@app.on_event("startup")
async def startup():
    global client
    client = httpx.AsyncClient(timeout=30.0, limits=httpx.Limits(max_connections=100, max_keepalive_connections=50))


@app.post("/__relay/config")
async def config(request: Request):
    CFG.update(await request.json())
    return CFG


@app.get("/__relay/stats")
def stats():
    return STATS


@app.post("/__relay/clear")
def clear():
    STATS.clear()
    return {"cleared": True}


def source_ip():
    if CFG["mode"] == "rotate":
        return "198.%d.%d.%d" % (RNG.randint(19, 99), RNG.randint(0, 255), RNG.randint(1, 254))
    return CFG["ip"]


@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"])
async def relay(path: str, request: Request):
    body = await request.body()
    headers = {k: v for k, v in request.headers.items() if k.lower() not in ("host", "content-length", "x-forwarded-for")}
    headers["X-Forwarded-For"] = source_ip()
    url = CFG["target"] + request.url.path + ("?" + request.url.query if request.url.query else "")
    st = STATS.setdefault(CFG["label"], {"n": 0, "n403": 0, "n429": 0, "n_other_4xx": 0, "n_5xx": 0, "n_err": 0})
    st["n"] += 1
    try:
        r = await client.request(request.method, url, content=body, headers=headers)
    except Exception:
        st["n_err"] += 1
        return Response(status_code=502)
    if r.status_code == 403:
        st["n403"] += 1
    elif r.status_code == 429:
        st["n429"] += 1
    elif 400 <= r.status_code < 500:
        st["n_other_4xx"] += 1
    elif r.status_code >= 500:
        st["n_5xx"] += 1
    out = {k: v for k, v in r.headers.items() if k.lower() not in ("content-length", "content-encoding", "transfer-encoding", "connection")}
    return Response(content=r.content, status_code=r.status_code, headers=out)
