from fastapi import FastAPI, Request, Response

app = FastAPI()
BODY = b'{"id": 1, "name": "Laptop", "price": 950.0}'


@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
async def any_path(path: str, request: Request):
    return Response(content=BODY, media_type="application/json")
