from fastapi import FastAPI, Request, Header, HTTPException
from webhook_handler import handle_github_event
import os
import uvicorn

app = FastAPI()

@app.post("/webhook")
async def github_webhook(
    request: Request,
    x_github_event: str = Header(None),
    x_hub_signature_256: str = Header(None)
):
    payload = await request.body()
    headers = {
        "X-GitHub-Event": x_github_event,
        "X-Hub-Signature-256": x_hub_signature_256
    }
    
    try:
        await handle_github_event(payload, headers)
        return {"status": "received"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    uvicorn.run("main:app", host="localhost", port=8000, reload=True)
