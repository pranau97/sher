from fastapi import FastAPI, Request, HTTPException
import hashlib
import hmac
import tomllib

app = FastAPI()

with open("secrets.toml", "rb") as f:
    WEBHOOK_SECRET = tomllib.load(f)["webhook"]["secret"]


def verify_signature(payload_body, secret_token: str, signature_header: str | None):
    if not signature_header:
        raise HTTPException(
            status_code=403, detail="x-hub-signature-256 header is missing!"
        )
    hash_object = hmac.new(
        secret_token.encode("utf-8"), msg=payload_body, digestmod=hashlib.sha256
    )
    expected_signature = "sha256=" + hash_object.hexdigest()
    if not hmac.compare_digest(expected_signature, signature_header):
        raise HTTPException(status_code=403, detail="Request signatures didn't match!")


@app.post("/webhook")
async def github_webhook(request: Request):
    signature_header = request.headers.get("X-Hub-Signature-256")

    payload_body = await request.body()
    print(type(payload_body))

    verify_signature(payload_body, WEBHOOK_SECRET, signature_header)

    payload = await request.json()

    event_header = request.headers.get("X-GitHub-Event")
    if not event_header:
        raise HTTPException(status_code=400, detail="X-GitHub-Event header is missing!")

    if event_header == "workflow_job":
        print(payload)

    return {"message": "Webhook received and verified!"}
