from .auth import authenticate_github_app
from .utils import logger, environment
from .vagrant import start_vm

from fastapi import FastAPI, Request, HTTPException, BackgroundTasks

import hashlib
import hmac
import requests

app = FastAPI()


def verify_signature(payload_body: bytes, signature_header: str | None) -> None:
    if not signature_header:
        raise HTTPException(
            status_code=403, detail="x-hub-signature-256 header is missing!"
        )
    secret_token = environment.get("WEBHOOK_SECRET")
    if not secret_token:
        raise HTTPException(status_code=502, detail="Secret token not found!")

    hash_object = hmac.new(
        secret_token.encode("utf-8"), msg=payload_body, digestmod=hashlib.sha256
    )
    expected_signature = "sha256=" + hash_object.hexdigest()
    if not hmac.compare_digest(expected_signature, signature_header):
        raise HTTPException(status_code=403, detail="Request signatures didn't match!")


def start_runner(payload: dict) -> None:
    labels = payload["workflow_job"]["labels"]
    if "auto-runner" in labels:
        logger.info("Auto-runner label detected.")
        installation_id = payload["installation"]["id"]
        owner = payload["repository"]["owner"]["login"]
        repository = payload["repository"]["name"]
        url = payload["repository"]["html_url"]
        workflow_id = payload["workflow_job"]["id"]
        token = authenticate_github_app(installation_id)

        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-Github-Api-Version": "2022-11-28",
        }
        registration_token_url = f"https://api.github.com/repos/{owner}/{repository}/actions/runners/registration-token"
        response = requests.post(registration_token_url, headers=headers)
        response.raise_for_status()
        registration_token = response.json()["token"]
        logger.debug(f"Registration token generated, {registration_token}")

        start_vm(url, registration_token, labels, workflow_id)
    else:
        logger.info("auto-runner label not detected.")


@app.post("/webhook")
async def github_webhook(
    request: Request, background_tasks: BackgroundTasks
) -> dict[str, str]:

    payload_body = await request.body()

    signature_header = request.headers.get("X-Hub-Signature-256")
    verify_signature(payload_body, signature_header)

    event_header = request.headers.get("X-GitHub-Event")
    if not event_header:
        raise HTTPException(status_code=400, detail="X-GitHub-Event header is missing!")

    payload = await request.json()
    if event_header == "workflow_job" and payload["action"] == "queued":
        background_tasks.add_task(start_runner, payload)

    return {"message": "Webhook received and verified!"}
