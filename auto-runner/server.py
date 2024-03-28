from .auth import authenticate_github_app, generate_jwt
from .utils import logger, environment
from .vagrant import start_vm, destroy_vm

from fastapi import FastAPI, Request, HTTPException, BackgroundTasks
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles

from pathlib import Path

import hashlib
import hmac
import requests


app = FastAPI()

BASE_PATH = Path(__file__).resolve().parent
TEMPLATES = Jinja2Templates(directory=f"{BASE_PATH}/templates")
app.mount("/static", StaticFiles(directory=f"{BASE_PATH}/static"), name="static")


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
        logger.info("auto-runner label detected.")
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


def end_runner(payload: dict) -> None:
    workflow_id = payload["workflow_job"]["id"]
    labels = payload["workflow_job"]["labels"]

    if "auto-runner" in labels:
        logger.info("auto-runner label detected.")
        destroy_vm(workflow_id)
    else:
        logger.info("auto-runner label not detected.")


def get_repo_details(search: str) -> dict:
    jwt = generate_jwt()
    headers = {
        "Authorization": f"Bearer {jwt}",
        "Accept": "application/vnd.github+json",
        "X-Github-Api-Version": "2022-11-28",
    }

    installations_url = "https://api.github.com/app/installations"
    response = requests.get(installations_url, headers=headers)
    response.raise_for_status()
    installations = response.json()
    logger.debug(f"Installations: {installations}")

    search_terms = search.lower().strip().split("/")
    if len(search_terms) != 2:
        raise ValueError("Could not determine repo owner")

    owner, repo = search_terms
    installation_id = None

    for installation in installations:
        if installation["account"]["login"].lower() == owner:
            installation_id = installation["id"]
            break
    else:
        raise ValueError("Repo owner has not installed the app")

    token = authenticate_github_app(installation_id)
    if not token:
        raise ValueError("Failed to authenticate app")

    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-Github-Api-Version": "2022-11-28",
    }
    repos_url = "https://api.github.com/installation/repositories"
    response = requests.get(repos_url, headers=headers, params={"per_page": 100})
    response.raise_for_status()
    repos = response.json()["repositories"]
    logger.debug(f"Number of repos: {len(repos)}")

    for repo in repos:
        if repo["full_name"].lower() == search:
            logger.info(f"Found repo: {repo['full_name']}")
            return {
                "repo": repo["name"],
                "owner": repo["owner"]["login"],
                "installation_id": installation_id,
            }

    raise ValueError("Not found")


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
    elif event_header == "workflow_job" and payload["action"] == "completed":
        background_tasks.add_task(end_runner, payload)

    return {"message": "Webhook received and verified!"}


@app.get("/")
async def index(request: Request, search: str | None = None):
    if search:
        logger.info(f"Searching for {search}")
        try:
            details = get_repo_details(search)
        except ValueError as e:
            logger.error(e)
            return TEMPLATES.TemplateResponse(
                name="index.html.jinja", request=request, context={"error": e}
            )
        else:
            token = authenticate_github_app(details["installation_id"])
            headers = {
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github+json",
                "X-Github-Api-Version": "2022-11-28",
            }
            workflows_url = f"https://api.github.com/repos/{details['owner']}/{details['repo']}/actions/workflows"
            response = requests.get(workflows_url, headers=headers)
            response.raise_for_status()
            workflows = response.json()["workflows"]

            workflow_list = []
            for workflow in workflows:
                workflow_list.append((workflow["name"], workflow["path"]))

            context = {
                "repository": details["repo"],
                "workflows": workflow_list,
            }
            return TEMPLATES.TemplateResponse(
                name="workflows.html.jinja", request=request, context=context
            )

    return TEMPLATES.TemplateResponse(name="index.html.jinja", request=request)
