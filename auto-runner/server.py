from .auth import authenticate_github_app, generate_jwt
from .utils import logger, environment, gh_header_for_token
from .vagrant import start_vm, destroy_vm
from .rules import (
    check_commit_hash,
    check_workflow_permissions,
    check_secrets,
    set_workflow_permissions,
)

from fastapi import FastAPI, Request, HTTPException, BackgroundTasks
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles

from pathlib import Path

import hashlib
import hmac
import requests
import urllib.parse
import base64
import yaml


app = FastAPI()

BASE_PATH = Path(__file__).resolve().parent
TEMPLATES = Jinja2Templates(directory=f"{BASE_PATH}/templates")
app.mount("/static", StaticFiles(directory=f"{BASE_PATH}/static"), name="static")


def construct_yaml_str(self, node):
    return self.construct_scalar(node)


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

        if not token:
            logger.error("Failed to authenticate app")
            raise HTTPException(status_code=502, detail="Failed to authenticate app")

        headers = gh_header_for_token(token)
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
    headers = gh_header_for_token(jwt)

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

    headers = gh_header_for_token(token)
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


def get_workflow(
    installation_id: int, owner: str, repo: str, workflow_id: int
) -> tuple[dict, str]:

    token = authenticate_github_app(installation_id)
    if not token:
        logger.error("Failed to authenticate app")
        raise ValueError("Failed to authenticate app")

    headers = gh_header_for_token(token)

    workflow_url = (
        f"https://api.github.com/repos/{owner}/{repo}/actions/workflows/{workflow_id}"
    )
    response = requests.get(workflow_url, headers=headers)
    response.raise_for_status()
    workflow = response.json()

    workflow_path = workflow["path"]
    logger.debug(f"Workflow path: {workflow_path}")
    repos_url = f"https://api.github.com/repos/{owner}/{repo}/contents/{workflow_path}"
    headers = gh_header_for_token(token, accept="application/vnd.github.object+json")
    response = requests.get(repos_url, headers=headers)
    response.raise_for_status()
    workflow_contents = response.json()

    contents = base64.b64decode(workflow_contents["content"]).decode("utf-8")
    logger.debug(f"Workflow contents: {contents}")

    return (workflow, contents)


def scan_workflow(
    contents: str,
    installation_id: int,
    owner: str,
    repo: str,
    workflow_id: int,
    fix: str | None = None,
) -> dict:
    yaml.add_constructor(
        "tag:yaml.org,2002:bool", construct_yaml_str, Loader=yaml.SafeLoader
    )
    workflow = yaml.load(contents, Loader=yaml.SafeLoader)

    if fix and fix == "commit":
        commit_results = check_commit_hash(
            workflow, installation_id, owner, repo, workflow_id, fix=True
        )
    else:
        commit_results = check_commit_hash(
            workflow, installation_id, owner, repo, workflow_id
        )

    if fix and fix == "permissions":
        permissions_results = set_workflow_permissions(installation_id, owner, repo)
    else:
        permissions_results = check_workflow_permissions(installation_id, owner, repo)

    secrets_results = check_secrets(workflow)

    commit_flag = False
    for result in commit_results:
        if result["sev"] in ["warning", "danger"]:
            commit_flag = True
            break
    commit_fix_url = None
    if commit_flag:
        commit_fix_url = f"/scan/{repo}/{owner}?installation_id={installation_id}&workflow_id={workflow_id}&fix=commit"

    permissions_flag = False
    for result in permissions_results:
        if result["sev"] in ["warning", "danger"]:
            permissions_flag = True
            break
    permissions_fix_url = None
    if permissions_flag:
        permissions_fix_url = f"/scan/{repo}/{owner}?installation_id={installation_id}&workflow_id={workflow_id}&fix=permissions"

    results = {
        "commit": {
            "heading": "Rule: Use commit hashes instead of refs in Actions",
            "results": commit_results,
            "fix": commit_fix_url,
        },
        "permissions": {
            "heading": "Rule: Check workflow permissions",
            "results": permissions_results,
            "fix": permissions_fix_url,
        },
        "secrets": {
            "heading": "Rule: Check for secrets being inherited by external Actions",
            "results": secrets_results,
            "fix": None,
        },
    }
    return results


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
            if not token:
                logger.error("Failed to authenticate app")
                return TEMPLATES.TemplateResponse(
                    name="index.html.jinja",
                    request=request,
                    context={"error": "Failed to authenticate app"},
                )
            headers = gh_header_for_token(token)
            workflows_url = f"https://api.github.com/repos/{details['owner']}/{details['repo']}/actions/workflows"
            response = requests.get(workflows_url, headers=headers)
            response.raise_for_status()
            workflows = response.json()["workflows"]

            workflow_list = []
            for workflow in workflows:
                scan_url = f"/scan/{details['repo']}/{details['owner']}?"
                params = {
                    "installation_id": details["installation_id"],
                    "workflow_id": workflow["id"],
                }
                scan_url += urllib.parse.urlencode(params)
                workflow_list.append((workflow["name"], workflow["path"], scan_url))

            context = {
                "repository": details["repo"],
                "workflows": workflow_list,
            }
            return TEMPLATES.TemplateResponse(
                name="workflows.html.jinja", request=request, context=context
            )

    return TEMPLATES.TemplateResponse(name="index.html.jinja", request=request)


@app.get("/scan/{repo}/{owner}")
async def scan(
    request: Request,
    installation_id: int,
    workflow_id: int,
    repo: str,
    owner: str,
    fix: str | None = None,
):
    try:
        workflow, contents = get_workflow(installation_id, owner, repo, workflow_id)
        workflow_path = workflow["path"]

        results = scan_workflow(
            contents, installation_id, owner, repo, workflow_id, fix
        )

    except Exception as e:
        logger.error("Exception", exc_info=e)
        return TEMPLATES.TemplateResponse(
            name="scan.html.jinja", request=request, context={"error": e}
        )
    context = {"repository": repo, "workflow": workflow_path, "results": results}
    return TEMPLATES.TemplateResponse(
        name="scan.html.jinja", request=request, context=context
    )
