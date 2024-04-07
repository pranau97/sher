from .utils import logger, gh_header_for_token
from .auth import authenticate_github_app

import requests


def is_sha1(s):
    if len(s) == 40 and all(c in "0123456789abcdefABCDEF" for c in s):
        return True
    return False


def check_workflow_permissions(
    installation_id: int, owner: str, repo: str, fix=False
) -> list:
    token = authenticate_github_app(installation_id)
    if not token:
        logger.error("Failed to authenticate app")
        raise ValueError("Failed to authenticate app")

    headers = gh_header_for_token(token)
    permissions_url = (
        f"https://api.github.com/repos/{owner}/{repo}/actions/permissions/workflow"
    )
    response = requests.get(permissions_url, headers=headers)
    response.raise_for_status()
    permissions = response.json()
    logger.debug(f"Permissions: {permissions}")

    default_workflow_permissions = permissions["default_workflow_permissions"]
    can_approve_pull_request_reviews = permissions["can_approve_pull_request_reviews"]

    results = []
    if default_workflow_permissions == "write":
        logger.info("Default workflow permissions are write")
        results.append(
            {
                "line": "Settings",
                "rec": "Default workflow permissions are write. Consider changing to read.",
                "sev": "danger",
            }
        )
    else:
        logger.info("Default workflow permissions are read")
        results.append(
            {
                "line": "Settings",
                "rec": "Default workflow permissions are read.",
                "sev": "success",
            }
        )

    if can_approve_pull_request_reviews:
        logger.info("Can approve pull request reviews")
        results.append(
            {
                "line": "Settings",
                "rec": "Actions can approve pull request reviews. Consider disabling.",
                "sev": "danger",
            }
        )
    else:
        logger.info("Cannot approve pull request reviews")
        results.append(
            {
                "line": "Settings",
                "rec": "Actions cannot approve pull request reviews.",
                "sev": "success",
            }
        )

    return results


def check_commit_hash(workflow: dict, fix=False) -> list:
    jobs = workflow["jobs"]
    results = []
    for job, contents in jobs.items():
        logger.debug(f"Parsing job: {job}")
        if "steps" in contents:
            steps = contents["steps"]
            for step in steps:
                if "uses" in step:
                    uses = step["uses"]
                    logger.debug(f"Uses: {uses}")
                    if "@" not in uses:
                        continue
                    tag = uses.split("@")[-1]
                    if not is_sha1(tag):
                        logger.info(f"Found ref instead of hash: {tag}")
                        results.append(
                            {
                                "line": f"uses: {uses}",
                                "rec": f"It is best to use a commit hash instead of a ref. Found ref: {tag}",
                                "sev": "warning",
                            }
                        )
                    else:
                        logger.info(f"Found hash: {tag}")
                        results.append(
                            {
                                "line": f"uses: {uses}",
                                "rec": f"Commit hash found: {tag}",
                                "sev": "success",
                            }
                        )

    if not results:
        logger.info("No external actions found in workflow.")
        results.append(
            {
                "line": "No external actions found",
                "rec": "No external actions found in workflow",
                "sev": "info",
            }
        )

    return results


def check_secrets(workflow: dict) -> list:
    jobs = workflow["jobs"]
    results = []
    for job, contents in jobs.items():
        logger.debug(f"Parsing job: {job}")
        if "secrets" in contents:
            secrets = contents["secrets"]
            if type(secrets) is str and secrets == "inherit":
                logger.info("Secrets inherit")
                results.append(
                    {
                        "line": "Secrets",
                        "rec": "Secrets inherit. Consider setting explicit secrets.",
                        "sev": "warning",
                    }
                )
            elif type(secrets) is dict:
                for secret, _ in secrets.items():
                    logger.info(f"Found secret: {secret}")
                    results.append(
                        {
                            "line": f"secret: {secret}",
                            "rec": "Secret is being passed to another workflow.",
                            "sev": "info",
                        }
                    )
    if not results:
        logger.info("No secrets found in workflow.")
        results.append(
            {
                "line": "No secrets found",
                "rec": "No secrets being passed to other workflows.",
                "sev": "info",
            }
        )
    return results
