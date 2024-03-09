from .utils import logger, environment

from cryptography.hazmat.primitives.serialization import load_pem_private_key

import jwt
import requests
import time


def generate_jwt() -> str:
    private_key = load_pem_private_key(
        open(environment.get("PRIVATE_KEY_FILE")).read().encode(), password=None
    )
    app_id = environment.get("APP_ID")
    if not app_id:
        raise ValueError("APP_ID not found in environment variables")

    payload = {
        "iat": int(time.time()),  # Issued at time
        "exp": int(time.time()) + 600,  # JWT expiration time (10 minutes maximum)
        "iss": app_id,  # GitHub App's identifier
    }
    encoded_jwt = jwt.encode(payload, private_key, algorithm="RS256")
    logger.debug(f"JWT generated, {encoded_jwt}")
    return encoded_jwt


def authenticate_github_app(installation_id: int) -> str | None:
    # check if a token exists in the database
    # if not, generate a new token and store it in the database
    # TODO

    encoded_jwt = generate_jwt()

    headers = {
        "Authorization": f"Bearer {encoded_jwt}",
        "Accept": "application/vnd.github+json",
        "X-Github-Api-Version": "2022-11-28",
    }

    token_url = (
        f"https://api.github.com/app/installations/{installation_id}/access_tokens"
    )
    token_response = requests.post(token_url, headers=headers)
    token_response.raise_for_status()
    token = token_response.json()["token"]
    # expiry = token_response.json()["expires_at"]
    logger.debug(f"Token generated, {token}")

    return token
