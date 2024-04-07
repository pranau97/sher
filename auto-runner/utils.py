from uvicorn.logging import ColourizedFormatter
from dotenv import load_dotenv

import logging
import sys
import os

logger = logging.getLogger(__name__)
fmt = "%(levelprefix)s %(filename)s:%(funcName)s():L%(lineno)d - %(message)s"

formatter = ColourizedFormatter(fmt=fmt, use_colors=True)
stream_handler = logging.StreamHandler(stream=sys.stdout)
stream_handler.setFormatter(formatter)
logger.addHandler(stream_handler)
logger.setLevel(logging.DEBUG)

load_dotenv()
environment = os.environ


def gh_header_for_token(token: str, accept="application/vnd.github+json") -> dict:
    return {
        "Authorization": f"Bearer {token}",
        "Accept": accept,
        "X-Github-Api-Version": "2022-11-28",
    }
