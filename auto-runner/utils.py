from uvicorn.logging import ColourizedFormatter
from dotenv import load_dotenv

import logging
import sys
import os

logger = logging.getLogger(__name__)
formatter = ColourizedFormatter(fmt="%(levelprefix)s %(message)s", use_colors=True)
stream_handler = logging.StreamHandler(stream=sys.stdout)
stream_handler.setFormatter(formatter)
logger.addHandler(stream_handler)
logger.setLevel(logging.DEBUG)

load_dotenv()
environment = os.environ
