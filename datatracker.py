# Copyright The IETF Trust 2024, All Rights Reserved
import json
from base64 import b64encode
import logging
from typing import Optional
from urllib import parse, request

log = logging.getLogger(__name__)


class ApiError(Exception):
    """General API error"""
    pass


class BadDestinationError(ApiError):
    pass


class BadMessageError(ApiError):
    pass


class UnknownError(ApiError):
    pass


def post_message(
    dest: str,
    message: bytes,
    api_token: Optional[str] = None,
    base_url: Optional[str] = None,
):
    payload = {
        "dest": dest,
        "message": b64encode(message).decode(),
    }
    url = parse.urljoin(
        base_url or "https://datatracker.ietf.org",
        "api/email/",
    )
    headers = {"Content-Type": "application/json; charset=UTF-8"}
    if api_token is not None:
        headers["X-Api-Key"] = api_token
    response = request.urlopen(
        request.Request(
            url=url,
            method="POST",
            headers=headers,
            data=json.dumps(payload).encode("utf8"),
        ),
    )
    log.debug(f"API responded with status {response.status}")
    if response.status != 200:
        raise ApiError()

    log.debug(f"Response Content-Type was {response.headers['Content-Type']}")
    if response.headers["Content-Type"] != "application/json":
        raise ApiError()

    api_response = json.loads(response.read())
    log.debug(f"API result was {api_response['result']}")
    if api_response["result"] == "bad_dest":
        raise BadDestinationError()
    if api_response["result"] == "bad_msg":
        raise BadMessageError()
    if api_response["result"] != "ok":
        raise UnknownError()
    # if we got here, that meanssuccess!
