# Copyright The IETF Trust 2024, All Rights Reserved
#
"""General API definitions"""
from base64 import b64encode
import logging
import json
from urllib import parse, request

log = logging.getLogger("api")


class ApiError(Exception):
    pass


class BadDestinationError(ApiError):
    pass


class BadMessageError(ApiError):
    pass


class UnknownError(ApiError):
    pass


class Api:
    default_base_url: str | None = None  # subclasses should fill this in
    post_endpoint = "api/email/"

    def __init__(self, token: str, base_url: str | None):
        self.token = token
        self.base_url = base_url or self.default_base_url
        if self.base_url is None:
            raise ValueError("Must specify base_url")

    def post_message(self, dest: str, message: bytes) -> None:
        payload = {
            "dest": dest,
            "message": b64encode(message).decode(),
        }
        url = parse.urljoin(self.base_url, self.post_endpoint)
        headers = {"Content-Type": "application/json; charset=UTF-8"}
        if self.token is not None:
            headers["X-Api-Key"] = self.token
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
        # if we got here, that means success!
