# Copyright The IETF Trust 2024, All Rights Reserved
#
"""General API definitions"""
import logging
import json
from urllib import request

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

    def __init__(self, token: str, base_url: str | None):
        self.token = token
        self.base_url = base_url or self.default_base_url
        if self.base_url is None:
            raise ValueError("Must specify base_url")

    def post_with_auth(self, url, payload):
        headers = {"Content-Type": "application/json; charset=UTF-8"}
        if self.token is not None:
            headers["X-Api-Key"] = self.token
        return request.urlopen(
            request.Request(
                url=url,
                method="POST",
                headers=headers,
                data=json.dumps(payload).encode("utf8"),
            ),
        )

    def post_message(self, dest: str, message: bytes) -> None:
        raise NotImplementedError("Subclasses must implement this method")
