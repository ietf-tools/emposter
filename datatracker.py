# Copyright The IETF Trust 2024, All Rights Reserved
import api
from base64 import b64encode
import json
import logging
from urllib import parse

log = logging.getLogger("api")


class DatatrackerApi(api.Api):
    """API for posting messages to the datatracker"""
    default_base_url = "https://datatracker.ietf.org"

    def post_message(self, dest: str, message: bytes) -> None:
        payload = {
            "dest": dest,
            "message": b64encode(message).decode(),
        }
        url = parse.urljoin(self.base_url, "api/email/")
        response = self.post_with_auth(url, payload)

        log.debug(f"API responded with status {response.status}")
        if response.status != 200:
            raise api.ApiError()

        log.debug(f"Response Content-Type was {response.headers['Content-Type']}")
        if response.headers["Content-Type"] != "application/json":
            raise api.ApiError()

        api_response = json.loads(response.read())
        log.debug(f"API result was {api_response['result']}")
        if api_response["result"] == "bad_dest":
            raise api.BadDestinationError()
        if api_response["result"] == "bad_msg":
            raise api.BadMessageError()
        if api_response["result"] != "ok":
            raise api.UnknownError()
        # if we got here, that means success!
