# Copyright The IETF Trust 2024, All Rights Reserved
import api
from base64 import b64encode
import json
import logging
from urllib import parse

log = logging.getLogger("api")


class MailarchiveApi(api.Api):
    """API for posting messages to the Mail Archive

    Only supports public lists.
    """
    default_base_url = "https://mailarchive.ietf.org"

    def post_message(self, dest: str, message: bytes) -> None:
        payload = {
            "list_name": dest,
            "list_visibility": "public",
            "message": b64encode(message).decode(),
        }
        url = parse.urljoin(self.base_url, "api/v1/message/import/")
        response = self.post_with_auth(url, payload)

        log.debug(f"API responded with status {response.status} {response.reason}")
        # Successful responses actually return 201 as of now, but leaving a little flexibility.
        if response.status not in [200, 201, 202]:
            raise api.ApiError()

        # if we get here, that means success!
