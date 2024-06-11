# Copyright The IETF Trust 2024, All Rights Reserved
import json
from base64 import b64encode
from typing import Optional
from urllib import parse, request


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
    request.urlopen(
        request.Request(
            url=url,
            method="POST",
            headers=headers,
            data=json.dumps(payload).encode("utf8"),
        ),
    )
