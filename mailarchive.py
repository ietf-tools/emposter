# Copyright The IETF Trust 2024, All Rights Reserved
import api
import logging

log = logging.getLogger("api")


class MailarchiveApi(api.Api):
    default_base_url = "https://mailarchive.ietf.org"
