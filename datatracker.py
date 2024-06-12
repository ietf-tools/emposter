# Copyright The IETF Trust 2024, All Rights Reserved
import api
import logging

log = logging.getLogger("api")


class DatatrackerApi(api.Api):
    default_base_url = "https://datatracker.ietf.org"
