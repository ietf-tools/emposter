# Copyright The IETF Trust 2024, All Rights Reserved
#

import asyncio
from aiosmtpd.smtp import (
    Envelope as SMTPEnvelope,
    Session as SMTPSession,
    SMTP as SMTPServer,
)
from aiosmtpd.lmtp import LMTP as LMTPServer
from contextlib import suppress
from email.utils import parseaddr
from functools import partial
import logging
import os
import signal
import sys

import datatracker


# Exit codes
EXIT_OK = 0
EXIT_USAGE_ERR = 2

log = logging.getLogger("emposter")


class DatatrackerHandler:
    DOMAIN = "datatracker.ietf.internal"  # all lowercase

    def __init__(self, api_token, api_base_url=None):
        self.api_token = api_token
        self.api_base_url = api_base_url

    async def handle_RCPT(
        self,
        server: SMTPServer,
        session: SMTPSession,
        envelope: SMTPEnvelope,
        address: str,
        rcpt_options: [str],
    ):
        """Validate recipient domain before accepting"""
        addr_tuple = parseaddr(address)
        if addr_tuple == ("", ""):
            # this really shouldn't happen, aiosmtpd has already validated the address
            return "553 5.1.3 Error: malformed address"
        addr = addr_tuple[1]
        if not addr.lower().endswith("@" + self.DOMAIN):
            return "550 5.7.1 Error: unsupported or missing domain"
        envelope.rcpt_tos.append(address)
        envelope.rcpt_options.extend(rcpt_options)
        return "250 OK"

    def _parse_destination(self, address):
        addr_tuple = parseaddr(address.lower())
        if addr_tuple == ("", ""):
            # this really, REALLY shouldn't happen, aiosmtpd AND self.handle_RCPT
            # have already validated the address TWICE...
            return None
        loc_addr, domain = addr_tuple[1].split("@", 1)
        if domain != self.DOMAIN or loc_addr not in datatracker.DESTINATIONS:
            # We're being paranoid re-checking the domain, but just in case.
            return None
        return loc_addr

    async def handle_DATA(
        self,
        server: SMTPServer,
        session: SMTPSession,
        envelope: SMTPEnvelope,
    ):
        # Per RFC2033: https://datatracker.ietf.org/doc/html/rfc2033.html#section-4.2
        #     ...after the final ".", the server returns one reply
        #     for each previously successful RCPT command in the mail transaction,
        #     in the order that the RCPT commands were issued.  Even if there were
        #     multiple successful RCPT commands giving the same forward-path, there
        #     must be one reply for each successful RCPT command.
        response_lines = []
        for addr in envelope.rcpt_tos:
            dest = self._parse_destination(addr)
            if dest is None:
                log.info(f"Rejecting message from {envelope.mail_from} to {addr} (invalid destination)")
                response_lines.append("550 5.1.1 Error: invalid mailbox")
            log.debug(f"Posting message from {envelope.mail_from} to {dest} via Datatracker API")
            datatracker.post_message(
                dest=dest,
                message=envelope.original_content,  # envelope.content is decoded, pass original bytes
                api_token=self.api_token,
                base_url=self.api_base_url,
            )
            log.info(f"Accepted message from {envelope.mail_from} to {addr} (destination {dest})")
            response_lines.append("250 Message accepted for delivery")
        return "\n".join(response_lines)


def main():
    hostname = os.environ.get("EMPOSTER_HOSTNAME", "")
    log_level = os.environ.get("EMPOSTER_LOG_LEVEL", "INFO")
    smtp_log_level = os.environ.get("EMPOSTER_SMTP_LOG_LEVEL", "WARNING")
    api_token = os.environ.get("EMPOSTER_API_TOKEN", None)
    api_base_url = os.environ.get("EMPOSTER_API_BASE", None)

    if api_token is None:
        sys.stderr.write(
            "Error: API token is not set. Set EMPOSTER_API_TOKEN in the environment.\n\n"
        )
        sys.exit(EXIT_USAGE_ERR)

    # configure logging
    logging.basicConfig(level=logging.ERROR)
    log.setLevel(log_level.upper())
    logging.getLogger("mail.log").setLevel(smtp_log_level.upper())

    # factory to generate an LMTPServer
    factory = partial(
        LMTPServer,
        DatatrackerHandler(
            api_token=api_token,
            api_base_url=api_base_url,
        ),
        enable_SMTPUTF8=True,
        hostname=hostname,
        ident="emposter LMTP",
    )

    # set up the asyncio loop
    log.debug("Creating event loop")
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    log.info("Starting server")
    server = loop.create_server(factory, host="", port="8025")
    server_loop = loop.run_until_complete(server)

    # Handle interrupt / term signals
    for sig in [signal.SIGINT, signal.SIGTERM]:
        loop.add_signal_handler(sig, loop.stop)

    # main event loop
    log.debug("Entering main event loop")
    with suppress(KeyboardInterrupt):
        loop.run_forever()

    # shut down and clean up
    log.debug("Exited main event loop")
    server_loop.close()
    loop.run_until_complete(server_loop.wait_closed())
    loop.close()
    log.info("Stopped server")
    sys.exit(EXIT_OK)


if __name__ == "__main__":
    main()
