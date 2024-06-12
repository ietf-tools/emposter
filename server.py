# Copyright The IETF Trust 2024, All Rights Reserved
#
"""LMTP-to-HTTP API server"""

import api
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


# Exit codes
EXIT_OK = 0
EXIT_USAGE_ERR = 2

log = logging.getLogger("emposter")


class EmposterHandler:
    MAX_RCPT_TO = 100  # min required - https://datatracker.ietf.org/doc/html/rfc5321#section-4.5.3.1.8

    def __init__(self, domain, api):
        self.domain = domain
        self.api = api

    async def handle_RCPT(
        self,
        server: SMTPServer,
        session: SMTPSession,
        envelope: SMTPEnvelope,
        address: str,
        rcpt_options: [str],
    ):
        """Validate recipient domain before accepting"""
        try:
            loc_addr, domain = self._parse_destination(address)
        except ValueError:
            # this really shouldn't happen, aiosmtpd has already validated the address
            log.debug(f"Bad RCPT TO: {address}")
            return "553 5.1.3 Error: malformed address"
        if domain != self.domain:
            log.debug(f"Bad RCPT TO domain: {address}")
            return "550 5.7.1 Error: unsupported or missing domain"
        if len(loc_addr) == 0:
            log.debug(f"Empty RCPT TO destination: {address}")
            return "550 5.1.1 Error: invalid mailbox"
        if len(envelope.rcpt_tos) >= self.MAX_RCPT_TO:
            log.debug(
                f"Refusing RCPT TO: {address}, already have {len(envelope.rcpt_tos)} recipients"
            )
            return "452 Too many recipients"
        envelope.rcpt_tos.append(address)
        envelope.rcpt_options.extend(rcpt_options)
        return "250 OK"

    @staticmethod
    def _parse_destination(address):
        addr_tuple = parseaddr(address.lower())
        if addr_tuple == ("", ""):
            # this really, REALLY shouldn't happen, aiosmtpd AND self.handle_RCPT
            # have already validated the address TWICE...
            raise ValueError()
        loc_addr, domain = addr_tuple[1].split("@", 1)
        return loc_addr, domain

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
        #
        # Ensure we only POST once for each unique dest. Keep track of address -> dest map
        # so we can correctly reply to the DATA command.
        dests: dict[str, str] = {
            # in handle_RCPT(), already confirmed that _parse_destination() likes the addr
            addr: self._parse_destination(addr)[0]
            for addr in envelope.rcpt_tos
        }  # addr -> dest
        responses: dict[str, str] = {}  # dest -> reply line
        for dest in set(dests.values()):
            log.debug(f"Posting message from {envelope.mail_from} to {dest} via API")
            try:
                self.api.post_message(
                    dest=dest,
                    message=envelope.original_content,  # envelope.content is decoded, pass original bytes
                )
            except (
                api.BadDestinationError,
                api.BadMessageError,
                api.UnknownError,
            ):
                log.info(
                    f"Permanently rejecting message from {envelope.mail_from} to {dest}"
                )
                responses[dest] = "550 Message rejected"
            except Exception as err:
                log.error(
                    f"Error processing message from {envelope.mail_from} to {dest}: {err}"
                )
                responses[dest] = "451 Local error processing message"
            else:
                log.info(f"Accepted message from {envelope.mail_from} to {dest}")
                responses[dest] = "250 Message accepted for delivery"
        # Assemble the results in the original RCPT TO address order for our reply
        return "\n".join(responses[dests[addr]] for addr in envelope.rcpt_tos)


def main():
    api_flavor = os.environ.get("EMPOSTER_API_FLAVOR", "datatracker").lower()
    allowed_mail_domain = os.environ.get("EMPOSTER_DOMAIN", None)
    hostname = os.environ.get("EMPOSTER_HOSTNAME", "")
    log_level = os.environ.get("EMPOSTER_LOG_LEVEL", "INFO")
    api_log_level = os.environ.get("EMPOSTER_API_LOG_LEVEL", "WARNING")
    mail_log_level = os.environ.get("EMPOSTER_MAIL_LOG_LEVEL", "WARNING")
    api_token = os.environ.get("EMPOSTER_API_TOKEN", None)
    api_base_url = os.environ.get("EMPOSTER_API_BASE_URL", None)

    if api_flavor == "datatracker":
        import datatracker
        ApiClass = datatracker.DatatrackerApi
    elif api_flavor == "mailarchive":
        import mailarchive
        ApiClass = mailarchive.MailarchiveApi
    else:
        sys.stderr.write(
            f"Error: Unknown api flavor '{api_flavor}'. "
            "EMPOSTER_API_FLAVOR must be 'datatracker' or 'mailarchive'.\n\n"
        )
        sys.exit(EXIT_USAGE_ERR)

    if api_token is None:
        sys.stderr.write(
            "Error: API token is not set. Set EMPOSTER_API_TOKEN in the environment.\n\n"
        )
        sys.exit(EXIT_USAGE_ERR)

    if allowed_mail_domain is None:
        allowed_mail_domain = f"{api_flavor}.ietf.internal"

    # configure logging
    logging.basicConfig(level=logging.ERROR)
    log.setLevel(log_level.upper())
    logging.getLogger("api").setLevel(api_log_level.upper())
    logging.getLogger("mail.log").setLevel(mail_log_level.upper())

    # factory to generate an LMTPServer
    factory = partial(
        LMTPServer,
        EmposterHandler(
            domain=allowed_mail_domain,
            api=ApiClass(token=api_token, base_url=api_base_url),
        ),
        enable_SMTPUTF8=True,
        hostname=hostname,
        ident="emposter LMTP",
    )

    # set up the asyncio loop
    log.debug("Creating event loop")
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    log.info(f"Starting server for @{allowed_mail_domain} using {api_flavor} API on {api_base_url}")
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
