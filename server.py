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
from functools import partial
import logging
import os
import signal

log = logging.getLogger("emposter")

class DatatrackerHandler:
    async def handle_DATA(
        self,
        server: SMTPServer,
        session: SMTPSession,
        envelope: SMTPEnvelope,
    ):
        log.info(f"Accepted message from {envelope.mail_from} to {envelope.rcpt_tos}")
        return "250 Message accepted for delivery"


def main():
    hostname = os.environ.get("EMPOSTER_HOSTNAME", "")
    log_level = os.environ.get("EMPOSTER_LOG_LEVEL", "INFO")
    smtp_log_level = os.environ.get("EMPOSTER_SMTP_LOG_LEVEL", "WARNING")

    # configure logging
    logging.basicConfig(level=logging.ERROR)
    log.setLevel(log_level.upper())
    logging.getLogger("mail.log").setLevel(smtp_log_level.upper())


    # factory to generate an LMTPServer
    factory = partial(
        LMTPServer,
        DatatrackerHandler(),
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
    log.debug("Exited event loop. Stopping server loop.")
    server_loop.close()
    loop.run_until_complete(server_loop.wait_closed())
    loop.close()
    log.debug("Server loop closed. Exiting.")


if __name__ == "__main__":
    main()
