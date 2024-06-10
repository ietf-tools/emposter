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
import os
import signal


class DatatrackerHandler:
    async def handle_RCPT(
        self,
        server: SMTPServer,
        session: SMTPSession,
        envelope: SMTPEnvelope,
        address: str,
        rcpt_options: [str],
    ):
        print(f">> Received msg for {address}")
        envelope.rcpt_tos.append(address)
        return "250 OK"

    async def handle_DATA(
        self,
        server: SMTPServer,
        session: SMTPSession,
        envelope: SMTPEnvelope,
    ):
        print(f"Message from {envelope.mail_from}")
        print(f"Message for {envelope.rcpt_tos}")
        print("Message:\n---")
        for line in envelope.content.decode("utf8").splitlines():
            print(f"> {line}".strip())
        print("\n---")
        return "250 Message accepted for delivery"


def main():
    hostname = os.environ.get("EMPOSTER_HOSTNAME", "")

    # factory to generate an LMTPServer
    factory = partial(
        LMTPServer,
        DatatrackerHandler(),
        enable_SMTPUTF8=True,
        hostname=hostname,
        ident="emposter LMTP",
    )

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    server = loop.create_server(factory, host="", port="8025")
    server_loop = loop.run_until_complete(server)
    loop.add_signal_handler(signal.SIGINT, loop.stop)
    with suppress(KeyboardInterrupt):
        loop.run_forever()
    server_loop.close()
    loop.run_until_complete(server_loop.wait_closed())
    loop.close()


if __name__ == "__main__":
    main()
