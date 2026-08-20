"""
Entry point.

TLS is configured here rather than left to a front proxy. The broker
terminates it itself so the client certificate is available to the process
that makes the authorization decision — see `identity.py` for why there is no
header-based alternative.
"""

from __future__ import annotations

import os
import ssl
import sys

from .app import create_app
from .audit import configure_logging
from .config import ConfigError, load_config
from .vault import VaultClient


def main() -> int:
    configure_logging(os.environ.get('BROKER_LOG_LEVEL', 'INFO'))

    try:
        config = load_config()
    except ConfigError as exc:
        print(f'Configuration error: {exc}', file=sys.stderr)
        return 2

    cert = os.environ.get('BROKER_TLS_CERT')
    key = os.environ.get('BROKER_TLS_KEY')
    client_ca = os.environ.get('BROKER_TLS_CLIENT_CA')

    if not (cert and key and client_ca):
        # Refusing to start is the only correct response. Serving without
        # client certificates would leave every request unauthenticated while
        # looking healthy, and the failure would surface as a breach rather
        # than as an error.
        print(
            'BROKER_TLS_CERT, BROKER_TLS_KEY, and BROKER_TLS_CLIENT_CA are all required. '
            'The broker authenticates callers by client certificate and has no other mode.',
            file=sys.stderr,
        )
        return 2

    # Authentication itself stays lazy, but the material has to be there. A
    # broker that starts, reports healthy, and then 500s on NetBox's first
    # request is a worse failure than one that refuses to start, because the
    # first person to notice is a user rather than the deploy.
    vault = VaultClient(config)
    try:
        vault.check_credentials()
    except ConfigError as exc:
        print(f'Configuration error: {exc}', file=sys.stderr)
        return 2

    import uvicorn

    from .tls_scope import resolve_http_protocol

    uvicorn.run(
        create_app(config, vault=vault),
        host=os.environ.get('BROKER_HOST', '0.0.0.0'),  # noqa: S104 — a container's only interface
        port=int(os.environ.get('BROKER_PORT', '8201')),
        ssl_certfile=cert,
        ssl_keyfile=key,
        ssl_ca_certs=client_ca,
        # CERT_REQUIRED is the whole authentication mechanism. Anything weaker
        # makes the client certificate advisory.
        ssl_cert_reqs=ssl.CERT_REQUIRED,
        # Publishes the verified peer certificate into the ASGI scope, which
        # uvicorn does not do on its own. Without it the broker cannot tell one
        # client from another and fails every request closed.
        http=resolve_http_protocol(),
        log_config=None,
        access_log=False,
    )
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
