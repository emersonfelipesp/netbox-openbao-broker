"""
Who is asking.

Identity comes from the **peer certificate presented during the TLS handshake**
and from nowhere else. There is deliberately no header-based fallback.

A trusted-header mode would be easy to add and is how this kind of service
usually ends up compromised: the header is only trustworthy if every path to
the socket is controlled, and the first person to put a debugging proxy in
front, or to expose the port for a health check, silently converts an
authentication mechanism into a self-declared identity. mTLS was chosen for
#10 precisely so there is no such mode, and adding one later would undo the
decision rather than extend it.
"""

from __future__ import annotations

__all__ = ('IdentityError', 'common_name_from_peer_cert', 'identity_from_scope')


class IdentityError(Exception):
    """No usable client identity. Always a 401, never a 500."""


def common_name_from_peer_cert(peer_cert: dict | None) -> str:
    """
    Extract the subject CN from a parsed peer certificate.

    `getpeercert()` returns the subject as a tuple of relative distinguished
    names, each a tuple of (attribute, value) pairs — an awkward shape that is
    easy to index wrongly, so it is walked explicitly.

    The certificate has already been verified against the configured CA by the
    TLS layer before this runs; this only reads a name out of something already
    known to be trustworthy.
    """
    if not peer_cert:
        raise IdentityError('No client certificate was presented.')

    try:
        for rdn in peer_cert.get('subject', ()):
            for attribute, value in rdn:
                if attribute == 'commonName' and value:
                    return value
    except (AttributeError, TypeError, ValueError) as exc:
        # The shape comes from the ssl module rather than from the client, so
        # this should be unreachable. If it ever is reached, an unusable
        # identity must fail closed as a 401 — a 500 here would be an
        # authentication failure wearing the costume of a server bug.
        raise IdentityError('The client certificate could not be read.') from exc

    raise IdentityError('The client certificate has no subject common name.')


def identity_from_scope(scope) -> str:
    """
    Pull the client identity out of an ASGI connection scope.

    Reads the standard ASGI TLS extension, `scope["extensions"]["tls"]`, which
    `broker.tls_scope` populates because uvicorn does not implement it itself.

    An absent extension means TLS was not terminated by this process — the
    deployment is wrong, and failing closed is the only safe response. It must
    never fall back to anything the client could assert for itself.
    """
    tls = (scope.get('extensions') or {}).get('tls')

    if not tls:
        raise IdentityError(
            'No TLS information on this connection. The broker terminates TLS itself so it can '
            'see the client certificate; running it behind a terminating proxy is unsupported.'
        )

    return common_name_from_peer_cert(tls.get('peercert'))
