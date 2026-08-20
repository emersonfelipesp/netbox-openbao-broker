"""
Make the verified peer certificate visible to the application.

Uvicorn does not put the connection's TLS state into the ASGI scope — it
records `scheme = "https"` and nothing else — so an app served by it has no
supported way to see *which* client certificate was presented. That is a
problem for a service whose entire authorization decision is "which client is
this".

Rather than reach into uvicorn's internals from the request path, this
subclasses its HTTP protocol and populates the standard **ASGI TLS extension**
(`scope["extensions"]["tls"]`), which is the shape an ASGI app is supposed to
find this information in. If uvicorn ever implements the extension natively,
the application code keeps working and this module simply becomes unnecessary.

The injection happens through a property on `scope`. The alternative would be
overriding `handle_events()`, which means copying uvicorn's request loop and
re-copying it on every upgrade — a much larger surface to get wrong than
intercepting one assignment.
"""

from __future__ import annotations

__all__ = ('tls_aware_protocol', 'resolve_http_protocol')


def tls_aware_protocol(base):
    """
    Return a subclass of `base` that publishes the peer certificate.

    `base` is one of uvicorn's HTTP protocol classes. The subclass records the
    connection's `ssl_object` when the connection is made, and attaches the
    verified peer certificate to every scope built on that connection.
    """

    class TLSAwareProtocol(base):
        _ssl_object = None

        def connection_made(self, transport):
            # Captured once per connection, before any request is parsed. By
            # this point the TLS handshake has completed and the certificate
            # has been verified against the configured CA — this only reads
            # what the TLS layer already accepted.
            self._ssl_object = transport.get_extra_info('ssl_object')
            super().connection_made(transport)

        @property
        def scope(self):
            return self.__dict__.get('_tls_scope')

        @scope.setter
        def scope(self, value):
            if isinstance(value, dict) and self._ssl_object is not None:
                extensions = value.setdefault('extensions', {})
                extensions['tls'] = {
                    'peercert': self._ssl_object.getpeercert(),
                    'cipher': self._ssl_object.cipher(),
                    'tls_version': self._ssl_object.version(),
                }
            self.__dict__['_tls_scope'] = value

    TLSAwareProtocol.__name__ = f'TLSAware{base.__name__}'
    TLSAwareProtocol.__qualname__ = TLSAwareProtocol.__name__
    return TLSAwareProtocol


def resolve_http_protocol():
    """
    Pick uvicorn's HTTP protocol implementation and wrap it.

    `httptools` is used when installed and `h11` otherwise, mirroring uvicorn's
    own `http="auto"` behaviour. Both are wrapped identically so the broker
    behaves the same either way — a difference in identity handling between two
    parser backends would be a spectacularly unpleasant bug to find.
    """
    try:
        from uvicorn.protocols.http.httptools_impl import HttpToolsProtocol

        return tls_aware_protocol(HttpToolsProtocol)
    except ImportError:
        from uvicorn.protocols.http.h11_impl import H11Protocol

        return tls_aware_protocol(H11Protocol)
