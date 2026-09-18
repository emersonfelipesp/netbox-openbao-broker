"""
End-to-end mTLS, against the broker running as a real process.

The authorization tests stub identity extraction, which leaves the single most
security-critical assumption in the service untested: that
`identity_from_scope` can actually pull a verified peer certificate out of a
live ASGI connection. If that returns nothing, or the wrong name, every request
either fails closed (annoying) or resolves to the wrong instance (a breach).
Neither shows up in a stubbed test — and uvicorn does not populate the ASGI TLS
extension on its own, so `broker.tls_scope` has to, which is exactly the kind
of thing that breaks silently on a dependency upgrade.

The server runs as a **subprocess**, not a thread. That is how it runs in
production, and running uvicorn in a thread alongside the test client in one
process produced connection resets that had nothing to do with the code under
test. A harness artifact is a poor thing to spend an afternoon debugging and a
worse thing to leave in a suite as a flake.
"""

from __future__ import annotations

import datetime
import os
import socket
import ssl
import subprocess
import sys
import textwrap
import time

import httpx
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _name(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _make_ca(tmp):
    key = _key()
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(_name('broker-test-ca')).issuer_name(_name('broker-test-ca'))
        .public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, key_cert_sign=True, crl_sign=True,
                content_commitment=False, key_encipherment=False, data_encipherment=False,
                key_agreement=False, encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )
    path = tmp / 'ca.pem'
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return key, cert, path


def _issue(tmp, ca_key, ca_cert, cn, filename, server=False):
    key = _key()
    now = datetime.datetime.now(datetime.timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(_name(cn)).issuer_name(ca_cert.subject)
        .public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=1))
    )
    # Strict OpenSSL versions require a complete, internally consistent chain:
    # CA SKI, matching leaf AKI, CA/leaf basic constraints, leaf key usage, and
    # the EKU for the certificate's actual TLS role. Missing any of these can
    # fail before the broker receives a request and invalidate the mTLS suite.
    usage = x509.ExtendedKeyUsage(
        [ExtendedKeyUsageOID.SERVER_AUTH] if server else [ExtendedKeyUsageOID.CLIENT_AUTH]
    )
    builder = (
        builder
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
                ca_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
            ),
            critical=False,
        )
        .add_extension(usage, critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
    )
    if server:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName('localhost')]), critical=False,
        )
    cert = builder.sign(ca_key, hashes.SHA256())

    cert_path = tmp / f'{filename}.pem'
    key_path = tmp / f'{filename}.key'
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    ))
    return cert_path, key_path


def test_test_pki_has_a_strict_verifiable_extension_chain(tmp_path):
    ca_key, ca_cert, _ = _make_ca(tmp_path)
    leaf_path, _ = _issue(tmp_path, ca_key, ca_cert, 'localhost', 'leaf', server=True)
    leaf = x509.load_pem_x509_certificate(leaf_path.read_bytes())

    ca_ski = ca_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value.digest
    leaf_aki = leaf.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier).value
    assert leaf_aki.key_identifier == ca_ski
    assert ca_cert.extensions.get_extension_for_class(x509.BasicConstraints).value.path_length == 0
    assert leaf.extensions.get_extension_for_class(x509.BasicConstraints).value.ca is False
    assert leaf.extensions.get_extension_for_class(x509.KeyUsage).value.key_cert_sign is False
    assert leaf.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value == x509.ExtendedKeyUsage(
        [ExtendedKeyUsageOID.SERVER_AUTH]
    )


def _free_port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


SERVER_SCRIPT = textwrap.dedent(
    '''
    import ssl, sys
    sys.path.insert(0, {repo!r})
    import uvicorn
    from broker.app import create_app
    from broker.audit import AuditLog
    from broker.config import BrokerConfig, InstancePolicy
    from broker.tls_scope import resolve_http_protocol

    class FakeVault:
        """Logs reads to a file, so a test can prove a denial never got here."""
        def read(self, path, version=None):
            with open({calls!r}, "a") as handle:
                handle.write("read " + path + "\\n")
            return {{"password": "hunter2"}}
        def health(self):
            return {{"reachable": True, "sealed": False}}

    config = BrokerConfig(
        openbao_url="https://bao.invalid:8200",
        instances={{"netbox-prod": InstancePolicy(
            name="netbox-prod", path_prefixes=("netbox/credentials",))}},
    )
    uvicorn.run(
        create_app(config, vault=FakeVault(), audit=AuditLog()),
        host="127.0.0.1", port={port},
        ssl_certfile={cert!r}, ssl_keyfile={key!r}, ssl_ca_certs={ca!r},
        ssl_cert_reqs=ssl.CERT_REQUIRED,
        http=resolve_http_protocol(),
        log_level="warning",
    )
    '''
)


@pytest.fixture(scope='module')
def live(tmp_path_factory):
    tmp = tmp_path_factory.mktemp('mtls')
    ca_key, ca_cert, ca_path = _make_ca(tmp)
    server_cert, server_key = _issue(tmp, ca_key, ca_cert, 'localhost', 'server', server=True)
    # The CN is the instance identity. One is configured; the other is not.
    known = _issue(tmp, ca_key, ca_cert, 'netbox-prod', 'known')
    stranger = _issue(tmp, ca_key, ca_cert, 'not-configured', 'stranger')

    port = _free_port()
    calls = tmp / 'vault-calls.log'
    script = tmp / 'serve.py'
    script.write_text(SERVER_SCRIPT.format(
        repo=REPO_ROOT, calls=str(calls), port=port,
        cert=str(server_cert), key=str(server_key), ca=str(ca_path),
    ))

    process = subprocess.Popen(
        [sys.executable, str(script)],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )

    deadline = time.time() + 30
    ready = False
    while time.time() < deadline and process.poll() is None:
        try:
            with socket.create_connection(('127.0.0.1', port), timeout=1):
                ready = True
                break
        except OSError:
            time.sleep(0.1)

    if not ready:
        process.kill()
        output = process.communicate()[0] or '(no output)'
        # Deliberately a failure and not a skip. These are the only tests that
        # exercise identity extraction against a real handshake, and a skip
        # would let a broken environment green the pipeline with the service's
        # single most security-critical assumption never having been checked.
        pytest.fail(f'The broker process did not start:\n{output}')

    yield {
        'base': f'https://localhost:{port}',
        'ca': str(ca_path),
        'known': (str(known[0]), str(known[1])),
        'stranger': (str(stranger[0]), str(stranger[1])),
        'calls': calls,
    }

    process.terminate()
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()


def _client(live, which):
    context = ssl.create_default_context(cafile=live['ca'])
    context.load_cert_chain(*live[which])
    return httpx.Client(base_url=live['base'], verify=context, timeout=15)


def _vault_calls(live):
    return live['calls'].read_text().splitlines() if live['calls'].exists() else []


class TestRealHandshake:

    def test_a_configured_client_certificate_is_identified(self, live):
        """
        The assumption the whole service rests on: the CN of the verified peer
        certificate reaches the authorization decision. uvicorn does not
        publish the peer certificate itself, so this is really a test of
        `broker.tls_scope` surviving contact with a real handshake.
        """
        with _client(live, 'known') as client:
            response = client.post('/v1/secret/read', json={'path': 'netbox/credentials/abc'})

        assert response.status_code == 200, response.text
        assert response.json()['data'] == {'password': 'hunter2'}

    def test_prefix_enforcement_holds_over_real_tls(self, live):
        before = len(_vault_calls(live))
        with _client(live, 'known') as client:
            response = client.post('/v1/secret/read', json={'path': 'production/root'})

        assert response.status_code == 403
        assert len(_vault_calls(live)) == before, 'a refused request reached OpenBao'

    def test_traversal_is_refused_over_real_tls(self, live):
        before = len(_vault_calls(live))
        with _client(live, 'known') as client:
            response = client.post(
                '/v1/secret/read', json={'path': 'netbox/credentials/../../production/root'},
            )

        assert response.status_code == 400
        assert len(_vault_calls(live)) == before

    def test_a_certificate_from_the_ca_but_unknown_instance_is_refused(self, live):
        """
        Signed by the trusted CA, so the handshake succeeds — and the request
        is still refused, because a valid certificate is not authorization. If
        it were, one mis-issued certificate would be full vault access.
        """
        before = len(_vault_calls(live))
        with _client(live, 'stranger') as client:
            response = client.post('/v1/secret/read', json={'path': 'netbox/credentials/abc'})

        assert response.status_code == 403
        assert len(_vault_calls(live)) == before

    def test_no_client_certificate_cannot_complete_the_handshake(self, live):
        """
        `CERT_REQUIRED` is the authentication mechanism, so this must fail at
        the TLS layer rather than reaching any application code.
        """
        context = ssl.create_default_context(cafile=live['ca'])
        with httpx.Client(base_url=live['base'], verify=context, timeout=15) as client:
            # httpx surfaces a TLS-layer refusal as a transport error. Which
            # one depends on where in the handshake the server gives up, so the
            # assertion is on the category rather than on a specific class.
            with pytest.raises(httpx.TransportError):
                client.post('/v1/secret/read', json={'path': 'netbox/credentials/abc'})

    def test_healthz_leaks_nothing(self, live):
        with _client(live, 'known') as client:
            body = client.get('/healthz').json()

        assert body['ok'] is True
        # Reachability and sealed state only — nothing about instances, paths,
        # or policy.
        assert set(body['openbao']) <= {'reachable', 'sealed', 'version'}
        assert 'instances' not in body

    def test_interactive_docs_are_not_served(self, live):
        """A second, differently-shaped surface on a deliberately small service."""
        with _client(live, 'known') as client:
            assert client.get('/docs').status_code == 404
            assert client.get('/openapi.json').status_code == 404


class TestIdentityAcrossConnections:
    """
    Where a subtle bug in `broker.tls_scope` would actually hide.

    The peer certificate is captured once per connection and attached to every
    scope built on it. That is correct only if the association really is
    per-connection: if the certificate were ever captured per-process, or a
    scope shared between connections, one client would inherit another's
    authorization. Nothing in the single-request tests above would notice,
    because each of them opens a fresh connection and makes one request.
    """

    def test_keep_alive_does_not_lose_the_identity(self, live):
        """
        Several requests down one connection. The first builds the scope; the
        rest reuse the protocol instance, and each must still resolve to the
        same verified certificate rather than to nothing.
        """
        with _client(live, 'known') as client:
            for _ in range(5):
                response = client.post(
                    '/v1/secret/read', json={'path': 'netbox/credentials/abc'})
                assert response.status_code == 200, response.text

    def test_two_clients_interleaved_do_not_cross_over(self, live):
        """
        A configured instance and a stranger, alternating against the same
        server. If identity leaked between connections, the stranger would be
        served — which is the whole breach in one request.
        """
        before = len(_vault_calls(live))

        with _client(live, 'known') as good, _client(live, 'stranger') as bad:
            for _ in range(4):
                assert good.post(
                    '/v1/secret/read', json={'path': 'netbox/credentials/abc'},
                ).status_code == 200
                assert bad.post(
                    '/v1/secret/read', json={'path': 'netbox/credentials/abc'},
                ).status_code == 403

        # Four permitted reads and not one from the stranger.
        assert len(_vault_calls(live)) == before + 4
