"""
The failure modes, which live testing found and the stubs had not.

Running the container against a real OpenBao surfaced two defects that every
in-process test had passed straight over:

1. The AppRole material is read on the *first request*, not at startup. A broker
   whose SecretID was unreadable therefore started, reported healthy, and
   answered NetBox's first read with a 500.
2. That 500 was **unaudited**. `run()` audited `VaultError` and success and let
   anything else unwind past it — in a service whose distinguishing feature is
   that its record survives a NetBox compromise, a request that leaves no trace
   is the worst kind of bug to ship.

Neither was reachable from a fake backend, because a fake never fails in a way
its author did not think of.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from broker.app import create_app
from broker.audit import AuditLog
from broker.config import BrokerConfig, ConfigError, InstancePolicy
from broker.identity import IdentityError, common_name_from_peer_cert
from broker.vault import VaultClient, VaultMisconfigured

PREFIX = 'BROKER_TEST_BAO'


def config(auth_method='approle'):
    return BrokerConfig(
        openbao_url='https://bao.invalid:8200',
        auth_method=auth_method,
        env_prefix=PREFIX,
        instances={'netbox-prod': InstancePolicy(
            name='netbox-prod', path_prefixes=('netbox/credentials',))},
    )


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    for suffix in ('ROLE_ID', 'SECRET_ID', 'TOKEN'):
        monkeypatch.delenv(f'{PREFIX}_{suffix}', raising=False)
        monkeypatch.delenv(f'{PREFIX}_{suffix}_FILE', raising=False)


class TestStartupCredentialCheck:
    """
    A misconfiguration has no reason to wait for the first request to surface.
    Authentication stays lazy — binding process start to OpenBao's availability
    would mean a restart during a vault maintenance window leaves the broker
    down after the vault comes back — but *presence of the material* is a local
    question answerable at startup.
    """

    def test_missing_approle_material_is_refused(self):
        with pytest.raises(ConfigError) as caught:
            VaultClient(config()).check_credentials()

        assert f'{PREFIX}_ROLE_ID' in str(caught.value)
        assert f'{PREFIX}_SECRET_ID' in str(caught.value)

    def test_a_half_configured_approle_is_refused(self, monkeypatch):
        """The RoleID alone is a configuration that cannot authenticate."""
        monkeypatch.setenv(f'{PREFIX}_ROLE_ID', 'role')

        with pytest.raises(ConfigError) as caught:
            VaultClient(config()).check_credentials()

        assert f'{PREFIX}_SECRET_ID' in str(caught.value)
        assert f'{PREFIX}_ROLE_ID' not in str(caught.value)

    def test_missing_token_is_refused_under_token_auth(self):
        with pytest.raises(ConfigError) as caught:
            VaultClient(config('token')).check_credentials()

        assert f'{PREFIX}_TOKEN' in str(caught.value)

    def test_material_supplied_by_file_is_accepted(self, monkeypatch, tmp_path):
        """
        The `_FILE` indirection is the recommended form — it keeps the SecretID
        out of `/proc/<pid>/environ` — so the startup check has to accept it.
        """
        role = tmp_path / 'role_id'
        secret = tmp_path / 'secret_id'
        role.write_text('role\n')
        secret.write_text('secret\n')
        monkeypatch.setenv(f'{PREFIX}_ROLE_ID_FILE', str(role))
        monkeypatch.setenv(f'{PREFIX}_SECRET_ID_FILE', str(secret))

        VaultClient(config()).check_credentials()

    def test_an_unreadable_file_is_refused_by_path(self, monkeypatch, tmp_path):
        """
        This is the deployment mistake that produced the 500: a secret file the
        broker's user cannot read. Naming the path is safe — it is operator
        configuration, not material — and without it the failure is undiagnosable.
        """
        monkeypatch.setenv(f'{PREFIX}_ROLE_ID', 'role')
        monkeypatch.setenv(f'{PREFIX}_SECRET_ID_FILE', str(tmp_path / 'absent'))

        with pytest.raises(ConfigError) as caught:
            VaultClient(config()).check_credentials()

        assert 'absent' in str(caught.value)


class TestCredentialFailureAtRequestTime:

    def test_unreadable_material_becomes_a_503_not_a_crash(self):
        """
        Startup checked this, so reaching it means the material became
        unreadable while running — a rotation that went wrong. The caller is
        told the broker cannot serve the request and nothing more; the reason
        names an operator's file path and belongs in this process's log.
        """
        client = VaultClient(config())

        with pytest.raises(VaultMisconfigured) as caught:
            client._get()

        assert caught.value.status_code == 503
        assert 'SECRET_ID' not in str(caught.value)


class TestNoRequestGoesUnaudited:

    def test_an_unexpected_error_is_still_audited(self):
        """
        The audit record is the thing this service exists to produce. "Every
        request is audited" cannot hold if an unforeseen exception unwinds past
        the only place that writes one.
        """
        records = []

        class Recording(AuditLog):
            def __init__(self):
                pass

            def record(self, **kwargs):
                records.append(kwargs)

        class BrokenVault:
            def read(self, path, version=None):
                raise RuntimeError('something nobody anticipated')

            def health(self):
                return {'reachable': True, 'sealed': False}

        app = create_app(config(), vault=BrokenVault(), audit=Recording())

        import broker.app as app_module
        original = app_module.identity_from_scope
        app_module.identity_from_scope = lambda scope: 'netbox-prod'
        try:
            with TestClient(app, raise_server_exceptions=False) as client:
                response = client.post(
                    '/v1/secret/read', json={'path': 'netbox/credentials/abc'})
        finally:
            app_module.identity_from_scope = original

        assert response.status_code == 500
        assert records, 'the request left no audit record at all'
        assert records[-1]['outcome'] == 'error'
        assert records[-1]['instance'] == 'netbox-prod'
        assert records[-1]['path'] == 'netbox/credentials/abc'
        # The exception text is a bug report, not an audit field, and could
        # carry anything at all. It goes to the process log.
        assert 'nobody anticipated' not in records[-1]['reason']
        assert 'nobody anticipated' not in response.text


class TestMalformedPeerCertificate:
    """
    The shape comes from the ssl module rather than from the client, so this
    should be unreachable. If it ever is reached, an unusable identity must
    fail closed as a 401 — a 500 would be an authentication failure wearing the
    costume of a server bug.
    """

    @pytest.mark.parametrize('peer_cert', [
        {'subject': 'not-a-sequence-of-rdns'},
        {'subject': [('commonName',)]},
        {'subject': [None]},
        {'subject': [[('commonName', None)]]},
    ])
    def test_it_raises_identity_error_and_nothing_else(self, peer_cert):
        with pytest.raises(IdentityError):
            common_name_from_peer_cert(peer_cert)


class TestMalformedRequestsAreAudited:
    """
    Body validation runs before the dependency that identifies the caller, so a
    malformed request to a secret route used to produce a 422 and no audit
    record. An attempt to read a secret is exactly what an operator
    reconstructing an incident wants to find, whether or not it parsed.
    """

    def _client(self, records):
        class Recording(AuditLog):
            def __init__(self):
                pass

            def record(self, **kwargs):
                records.append(kwargs)

        class UnusedVault:
            def read(self, path, version=None):
                raise AssertionError('a malformed request must never reach OpenBao')

            def write(self, path, data, cas=None):
                raise AssertionError('a malformed request must never reach OpenBao')

            def health(self):
                return {'reachable': True, 'sealed': False}

        app = create_app(config(), vault=UnusedVault(), audit=Recording())

        import broker.app as app_module
        original = app_module.identity_from_scope
        app_module.identity_from_scope = lambda scope: 'netbox-prod'
        client = TestClient(app, raise_server_exceptions=False)
        client._restore = lambda: setattr(app_module, 'identity_from_scope', original)
        return client

    @pytest.mark.parametrize('body', [
        {},                                              # no path at all
        {'path': 123},                                   # wrong type
        {'path': 'netbox/credentials/a', 'version': 0},  # ge=1
        {'path': 'x' * 501},                             # max_length
    ])
    def test_a_malformed_body_still_leaves_a_record(self, body):
        records = []
        client = self._client(records)
        try:
            response = client.post('/v1/secret/read', json=body)
        finally:
            client._restore()

        assert response.status_code == 422
        assert records, 'a malformed request left no audit record'
        assert records[-1]['operation'] == 'malformed'
        assert records[-1]['outcome'] == 'denied'
        assert records[-1]['instance'] == 'netbox-prod'

    def test_the_response_does_not_echo_the_material_back(self):
        """
        FastAPI's default 422 includes the offending input, which for a write is
        the secret itself. The caller sent it, so echoing is not a disclosure —
        but it puts material in a response body, and from there into whatever
        logs it.
        """
        records = []
        client = self._client(records)
        try:
            response = client.post(
                '/v1/secret/write',
                json={'path': 'netbox/credentials/a', 'data': {'password': 'hunter2'}, 'cas': -1},
            )
        finally:
            client._restore()

        assert response.status_code == 422
        assert 'hunter2' not in response.text
        assert response.json() == {'detail': 'Invalid request.'}
