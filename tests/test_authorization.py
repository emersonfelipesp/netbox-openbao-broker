"""
Authorization.

This is the whole reason the service exists, so it gets the weight. The single
most important property is not that permitted requests succeed — it is that
**refused requests never reach OpenBao**. A broker that reads a secret and then
declines to return it has already defeated its own purpose: the material left
the vault, the vault's audit log records a read that no one authorized, and
only a bug stands between that and disclosure.

Every denial test below therefore asserts on the fake vault's call log, not
merely on the status code.
"""

from __future__ import annotations

import asyncio

import pytest
from fastapi.testclient import TestClient

from broker.app import Caller, create_app
from broker.audit import AuditLog
from broker.config import BrokerConfig, InstancePolicy, normalize_path


class FakeVault:
    """Records every call, so a test can prove one did not happen."""

    def __init__(self):
        self.calls = []

    def read(self, path, version=None):
        self.calls.append(("read", path, version))
        return {"password": "hunter2"}

    def write(self, path, data, cas=None):
        self.calls.append(("write", path, cas))
        return 1

    def delete(self, path, versions=None):
        self.calls.append(("delete", path, versions))

    def read_metadata(self, path):
        self.calls.append(("metadata_read", path, None))
        return {"current_version": 1}

    def set_metadata(self, path, custom_metadata):
        self.calls.append(("metadata_write", path, None))

    def list_versions(self, path):
        self.calls.append(("versions", path, None))
        return [{"version": 1}]

    def health(self):
        return {"reachable": True, "sealed": False}

    def execute_administration(self, operation, arguments):
        self.calls.append(("administration", operation, arguments))
        return {"sealed": False}

    def download_raft_snapshot(self):
        self.calls.append(("download_raft_snapshot",))

        class Download:
            declared_size = 8

            @staticmethod
            def chunks():
                yield b"snapshot"

        return Download()

    def restore_raft_snapshot(self, stream, size, *, force=False):
        self.calls.append(("restore_raft_snapshot", stream.read(), size, force))


class RecordingAudit(AuditLog):
    def __init__(self):
        self.records = []

    def record(self, **kwargs):
        self.records.append(kwargs)


def build(identity="netbox-prod", **policy_overrides):
    """A client whose TLS identity is stubbed to `identity`."""
    policy = {
        "path_prefixes": ("netbox/credentials",),
        "may_write": False,
        "may_delete": False,
    }
    policy.update(policy_overrides)

    config = BrokerConfig(
        openbao_url="https://bao.invalid:8200",
        instances={"netbox-prod": InstancePolicy(name="netbox-prod", **policy)},
    )
    vault = FakeVault()
    audit = RecordingAudit()
    app = create_app(config, vault=vault, audit=audit)

    # Stand in for the TLS handshake. Production identity comes from the peer
    # certificate and nowhere else; this replaces only that extraction.
    import broker.app as app_module

    original = app_module.identity_from_scope
    app_module.identity_from_scope = lambda scope: identity if identity is not None else _raise_identity()

    client = TestClient(app, raise_server_exceptions=False)
    client._restore = lambda: setattr(app_module, "identity_from_scope", original)
    return client, vault, audit


class TestAdministrationContract:
    def test_disabled_instance_is_refused_and_audited(self):
        client, vault, audit = build()
        try:
            response = client.get("/v1/administration/contract")
            assert response.status_code == 403
            assert vault.calls == []
            assert audit.records[-1]["operation"] == "administration_contract"
            assert audit.records[-1]["outcome"] == "denied"
        finally:
            client._restore()

    def test_enabled_instance_sees_only_its_reviewed_families(self):
        client, vault, audit = build(administration_families=("cluster", "access"))
        try:
            response = client.get("/v1/administration/contract")
            assert response.status_code == 200
            assert response.json()["families"] == ["access", "cluster"]
            assert {item["family"] for item in response.json()["operations"]} == {"access", "cluster"}
            assert vault.calls == []
            assert audit.records[-1]["outcome"] == "ok"
        finally:
            client._restore()

    def test_stale_contract_is_refused_before_openbao(self):
        client, vault, audit = build(administration_families=("cluster",))
        try:
            response = client.post(
                "/v1/administration/request",
                json={"contract_digest": "0" * 64, "operation": "seal_status", "arguments": {}},
            )
            assert response.status_code == 409
            assert vault.calls == []
            assert audit.records[-1]["reason"] == "contract digest mismatch"
        finally:
            client._restore()

    def test_disabled_family_is_refused_before_openbao(self):
        from broker.administration import CONTRACT_DIGEST

        client, vault, audit = build(administration_families=("access",))
        try:
            response = client.post(
                "/v1/administration/request",
                json={"contract_digest": CONTRACT_DIGEST, "operation": "seal_status", "arguments": {}},
            )
            assert response.status_code == 403
            assert vault.calls == []
            assert audit.records[-1]["reason"] == "administration family denied"
        finally:
            client._restore()

    def test_invalid_arguments_are_refused_before_openbao(self):
        from broker.administration import CONTRACT_DIGEST

        client, vault, audit = build(administration_families=("cluster",))
        try:
            response = client.post(
                "/v1/administration/request",
                json={
                    "contract_digest": CONTRACT_DIGEST,
                    "operation": "seal_status",
                    "arguments": {"path": "/sys/raw"},
                },
            )
            assert response.status_code == 422
            assert vault.calls == []
            assert audit.records[-1]["reason"] == "invalid administration operation"
        finally:
            client._restore()

    def test_reviewed_operation_reaches_openbao_once_and_is_audited(self):
        from broker.administration import CONTRACT_DIGEST

        client, vault, audit = build(administration_families=("cluster",))
        try:
            response = client.post(
                "/v1/administration/request",
                json={"contract_digest": CONTRACT_DIGEST, "operation": "seal_status", "arguments": {}},
            )
            assert response.status_code == 200
            assert response.json() == {"data": {"sealed": False}}
            assert vault.calls == [("administration", "seal_status", {})]
            assert audit.records[-1]["operation"] == "administration.seal_status"
            assert audit.records[-1]["outcome"] == "ok"
        finally:
            client._restore()

    def test_snapshot_routes_are_digest_and_family_bound(self):
        from broker.administration import CONTRACT_DIGEST

        client, vault, audit = build(administration_families=("cluster",))
        headers = {"X-Administration-Contract-Digest": CONTRACT_DIGEST}
        try:
            downloaded = client.get("/v1/administration/snapshot", headers=headers)
            assert downloaded.status_code == 200
            assert downloaded.content == b"snapshot"
            restored = client.post(
                "/v1/administration/snapshot?force=true",
                headers={**headers, "Content-Type": "application/octet-stream"},
                content=b"snapshot",
            )
            assert restored.status_code == 200
            assert vault.calls == [
                ("download_raft_snapshot",),
                ("restore_raft_snapshot", b"snapshot", 8, True),
            ]
            assert [record["outcome"] for record in audit.records] == ["ok", "ok"]
        finally:
            client._restore()

    def test_snapshot_refusal_never_reaches_openbao(self):
        client, vault, audit = build(administration_families=("access",))
        try:
            response = client.get(
                "/v1/administration/snapshot",
                headers={"X-Administration-Contract-Digest": "0" * 64},
            )
            assert response.status_code == 409
            assert vault.calls == []
            assert audit.records[-1]["reason"] == "contract digest mismatch"
        finally:
            client._restore()

    def test_unconsumed_snapshot_is_closed_and_audited(self):
        from broker.administration import CONTRACT_DIGEST

        class Download:
            declared_size = None

            def __init__(self):
                self.closed = False

            def chunks(self):
                yield b"snapshot"

            def close(self):
                self.closed = True

        policy = InstancePolicy(
            name="netbox-prod",
            path_prefixes=("netbox/credentials",),
            administration_families=("cluster",),
        )
        vault = FakeVault()
        download = Download()
        vault.download_raft_snapshot = lambda: download
        audit = RecordingAudit()
        app = create_app(BrokerConfig(openbao_url="https://bao.invalid", instances={}), vault, audit)
        endpoint = next(
            route.endpoint
            for route in app.routes
            if getattr(route, "path", "") == "/v1/administration/snapshot"
            and "GET" in getattr(route, "methods", set())
        )
        response = endpoint(Caller(policy, "request-id"), CONTRACT_DIGEST)

        async def receive():
            return {"type": "http.disconnect"}

        async def send(_message):
            raise RuntimeError("client disconnected before headers")

        with pytest.raises(RuntimeError, match="before headers"):
            asyncio.run(
                response(
                    {"type": "http", "asgi": {"spec_version": "2.4"}},
                    receive,
                    send,
                )
            )
        assert download.closed is True
        assert audit.records == [
            {
                "instance": "netbox-prod",
                "operation": "administration.download_raft_snapshot",
                "path": None,
                "outcome": "error",
                "reason": "snapshot stream not completed",
                "request_id": "request-id",
            }
        ]

    def test_snapshot_upload_stream_failure_is_audited(self):
        from broker.administration import CONTRACT_DIGEST

        class BrokenRequest:
            async def stream(self):
                raise RuntimeError("client disconnected")
                yield b""  # pragma: no cover

        policy = InstancePolicy(
            name="netbox-prod",
            path_prefixes=("netbox/credentials",),
            administration_families=("cluster",),
        )
        vault = FakeVault()
        audit = RecordingAudit()
        app = create_app(BrokerConfig(openbao_url="https://bao.invalid", instances={}), vault, audit)
        endpoint = next(
            route.endpoint
            for route in app.routes
            if getattr(route, "path", "") == "/v1/administration/snapshot"
            and "POST" in getattr(route, "methods", set())
        )
        with pytest.raises(RuntimeError, match="disconnected"):
            asyncio.run(
                endpoint(
                    request=BrokenRequest(),
                    force=False,
                    who=Caller(policy, "request-id"),
                    contract_digest=CONTRACT_DIGEST,
                    content_length=8,
                    content_type="application/octet-stream",
                )
            )
        assert audit.records[-1]["outcome"] == "error"
        assert audit.records[-1]["reason"] == "snapshot upload interrupted"
        assert vault.calls == []


def _raise_identity():
    from broker.identity import IdentityError

    raise IdentityError("No client certificate was presented.")


@pytest.fixture
def prod():
    client, vault, audit = build()
    yield client, vault, audit
    client._restore()


class TestPathTraversal:
    """
    A prefix check that `..` can walk out of is not a check. An instance
    confined to `netbox/` could otherwise reach `netbox/../production/` while
    `startswith` still passed.
    """

    @pytest.mark.parametrize(
        "path",
        [
            "netbox/credentials/../../production/root",
            "netbox/credentials/..",
            "../etc/passwd",
            "/absolute/path",
            "netbox/credentials/./x",
            "netbox//credentials",
            "netbox\\credentials\\x",
            "netbox/credentials/\x00evil",
            "",
        ],
    )
    def test_normalize_refuses(self, path):
        with pytest.raises(ValueError):
            normalize_path(path)

    def test_traversal_is_refused_without_touching_openbao(self, prod):
        client, vault, audit = prod

        response = client.post(
            "/v1/secret/read",
            json={"path": "netbox/credentials/../../production/root"},
        )

        assert response.status_code == 400
        assert vault.calls == [], "a refused request must never reach OpenBao"
        assert audit.records[-1]["outcome"] == "denied"


class TestPrefixEnforcement:
    def test_a_permitted_path_is_read(self, prod):
        client, vault, _audit = prod

        response = client.post("/v1/secret/read", json={"path": "netbox/credentials/abc"})

        assert response.status_code == 200
        assert response.json()["data"] == {"password": "hunter2"}
        assert vault.calls == [("read", "netbox/credentials/abc", None)]

    def test_a_path_outside_the_prefix_never_reaches_openbao(self, prod):
        client, vault, audit = prod

        response = client.post("/v1/secret/read", json={"path": "production/root"})

        assert response.status_code == 403
        assert vault.calls == []
        assert audit.records[-1]["reason"] == "outside permitted prefixes"

    def test_a_prefix_is_not_a_substring_match(self):
        """
        `netbox/credentials` must not authorize `netbox/credentials-evil`.
        Naive startswith on the bare prefix would let it through.
        """
        client, vault, _audit = build()
        try:
            response = client.post("/v1/secret/read", json={"path": "netbox/credentials-evil/x"})
            assert response.status_code == 403
            assert vault.calls == []
        finally:
            client._restore()

    def test_the_prefix_itself_is_permitted(self):
        client, vault, _audit = build()
        try:
            response = client.post("/v1/secret/read", json={"path": "netbox/credentials"})
            assert response.status_code == 200
            assert vault.calls
        finally:
            client._restore()


class TestOperationPermissions:
    def test_a_read_only_instance_cannot_write(self, prod):
        client, vault, audit = prod

        response = client.post(
            "/v1/secret/write",
            json={"path": "netbox/credentials/abc", "data": {"password": "x"}},
        )

        assert response.status_code == 403
        assert vault.calls == []
        assert audit.records[-1]["reason"] == "instance is read-only"

    def test_a_read_only_instance_cannot_delete(self, prod):
        client, vault, _audit = prod

        response = client.post("/v1/secret/delete", json={"path": "netbox/credentials/abc"})

        assert response.status_code == 403
        assert vault.calls == []

    def test_a_writer_can_write(self):
        client, vault, audit = build(may_write=True)
        try:
            response = client.post(
                "/v1/secret/write",
                json={"path": "netbox/credentials/abc", "data": {"password": "x"}, "cas": 0},
            )
            assert response.status_code == 200
            assert vault.calls == [("write", "netbox/credentials/abc", 0)]
            # The version OpenBao assigned, not None. A write is the one
            # operation that produces a version, so an audit record without it
            # is the one place the field would actually have been useful.
            assert audit.records[-1]["version"] == 1
        finally:
            client._restore()

    def test_writing_metadata_needs_write_permission(self, prod):
        """
        Metadata is not material, but it is still a mutation of the vault by a
        caller the operator declared read-only.
        """
        client, vault, _audit = prod

        response = client.post(
            "/v1/secret/metadata/write",
            json={"path": "netbox/credentials/abc", "custom_metadata": {"a": "b"}},
        )

        assert response.status_code == 403
        assert vault.calls == []


class TestIdentity:
    def test_no_client_certificate_is_a_401(self):
        client, vault, audit = build(identity=None)
        try:
            response = client.post("/v1/secret/read", json={"path": "netbox/credentials/abc"})
            assert response.status_code == 401
            assert vault.calls == []
        finally:
            client._restore()

    def test_a_valid_certificate_is_not_authorization(self):
        """
        A certificate signed by the right CA but naming an instance nobody
        configured is refused. If it were not, one mis-issued certificate would
        be full vault access.
        """
        client, vault, audit = build(identity="some-other-host")
        try:
            response = client.post("/v1/secret/read", json={"path": "netbox/credentials/abc"})
            assert response.status_code == 403
            assert vault.calls == []
            assert audit.records[-1]["reason"] == "instance not configured"
        finally:
            client._restore()
