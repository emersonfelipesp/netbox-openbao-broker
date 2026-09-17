"""OpenBao request semantics for the closed administration transport."""

from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest
import requests

from broker.config import BrokerConfig
from broker.vault import VaultClient, VaultError, VaultMutationUnknown, VaultUnavailable


@pytest.fixture
def client():
    return VaultClient(BrokerConfig(openbao_url="https://bao.example.invalid:8200"))


def response(status=200, payload=None):
    result = Mock()
    result.status_code = status
    result.is_redirect = 300 <= status < 400
    content = b"" if payload is None else __import__("json").dumps(payload).encode()
    result.content = content
    result.iter_content.return_value = [content] if content else []
    result.json.return_value = payload
    return result


def test_read_uses_server_owned_path_without_authentication(client):
    with patch(
        "broker.vault.requests.request",
        return_value=response(payload={"initialized": True}),
    ) as request:
        assert client.execute_administration("initialization_status", {}) == {"initialized": True}
    assert request.call_args.args[:2] == ("GET", "https://bao.example.invalid:8200/v1/sys/init")
    assert "X-Vault-Token" not in request.call_args.kwargs["headers"]
    assert request.call_args.kwargs["allow_redirects"] is False


def test_mutation_transport_failure_is_unknown(client):
    with patch("broker.vault.requests.request", side_effect=requests.ConnectionError):
        with pytest.raises(VaultMutationUnknown):
            client.execute_administration("initialize", {"secret_shares": 1, "secret_threshold": 1})


def test_read_transport_failure_is_unavailable(client):
    with patch("broker.vault.requests.request", side_effect=requests.ConnectionError):
        with pytest.raises(VaultUnavailable):
            client.execute_administration("seal_status", {})


def test_redirect_and_non_object_json_fail_closed(client):
    with patch("broker.vault.requests.request", return_value=response(status=302)):
        with pytest.raises(VaultError, match="redirects"):
            client.execute_administration("seal_status", {})
    with patch("broker.vault.requests.request", return_value=response(payload=[])):
        with pytest.raises(VaultError, match="unreadable"):
            client.execute_administration("seal_status", {})


def test_final_list_and_wrapping_headers_are_server_owned(client):
    client._client = SimpleNamespace(token="service-token")
    with patch("broker.vault.requests.request", return_value=response(payload={"data": {}})) as request:
        client.execute_administration(
            "execute_final_operation",
            {"method": "LIST", "path": "/sys/leases/lookup/auth/team", "payload": {}},
        )
    assert request.call_args.args[0] == "GET"
    assert request.call_args.kwargs["params"] == {"list": "true"}

    with patch("broker.vault.requests.request", return_value=response(payload={"wrap_info": {}})) as request:
        client.execute_administration(
            "execute_final_operation",
            {
                "method": "POST",
                "path": "/sys/wrapping/wrap",
                "payload": {"data": {"owner": "test"}, "ttl": "5m"},
            },
        )
    assert request.call_args.kwargs["json"] == {"owner": "test"}
    assert request.call_args.kwargs["headers"]["X-Vault-Wrap-TTL"] == "5m"


def test_authentication_selects_service_none_or_submitted_token(client):
    client._client = SimpleNamespace(token="service-token")
    with patch("broker.vault.requests.request", return_value=response(payload={"data": {}})) as request:
        client.execute_administration(
            "execute_authentication_operation",
            {"method": "GET", "path": "/auth/userpass/config", "payload": {}},
        )
    assert request.call_args.kwargs["headers"]["X-Vault-Token"] == "service-token"

    with patch("broker.vault.requests.request", return_value=response(payload={"auth": {}})) as request:
        client.execute_administration(
            "execute_authentication_operation",
            {
                "method": "POST",
                "path": "/auth/userpass/login/alice",
                "payload": {"password": "request-scoped"},
            },
        )
    assert "X-Vault-Token" not in request.call_args.kwargs["headers"]

    with patch("broker.vault.requests.request", return_value=response(payload={"data": {}})) as request:
        client.execute_administration(
            "execute_authentication_operation",
            {
                "method": "GET",
                "path": "/auth/token/lookup-self",
                "payload": {},
                "token": "submitted-token",
            },
        )
    assert request.call_args.kwargs["headers"]["X-Vault-Token"] == "submitted-token"


def test_mounted_operation_requires_matching_live_openapi_contract(client):
    client._client = SimpleNamespace(token="service-token")
    document = {
        "paths": {
            "/{team_kv_mount_path}/data/{path}": {
                "parameters": [
                    {
                        "in": "path",
                        "name": "team_kv_mount_path",
                        "required": True,
                        "schema": {"type": "string", "default": "team-kv"},
                    }
                ],
                "post": {
                    "operationId": "kv-v2-write",
                    "parameters": [
                        {"in": "query", "name": "cas"},
                    ],
                    "requestBody": {
                        "content": {"application/json": {"schema": {"properties": {"data": {}}}}}
                    },
                },
            }
        }
    }
    result = response(payload=document)
    written = response(payload={"data": {"version": 2}})
    with patch("broker.vault.requests.request", side_effect=[result, written]) as request:
        payload = client.execute_administration(
            "execute_mounted_operation",
            {
                "method": "POST",
                "mount_path": "team-kv",
                "operation_id": "kv-v2-write",
                "path": "/team-kv/data/app",
                "path_template": "/{team_kv_mount_path}/data/{path}",
                "query": {},
                "body": {"data": {"value": "request-scoped"}},
            },
        )
    assert payload == {"data": {"version": 2}}
    assert request.call_count == 2
    assert request.call_args.args[:2] == ("POST", "https://bao.example.invalid:8200/v1/team-kv/data/app")


def test_mounted_operation_accepts_real_mount_placeholder_and_nested_path(client):
    client._client = SimpleNamespace(token="service-token")
    document = {
        "paths": {
            "/{team_kv_mount_path}/data/{path}": {
                "parameters": [
                    {
                        "in": "path",
                        "name": "team_kv_mount_path",
                        "required": True,
                        "schema": {"type": "string", "default": "team-kv"},
                    }
                ],
                "post": {
                    "operationId": "kv-v2-write",
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "required": ["data"],
                                    "properties": {"data": {"type": "object", "additionalProperties": True}},
                                }
                            }
                        }
                    },
                },
            }
        }
    }
    with patch(
        "broker.vault.requests.request",
        side_effect=[response(payload=document), response(payload={"data": {"version": 2}})],
    ) as request:
        result = client.execute_administration(
            "execute_mounted_operation",
            {
                "method": "POST",
                "mount_path": "team-kv",
                "operation_id": "kv-v2-write",
                "path": "/team-kv/data/team/app",
                "path_template": "/{team_kv_mount_path}/data/{path}",
                "query": {},
                "body": {"data": {"value": "request-scoped"}},
            },
        )
    assert result == {"data": {"version": 2}}
    assert request.call_count == 2


def test_mounted_patch_uses_merge_patch_media_type(client):
    client._client = SimpleNamespace(token="service-token")
    document = {
        "paths": {
            "/{transit_mount_path}/keys/{name}": {
                "parameters": [
                    {
                        "in": "path",
                        "name": "transit_mount_path",
                        "required": True,
                        "schema": {"type": "string", "default": "transit"},
                    }
                ],
                "patch": {
                    "operationId": "transit-patch-key",
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {"min_decryption_version": {"type": "integer"}},
                                }
                            }
                        }
                    },
                },
            }
        }
    }
    with patch(
        "broker.vault.requests.request",
        side_effect=[response(payload=document), response(payload={})],
    ) as request:
        client.execute_administration(
            "execute_mounted_operation",
            {
                "method": "PATCH",
                "mount_path": "transit",
                "operation_id": "transit-patch-key",
                "path": "/transit/keys/app",
                "path_template": "/{transit_mount_path}/keys/{name}",
                "query": {},
                "body": {"min_decryption_version": 2},
            },
        )
    assert request.call_args.kwargs["headers"]["Content-Type"] == "application/merge-patch+json"


@pytest.mark.parametrize(
    ("query", "body", "message"),
    [
        ({"unreviewed": "yes"}, {}, "query"),
        ({}, {"unreviewed": True}, "body"),
    ],
)
def test_mounted_operation_rejects_fields_missing_from_live_openapi(client, query, body, message):
    client._client = SimpleNamespace(token="service-token")
    document = {
        "paths": {
            "/{team_kv_mount_path}/data/{path}": {
                "parameters": [
                    {
                        "in": "path",
                        "name": "team_kv_mount_path",
                        "required": True,
                        "schema": {"type": "string", "default": "team-kv"},
                    }
                ],
                "post": {
                    "operationId": "kv-v2-write",
                    "parameters": [
                        {"in": "query", "name": "cas"},
                    ],
                    "requestBody": {
                        "content": {"application/json": {"schema": {"properties": {"data": {}}}}}
                    },
                },
            }
        }
    }
    with patch("broker.vault.requests.request", return_value=response(payload=document)) as request:
        with pytest.raises(VaultError, match=message):
            client.execute_administration(
                "execute_mounted_operation",
                {
                    "method": "POST",
                    "mount_path": "team-kv",
                    "operation_id": "kv-v2-write",
                    "path": "/team-kv/data/app",
                    "path_template": "/{team_kv_mount_path}/data/{path}",
                    "query": query,
                    "body": body,
                },
            )
    assert request.call_count == 1


@pytest.mark.parametrize(
    "body",
    [
        {},
        {"data": "not-an-object"},
        {"data": {"values": [1, "wrong"]}},
        {"data": {"values": [1, 2]}, "mode": "invalid"},
    ],
)
def test_mounted_operation_rejects_live_schema_violations(client, body):
    client._client = SimpleNamespace(token="service-token")
    document = {
        "components": {
            "schemas": {
                "WriteRequest": {
                    "type": "object",
                    "required": ["data", "mode"],
                    "properties": {
                        "data": {
                            "type": "object",
                            "required": ["values"],
                            "properties": {"values": {"type": "array", "items": {"type": "integer"}}},
                        },
                        "mode": {"type": "string", "enum": ["safe"]},
                    },
                }
            }
        },
        "paths": {
            "/{custom_mount_path}/write": {
                "parameters": [
                    {
                        "in": "path",
                        "name": "custom_mount_path",
                        "required": True,
                        "schema": {"type": "string", "default": "custom"},
                    }
                ],
                "post": {
                    "operationId": "custom-write",
                    "requestBody": {
                        "content": {
                            "application/json": {"schema": {"$ref": "#/components/schemas/WriteRequest"}}
                        }
                    },
                },
            }
        },
    }
    with patch("broker.vault.requests.request", return_value=response(payload=document)) as request:
        with pytest.raises(VaultError, match="schema|required"):
            client.execute_administration(
                "execute_mounted_operation",
                {
                    "method": "POST",
                    "mount_path": "custom",
                    "operation_id": "custom-write",
                    "path": "/custom/write",
                    "path_template": "/{custom_mount_path}/write",
                    "query": {},
                    "body": body,
                },
            )
    assert request.call_count == 1


@pytest.mark.parametrize(
    ("keyword", "schemas", "value", "accepted"),
    [
        ("oneOf", [{"type": "integer"}, {"type": "number"}], 2, False),
        ("oneOf", [{"type": "integer"}, {"type": "string"}], 2, True),
        ("anyOf", [{"type": "integer"}, {"type": "number"}], 2, True),
    ],
)
def test_mounted_operation_honors_openapi_composition(client, keyword, schemas, value, accepted):
    client._client = SimpleNamespace(token="service-token")
    document = {
        "paths": {
            "/{custom_mount_path}/write": {
                "parameters": [
                    {
                        "in": "path",
                        "name": "custom_mount_path",
                        "required": True,
                        "schema": {"type": "string", "default": "custom"},
                    }
                ],
                "post": {
                    "operationId": "custom-write",
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "required": ["value"],
                                    "properties": {"value": {keyword: schemas}},
                                }
                            }
                        }
                    },
                },
            }
        }
    }
    calls = [response(payload=document), response(payload={})]
    with patch("broker.vault.requests.request", side_effect=calls) as request:
        arguments = {
            "method": "POST",
            "mount_path": "custom",
            "operation_id": "custom-write",
            "path": "/custom/write",
            "path_template": "/{custom_mount_path}/write",
            "query": {},
            "body": {"value": value},
        }
        if accepted:
            client.execute_administration("execute_mounted_operation", arguments)
            assert request.call_count == 2
        else:
            with pytest.raises(VaultError, match="schema"):
                client.execute_administration("execute_mounted_operation", arguments)
            assert request.call_count == 1


def test_administration_json_is_stream_bounded_and_closed(client):
    client._client = SimpleNamespace(token="service-token")
    oversized = response()
    oversized.iter_content.return_value = [b"x" * 1_000_001, b"x" * 1_000_001]
    with patch("broker.vault.requests.request", return_value=oversized):
        with pytest.raises(VaultError, match="oversized"):
            client.execute_administration("seal_status", {})
    oversized.close.assert_called_once_with()


def test_mounted_operation_contract_mismatch_never_executes_target(client):
    client._client = SimpleNamespace(token="service-token")
    document = {
        "paths": {
            "/{team_kv_mount_path}/data/{path}": {
                "parameters": [
                    {
                        "in": "path",
                        "name": "team_kv_mount_path",
                        "required": True,
                        "schema": {"type": "string", "default": "team-kv"},
                    }
                ],
                "post": {"operationId": "different-operation"},
            }
        }
    }
    with patch("broker.vault.requests.request", return_value=response(payload=document)) as request:
        with pytest.raises(VaultError, match="not advertised"):
            client.execute_administration(
                "execute_mounted_operation",
                {
                    "method": "POST",
                    "mount_path": "team-kv",
                    "operation_id": "kv-v2-write",
                    "path": "/team-kv/data/app",
                    "path_template": "/{team_kv_mount_path}/data/{path}",
                    "query": {},
                    "body": {"data": {}},
                },
            )
    assert request.call_count == 1


def test_mounted_operation_cannot_borrow_another_mount_contract(client):
    client._client = SimpleNamespace(token="service-token")
    document = {
        "paths": {
            "/{team_kv_mount_path}/data/{path}": {
                "parameters": [
                    {
                        "in": "path",
                        "name": "team_kv_mount_path",
                        "required": True,
                        "schema": {"type": "string", "default": "team_kv"},
                    }
                ],
                "post": {"operationId": "kv-v2-write"},
            }
        }
    }
    arguments = {
        "method": "POST",
        "mount_path": "team-kv",
        "operation_id": "kv-v2-write",
        "path": "/team-kv/data/app",
        "path_template": "/{team_kv_mount_path}/data/{path}",
        "query": {},
        "body": {},
    }
    with patch("broker.vault.requests.request", return_value=response(payload=document)) as request:
        with pytest.raises(VaultError, match="does not match its mount"):
            client.execute_administration("execute_mounted_operation", arguments)
    assert request.call_count == 1


@pytest.mark.parametrize(
    "parameters",
    [
        [],
        [
            {
                "in": "path",
                "name": "team_kv_mount_path",
                "required": False,
                "schema": {"type": "string", "default": "team-kv"},
            }
        ],
        [
            {
                "in": "path",
                "name": "team_kv_mount_path",
                "required": True,
                "schema": {"type": "integer", "default": "team-kv"},
            }
        ],
        [
            {
                "in": "path",
                "name": "team_kv_mount_path",
                "required": True,
                "schema": {"type": "string", "default": "team-kv"},
            },
            {
                "in": "path",
                "name": "team_kv_mount_path",
                "required": True,
                "schema": {"type": "string", "default": "team-kv"},
            },
        ],
    ],
)
def test_mounted_operation_rejects_malformed_mount_parameters_before_target(client, parameters):
    client._client = SimpleNamespace(token="service-token")
    document = {
        "paths": {
            "/{team_kv_mount_path}/data/{path}": {
                "parameters": parameters,
                "post": {"operationId": "kv-v2-write"},
            }
        }
    }
    with patch("broker.vault.requests.request", return_value=response(payload=document)) as request:
        with pytest.raises(VaultError, match="invalid mounted operation|does not match"):
            client.execute_administration(
                "execute_mounted_operation",
                {
                    "method": "POST",
                    "mount_path": "team-kv",
                    "operation_id": "kv-v2-write",
                    "path": "/team-kv/data/app",
                    "path_template": "/{team_kv_mount_path}/data/{path}",
                    "query": {},
                    "body": {},
                },
            )
    assert request.call_count == 1


def test_snapshot_download_is_bounded_uncompressed_and_closed(client):
    client._client = SimpleNamespace(token="service-token")
    result = response()
    result.headers = {"Content-Length": "8", "Content-Encoding": "identity"}
    result.iter_content.return_value = [b"snap", b"shot"]
    with patch("broker.vault.requests.get", return_value=result) as request:
        download = client.download_raft_snapshot()
        assert b"".join(download.chunks()) == b"snapshot"
    assert request.call_args.kwargs["headers"]["Accept-Encoding"] == "identity"
    assert request.call_args.kwargs["stream"] is True
    result.close.assert_called_once_with()


def test_snapshot_download_rejects_invalid_declared_size_and_closes(client):
    client._client = SimpleNamespace(token="service-token")
    result = response()
    result.headers = {"Content-Length": "0"}
    with patch("broker.vault.requests.get", return_value=result):
        with pytest.raises(VaultError, match="invalid snapshot"):
            client.download_raft_snapshot()
    result.close.assert_called_once_with()


def test_snapshot_restore_is_single_attempt_and_unknown_on_transport_failure(client):
    client._client = SimpleNamespace(token="service-token")
    stream = __import__("io").BytesIO(b"snapshot")
    with patch("broker.vault.requests.post", side_effect=requests.ConnectionError) as request:
        with pytest.raises(VaultMutationUnknown):
            client.restore_raft_snapshot(stream, 8, force=True)
    assert request.call_count == 1
    assert request.call_args.args[0].endswith("/v1/sys/storage/raft/snapshot-force")
    assert request.call_args.kwargs["headers"]["Content-Length"] == "8"
