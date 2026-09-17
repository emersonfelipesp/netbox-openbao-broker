"""Closed, instance-scoped administration contract tests."""

from pathlib import Path

import pytest

from broker.administration import (
    ADMINISTRATION_FAMILIES,
    CONTRACT_DIGEST,
    CONTRACT_VERSION,
    IMPLEMENTED_OPERATIONS,
    OPERATIONS,
    contract_document,
    operation_contract,
    validate_arguments,
)
from broker.config import ConfigError, load_config


def _write_config(tmp_path: Path, families: str) -> Path:
    path = tmp_path / "broker.toml"
    path.write_text(
        """
[openbao]
url = "https://bao.example.invalid:8200"

[instances.netbox]
path_prefixes = ["netbox/credentials"]
administration_families = %s
""".strip()
        % families
    )
    return path


def test_contract_registry_is_unique_complete_and_digest_bound():
    names = [operation.name for operation in OPERATIONS]
    assert len(names) == len(set(names))
    assert {operation.family for operation in OPERATIONS} == ADMINISTRATION_FAMILIES
    assert len(CONTRACT_DIGEST) == 64
    assert CONTRACT_VERSION == "1"


def test_contract_digest_covers_only_the_executable_registry():
    expected = {operation.name for operation in OPERATIONS if operation.name in IMPLEMENTED_OPERATIONS}
    advertised = {
        item["name"] for item in contract_document(tuple(sorted(ADMINISTRATION_FAMILIES)))["operations"]
    }
    assert advertised == expected


def test_contract_document_exposes_only_enabled_families():
    document = contract_document(("cluster", "finalization"))
    assert document["families"] == ["cluster", "finalization"]
    assert document["digest"] == CONTRACT_DIGEST
    assert {item["family"] for item in document["operations"]} == {"cluster", "finalization"}
    assert "seal_status" in {item["name"] for item in document["operations"]}


def test_streaming_and_json_operations_are_advertised_with_their_framing():
    document = contract_document(("cluster", "authentication"))
    operations = {item["name"]: item for item in document["operations"]}
    assert operations["download_raft_snapshot"]["framing"] == "stream-download"
    assert operations["restore_raft_snapshot"]["framing"] == "stream-upload"
    names = set(operations)
    assert "list_auth_methods" not in names
    with pytest.raises(ValueError, match="unsupported"):
        operation_contract("list_auth_methods")


def test_exact_argument_shapes_fail_closed():
    assert validate_arguments("seal", {}) == {}
    assert validate_arguments("remove_raft_peer", {"server_id": "raft-1"}) == {"server_id": "raft-1"}
    with pytest.raises(ValueError, match="unsupported fields"):
        validate_arguments("seal", {"path": "/sys/raw"})
    with pytest.raises(ValueError, match="missing required"):
        validate_arguments("remove_raft_peer", {})
    with pytest.raises(ValueError, match="server ID"):
        validate_arguments("remove_raft_peer", {"server_id": "../raft-1"})


def test_nonfinite_and_deep_arguments_are_refused():
    with pytest.raises((ValueError, TypeError)):
        validate_arguments("unseal", {"key": float("nan")})
    value = "share"
    for _ in range(10):
        value = [value]
    with pytest.raises(ValueError, match="deeply nested"):
        validate_arguments("unseal", {"key": value})


def test_cluster_material_and_addresses_are_strictly_typed():
    assert (
        validate_arguments(
            "join_raft",
            {"leader_api_addr": "https://leader.example.invalid:8200", "retry": True},
        )["retry"]
        is True
    )
    with pytest.raises(ValueError, match="leader address"):
        validate_arguments("join_raft", {"leader_api_addr": "http://leader.example.invalid:8200"})
    with pytest.raises(ValueError, match="secret_threshold"):
        validate_arguments("initialize", {"secret_shares": 5, "secret_threshold": "3"})
    with pytest.raises(ValueError, match="threshold"):
        validate_arguments("initialize", {"secret_shares": 3, "secret_threshold": 5})
    with pytest.raises(ValueError, match="key or reset"):
        validate_arguments("unseal", {"reset": False})


@pytest.mark.parametrize(
    ("operation", "method", "path"),
    [
        ("execute_access_operation", "POST", "/identity/entity/merge"),
        ("execute_access_operation", "GET", "/identity/oidc/client/portal"),
        ("execute_access_operation", "DELETE", "/sys/namespaces/team"),
        ("execute_final_operation", "LIST", "/sys/leases/lookup/auth/team"),
        ("execute_final_operation", "POST", "/sys/tools/hash/sha2-256"),
        ("execute_final_operation", "POST", "/sys/wrapping/unwrap"),
        ("execute_final_operation", "GET", "/sys/config/ui/headers/X-Frame-Options"),
    ],
)
def test_reviewed_proxy_paths_are_exact(operation, method, path):
    result = validate_arguments(
        operation,
        {"method": method, "path": path, "payload": {}, "material": False},
    )
    assert result["path"] == path


@pytest.mark.parametrize(
    ("operation", "method", "path"),
    [
        ("execute_access_operation", "GET", "/sys/raw"),
        ("execute_access_operation", "GET", "/identity/entity/../group"),
        ("execute_access_operation", "PUT", "/identity/entity/id"),
        ("execute_final_operation", "POST", "/sys/tools/hash/md5"),
        ("execute_final_operation", "GET", "/sys/config/ui/headers"),
        ("execute_final_operation", "POST", "/auth/token/create"),
    ],
)
def test_unreviewed_proxy_paths_fail_closed(operation, method, path):
    with pytest.raises(ValueError, match="reviewed contract|path is invalid"):
        validate_arguments(operation, {"method": method, "path": path, "payload": {}})


def test_authentication_paths_and_request_scoped_tokens_are_closed():
    assert validate_arguments(
        "execute_authentication_operation",
        {
            "method": "POST",
            "path": "/auth/userpass/login/alice",
            "payload": {"password": "request-scoped"},
        },
    )["path"].endswith("/alice")
    assert (
        validate_arguments(
            "execute_authentication_operation",
            {
                "method": "GET",
                "path": "/auth/token/lookup-self",
                "payload": {},
                "token": "request-scoped-token",
            },
        )["token"]
        == "request-scoped-token"
    )
    with pytest.raises(ValueError, match="token is invalid"):
        validate_arguments(
            "execute_authentication_operation",
            {"method": "GET", "path": "/auth/token/lookup-self", "payload": {}},
        )
    with pytest.raises(ValueError, match="token is not allowed"):
        validate_arguments(
            "execute_authentication_operation",
            {
                "method": "GET",
                "path": "/auth/userpass/config",
                "payload": {},
                "token": "caller-token",
            },
        )
    with pytest.raises(ValueError, match="reviewed contract"):
        validate_arguments(
            "execute_authentication_operation",
            {"method": "POST", "path": "/auth/token/create", "payload": {}},
        )


def test_secret_engine_lifecycle_and_mounted_operations_are_closed():
    assert (
        validate_arguments(
            "execute_secret_engine_operation",
            {"method": "POST", "path": "/sys/mounts/team-kv", "payload": {"type": "kv"}},
        )["path"]
        == "/sys/mounts/team-kv"
    )
    mounted = {
        "method": "POST",
        "mount_path": "team-kv",
        "operation_id": "kv-v2-write",
        "path": "/team-kv/data/app",
        "path_template": "/{team_kv_mount_path}/data/{path}",
        "query": {},
        "body": {"data": {"value": "request-scoped"}},
    }
    assert validate_arguments("execute_mounted_operation", mounted)["operation_id"] == "kv-v2-write"
    assert (
        validate_arguments(
            "execute_mounted_operation",
            {
                **mounted,
                "path": "/team-kv/data/team/app",
                "path_template": "/{team_kv_mount_path}/data/{path}",
            },
        )["path"]
        == "/team-kv/data/team/app"
    )
    for mount_path, template, path in (
        ("team/platform", "/{team/platform_mount_path}/data/{path}", "/team/platform/data"),
        ("2.team", "/{2.team_mount_path}/metadata/{path}", "/2.team/metadata"),
    ):
        assert (
            validate_arguments(
                "execute_mounted_operation",
                {
                    **mounted,
                    "mount_path": mount_path,
                    "path": path,
                    "path_template": template,
                },
            )["path"]
            == path
        )
    for changed in (
        {"path": "/other/data/app"},
        {"path": "/team-kv/data/../sys"},
        {"path_template": "/sys/raw"},
        {"path_template": "/{other_mount_path}/data/{path}"},
        {"operation_id": "bad operation"},
    ):
        with pytest.raises(ValueError):
            validate_arguments("execute_mounted_operation", {**mounted, **changed})


def test_recursive_argument_item_limit_is_global():
    payload = {f"outer-{index}": {f"inner-{child}": child for child in range(50)} for index in range(50)}
    with pytest.raises(ValueError, match="too many items"):
        validate_arguments(
            "execute_final_operation",
            {"method": "POST", "path": "/sys/wrapping/lookup", "payload": payload},
        )


def test_secret_engine_proxy_rejects_raw_system_paths():
    with pytest.raises(ValueError, match="reviewed contract"):
        validate_arguments(
            "execute_secret_engine_operation",
            {"method": "GET", "path": "/sys/raw", "payload": {}},
        )


def test_administration_is_disabled_by_default(tmp_path):
    config = load_config(str(_write_config(tmp_path, "[]")))
    assert config.instance("netbox").administration_families == ()


@pytest.mark.parametrize(
    "families",
    [
        '["unknown"]',
        '["cluster", "cluster"]',
        '"cluster"',
        '["cluster", 7]',
    ],
)
def test_invalid_administration_families_fail_at_startup(tmp_path, families):
    with pytest.raises(ConfigError, match="administration families|administration_families"):
        load_config(str(_write_config(tmp_path, families)))
