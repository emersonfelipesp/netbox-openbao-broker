"""Versioned broker contract for NetBox-native OpenBao administration.

The HTTP surface stays compact, but the authority behind it is closed: callers
name one operation from this registry rather than supplying an arbitrary
OpenBao method or path.  The registry mirrors the public
``AdministrationBackend`` contract in netbox-openbao.  Later protocol handlers
may add typed fields to an operation, but they may not execute a name absent
from this file.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass
from typing import Any
from urllib.parse import urlsplit

__all__ = (
    "ADMINISTRATION_FAMILIES",
    "CONTRACT_DIGEST",
    "CONTRACT_VERSION",
    "IMPLEMENTED_OPERATIONS",
    "OperationContract",
    "contract_document",
    "operation_contract",
    "validate_arguments",
)

CONTRACT_VERSION = "1"
ADMINISTRATION_FAMILIES = frozenset(
    {
        "access",
        "authentication",
        "cluster",
        "finalization",
        "mounted-secrets",
        "secret-engines",
    }
)


@dataclass(frozen=True, slots=True)
class OperationContract:
    """One callable transport operation and its response framing."""

    name: str
    family: str
    framing: str = "json"


def _operations(family: str, *names: str) -> tuple[OperationContract, ...]:
    return tuple(OperationContract(name, family) for name in names)


OPERATIONS = (
    *_operations(
        "cluster",
        "discover_capabilities",
        "initialization_status",
        "seal_status",
        "leader_status",
        "ha_status",
        "raft_configuration",
        "initialize",
        "join_raft",
        "unseal",
        "seal",
        "remove_raft_peer",
    ),
    OperationContract("download_raft_snapshot", "cluster", "stream-download"),
    OperationContract("restore_raft_snapshot", "cluster", "stream-upload"),
    *_operations(
        "secret-engines",
        "execute_secret_engine_operation",
        "list_secret_engines",
        "read_secret_engine",
        "read_secret_engine_tuning",
        "enable_secret_engine",
        "tune_secret_engine",
        "remount_secret_engine",
        "secret_engine_remount_status",
        "disable_secret_engine",
    ),
    *_operations("mounted-secrets", "execute_mounted_operation"),
    *_operations(
        "authentication",
        "execute_authentication_operation",
        "list_auth_methods",
        "read_auth_method",
        "enable_auth_method",
        "tune_auth_method",
        "remount_auth_method",
        "remount_status",
        "disable_auth_method",
        "read_auth_config",
        "write_auth_config",
        "run_auth_resource",
        "issue_approle_secret_id",
        "read_approle_role_id",
        "write_approle_role_id",
        "lookup_approle_secret_id",
        "destroy_approle_secret_id",
        "authenticate",
        "oidc_start",
        "oidc_poll",
        "read_direct_oidc_role",
        "validate_mfa",
        "list_mfa_methods",
        "read_mfa_method",
        "write_mfa_method",
        "delete_mfa_method",
        "setup_totp",
        "destroy_totp_setup",
        "reset_totp_setup",
        "list_mfa_enforcements",
        "read_mfa_enforcement",
        "write_mfa_enforcement",
        "delete_mfa_enforcement",
        "token_operation",
    ),
    *_operations("access", "execute_access_operation"),
    *_operations("finalization", "execute_final_operation"),
)

_OPERATION_INDEX = {operation.name: operation for operation in OPERATIONS}
IMPLEMENTED_OPERATIONS = frozenset(
    {
        "discover_capabilities",
        "download_raft_snapshot",
        "execute_access_operation",
        "execute_final_operation",
        "execute_authentication_operation",
        "execute_secret_engine_operation",
        "ha_status",
        "initialization_status",
        "initialize",
        "join_raft",
        "leader_status",
        "raft_configuration",
        "remove_raft_peer",
        "restore_raft_snapshot",
        "seal",
        "seal_status",
        "unseal",
        "execute_mounted_operation",
    }
)

MAX_ARGUMENT_BYTES = 1_000_000
MAX_ARGUMENT_DEPTH = 8
MAX_ARGUMENT_ITEMS = 2_000
MAX_ARGUMENT_STRING = 512_000
_SERVER_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,255}$")

_ARGUMENT_KEYS = {
    "discover_capabilities": frozenset(),
    "execute_access_operation": frozenset({"material", "method", "path", "payload"}),
    "execute_authentication_operation": frozenset({"method", "path", "payload", "token"}),
    "execute_final_operation": frozenset({"material", "method", "path", "payload"}),
    "execute_secret_engine_operation": frozenset({"method", "path", "payload"}),
    "execute_mounted_operation": frozenset(
        {"body", "method", "mount_path", "operation_id", "path", "path_template", "query"}
    ),
    "ha_status": frozenset(),
    "initialization_status": frozenset(),
    "initialize": frozenset(
        {
            "pgp_keys",
            "recovery_pgp_keys",
            "recovery_shares",
            "recovery_threshold",
            "root_token_pgp_key",
            "secret_shares",
            "secret_threshold",
            "stored_shares",
        }
    ),
    "join_raft": frozenset(
        {
            "leader_api_addr",
            "leader_ca_cert",
            "leader_client_cert",
            "leader_client_key",
            "non_voter",
            "retry",
        }
    ),
    "leader_status": frozenset(),
    "raft_configuration": frozenset(),
    "remove_raft_peer": frozenset({"server_id"}),
    "seal": frozenset(),
    "seal_status": frozenset(),
    "unseal": frozenset({"key", "migrate", "reset"}),
}

_REQUIRED_ARGUMENT_KEYS = {
    "execute_access_operation": frozenset({"method", "path", "payload"}),
    "execute_authentication_operation": frozenset({"method", "path", "payload"}),
    "execute_final_operation": frozenset({"method", "path", "payload"}),
    "execute_secret_engine_operation": frozenset({"method", "path", "payload"}),
    "execute_mounted_operation": frozenset(
        {"body", "method", "mount_path", "operation_id", "path", "path_template", "query"}
    ),
    "initialize": frozenset({"secret_shares", "secret_threshold"}),
    "join_raft": frozenset({"leader_api_addr"}),
    "remove_raft_peer": frozenset({"server_id"}),
}


def _canonical_contract() -> dict:
    return {
        "version": CONTRACT_VERSION,
        "operations": [
            asdict(operation) for operation in OPERATIONS if operation.name in IMPLEMENTED_OPERATIONS
        ],
    }


CONTRACT_DIGEST = hashlib.sha256(
    json.dumps(_canonical_contract(), separators=(",", ":"), sort_keys=True).encode("utf-8")
).hexdigest()


def contract_document(enabled_families: tuple[str, ...]) -> dict:
    """Return safe contract metadata for one authorized broker instance."""

    enabled = set(enabled_families)
    operations = [
        operation
        for operation in OPERATIONS
        if operation.family in enabled and operation.name in IMPLEMENTED_OPERATIONS
    ]
    return {
        "version": CONTRACT_VERSION,
        "digest": CONTRACT_DIGEST,
        "families": sorted({operation.family for operation in operations}),
        "operations": [asdict(operation) for operation in operations],
    }


def operation_contract(name: str) -> OperationContract:
    """Resolve only an implemented operation from the closed registry."""

    operation = _OPERATION_INDEX.get(name)
    if operation is None or name not in IMPLEMENTED_OPERATIONS:
        raise ValueError("The administration operation is unsupported.")
    return operation


def _validate_value(value: Any, *, depth: int = 0) -> int:
    if depth > MAX_ARGUMENT_DEPTH:
        raise ValueError("The administration arguments are too deeply nested.")
    if value is None or isinstance(value, bool):
        return 1
    if isinstance(value, int) and not isinstance(value, bool):
        return 1
    if isinstance(value, str):
        if len(value) > MAX_ARGUMENT_STRING or any(ord(character) < 0x20 for character in value):
            raise ValueError("The administration arguments contain an invalid string.")
        return 1
    if isinstance(value, list):
        return _validate_list(value, depth)
    if isinstance(value, dict):
        return _validate_mapping(value, depth)
    raise ValueError("The administration arguments contain an unsupported value.")


def _validate_list(value: list, depth: int) -> int:
    if len(value) > MAX_ARGUMENT_ITEMS:
        raise ValueError("The administration arguments contain too many items.")
    return 1 + sum(_validate_value(item, depth=depth + 1) for item in value)


def _validate_mapping(value: dict, depth: int) -> int:
    if len(value) > MAX_ARGUMENT_ITEMS:
        raise ValueError("The administration arguments contain too many fields.")
    count = 1
    for key, item in value.items():
        if not isinstance(key, str) or not key or len(key) > 200:
            raise ValueError("The administration arguments contain an invalid field name.")
        count += _validate_value(item, depth=depth + 1)
    return count


def validate_arguments(operation: str, arguments: Any) -> dict:
    """Validate one operation's exact top-level shape and global resource bounds."""

    operation_contract(operation)
    if not isinstance(arguments, dict):
        raise ValueError("The administration arguments must be an object.")
    allowed = _ARGUMENT_KEYS[operation]
    if not set(arguments) <= allowed:
        raise ValueError("The administration arguments contain unsupported fields.")
    required = _REQUIRED_ARGUMENT_KEYS.get(operation, frozenset())
    if not required <= set(arguments):
        raise ValueError("The administration arguments are missing required fields.")
    if _validate_value(arguments) > MAX_ARGUMENT_ITEMS:
        raise ValueError("The administration arguments contain too many items.")
    encoded = json.dumps(arguments, separators=(",", ":"), allow_nan=False).encode("utf-8")
    if len(encoded) > MAX_ARGUMENT_BYTES:
        raise ValueError("The administration arguments are too large.")
    _validate_operation_arguments(operation, arguments)
    return dict(arguments)


def _positive_integer(arguments: dict, key: str, *, required: bool = False) -> None:
    value = arguments.get(key)
    if value is None and not required:
        return
    if not isinstance(value, int) or isinstance(value, bool) or not 1 <= value <= 10_000:
        raise ValueError(f"The administration field {key} is invalid.")


def _string_list(arguments: dict, key: str) -> None:
    value = arguments.get(key)
    if value is None:
        return
    if not isinstance(value, list) or len(value) > 10_000:
        raise ValueError(f"The administration field {key} is invalid.")
    if not all(isinstance(item, str) and 0 < len(item) <= 20_000 for item in value):
        raise ValueError(f"The administration field {key} is invalid.")


def _validate_initialize(arguments: dict) -> None:
    for key in ("secret_shares", "secret_threshold"):
        _positive_integer(arguments, key, required=True)
    for key in ("stored_shares", "recovery_shares", "recovery_threshold"):
        _positive_integer(arguments, key)
    if arguments["secret_threshold"] > arguments["secret_shares"]:
        raise ValueError("The administration initialization threshold is invalid.")
    for key in ("pgp_keys", "recovery_pgp_keys"):
        _string_list(arguments, key)
    root_key = arguments.get("root_token_pgp_key")
    if root_key is not None and (not isinstance(root_key, str) or not 1 <= len(root_key) <= 20_000):
        raise ValueError("The administration field root_token_pgp_key is invalid.")


def _validate_join(arguments: dict) -> None:
    address = arguments["leader_api_addr"]
    if not isinstance(address, str) or len(address) > 4_096:
        raise ValueError("The administration leader address is invalid.")
    parsed = urlsplit(address)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("The administration leader address is invalid.")
    if parsed.query or parsed.fragment or parsed.path not in {"", "/"}:
        raise ValueError("The administration leader address is invalid.")
    _validate_optional_strings(
        arguments, ("leader_ca_cert", "leader_client_cert", "leader_client_key"), 512_000
    )
    _validate_optional_booleans(arguments, ("retry", "non_voter"))


def _validate_optional_strings(arguments: dict, keys: tuple[str, ...], maximum: int) -> None:
    for key in keys:
        value = arguments.get(key)
        if value is not None and (not isinstance(value, str) or not 1 <= len(value) <= maximum):
            raise ValueError(f"The administration field {key} is invalid.")


def _validate_optional_booleans(arguments: dict, keys: tuple[str, ...]) -> None:
    for key in keys:
        if key in arguments and not isinstance(arguments[key], bool):
            raise ValueError(f"The administration field {key} is invalid.")


def _validate_unseal(arguments: dict) -> None:
    key = arguments.get("key")
    if key is not None and (not isinstance(key, str) or not 1 <= len(key) <= 20_000):
        raise ValueError("The administration unseal key is invalid.")
    for field in ("reset", "migrate"):
        if field in arguments and not isinstance(arguments[field], bool):
            raise ValueError(f"The administration field {field} is invalid.")
    if not key and not arguments.get("reset"):
        raise ValueError("The administration unseal request needs a key or reset.")


_NAME = r"[A-Za-z0-9][A-Za-z0-9_.@+-]{0,199}"
_UUID = r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}"
_LEASE = r"[A-Za-z0-9][A-Za-z0-9_.:/+-]{0,499}"
_HEADER = r"[A-Za-z][A-Za-z0-9-]{0,126}"

_ACCESS_PATHS = (
    (
        frozenset({"GET", "LIST", "POST", "DELETE"}),
        re.compile(rf"^/sys/policies/(?:acl|password)(?:/{_NAME})?$"),
    ),
    (frozenset({"GET"}), re.compile(rf"^/sys/policies/password/{_NAME}/generate$")),
    (
        frozenset({"GET", "LIST", "POST", "DELETE"}),
        re.compile(rf"^/identity/(?:entity|entity-alias|group|group-alias)(?:/id(?:/{_UUID})?)?$"),
    ),
    (frozenset({"POST"}), re.compile(r"^/identity/entity/merge$")),
    (
        frozenset({"GET", "LIST", "POST", "DELETE"}),
        re.compile(rf"^/identity/oidc/(?:client|key|assignment|provider|scope)(?:/{_NAME})?$"),
    ),
    (frozenset({"POST"}), re.compile(rf"^/identity/oidc/key/{_NAME}/rotate$")),
    (frozenset({"GET", "LIST", "POST", "DELETE"}), re.compile(rf"^/sys/namespaces(?:/{_NAME})?$")),
)

_FINAL_PATHS = (
    (frozenset({"LIST"}), re.compile(rf"^/sys/leases/lookup(?:/{_LEASE})?$")),
    (frozenset({"POST"}), re.compile(r"^/sys/leases/(?:lookup|renew|revoke)$")),
    (frozenset({"POST"}), re.compile(rf"^/sys/leases/(?:revoke-prefix|revoke-force)/{_LEASE}$")),
    (frozenset({"POST"}), re.compile(r"^/sys/wrapping/(?:wrap|lookup|rewrap|unwrap)$")),
    (frozenset({"POST"}), re.compile(r"^/sys/tools/hash/(?:sha2|sha3)-(?:224|256|384|512)$")),
    (frozenset({"POST"}), re.compile(r"^/sys/tools/random/(?:platform|all)$")),
    (frozenset({"POST"}), re.compile(r"^/auth/token/lookup$")),
    (frozenset({"LIST"}), re.compile(r"^/sys/config/ui/headers$")),
    (frozenset({"GET", "POST", "DELETE"}), re.compile(rf"^/sys/config/ui/headers/{_HEADER}$")),
)

_MOUNT = r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}"
_MOUNT_PATH_RE = re.compile(rf"^{_MOUNT}(?:/{_MOUNT})*$")
_AUTH_PATHS = (
    (frozenset({"LIST"}), re.compile(r"^/sys/auth$")),
    (frozenset({"GET", "POST", "DELETE"}), re.compile(rf"^/sys/auth/{_MOUNT}(?:/tune)?$")),
    (frozenset({"POST"}), re.compile(r"^/sys/remount$")),
    (frozenset({"GET"}), re.compile(rf"^/sys/remount/status/{_UUID}$")),
    (frozenset({"GET", "POST"}), re.compile(rf"^/auth/{_MOUNT}/config$")),
    (
        frozenset({"GET", "LIST", "POST", "DELETE"}),
        re.compile(rf"^/auth/{_MOUNT}/(?:roles|users|role|groups|certs|crls)(?:/{_NAME})?$"),
    ),
    (
        frozenset({"GET", "POST"}),
        re.compile(rf"^/auth/{_MOUNT}/role/{_NAME}/(?:secret-id|role-id)$"),
    ),
    (
        frozenset({"POST"}),
        re.compile(rf"^/auth/{_MOUNT}/role/{_NAME}/secret-id-accessor/(?:lookup|destroy)$"),
    ),
    (frozenset({"GET", "POST"}), re.compile(rf"^/auth/{_MOUNT}/login(?:/{_NAME})?$")),
    (frozenset({"POST"}), re.compile(rf"^/auth/{_MOUNT}/oidc/(?:auth_url|poll)$")),
    (frozenset({"POST"}), re.compile(r"^/sys/mfa/validate$")),
    (frozenset({"LIST"}), re.compile(r"^/identity/mfa/method$")),
    (frozenset({"GET"}), re.compile(rf"^/identity/mfa/method/{_UUID}$")),
    (
        frozenset({"POST", "DELETE"}),
        re.compile(rf"^/identity/mfa/method/(?:totp|duo|okta|pingid)(?:/{_UUID})?$"),
    ),
    (
        frozenset({"POST"}),
        re.compile(r"^/identity/mfa/method/totp/(?:generate|admin-generate|admin-destroy)$"),
    ),
    (frozenset({"LIST"}), re.compile(r"^/identity/mfa/login-enforcement$")),
    (
        frozenset({"GET", "POST", "DELETE"}),
        re.compile(rf"^/identity/mfa/login-enforcement/{_NAME}$"),
    ),
    (
        frozenset({"GET", "POST"}),
        re.compile(r"^/auth/token/(?:lookup|renew|revoke)-(?:self|accessor)$"),
    ),
)

_SUBMITTED_TOKEN_PATHS = (
    re.compile(r"^/auth/token/(?:lookup|renew|revoke)-self$"),
    re.compile(r"^/identity/mfa/method/totp/generate$"),
)
_UNAUTHENTICATED_PATHS = (
    re.compile(rf"^/auth/{_MOUNT}/login(?:/{_NAME})?$"),
    re.compile(rf"^/auth/{_MOUNT}/oidc/(?:auth_url|poll)$"),
    re.compile(r"^/sys/mfa/validate$"),
)

_SECRET_ENGINE_PATHS = (
    (frozenset({"LIST"}), re.compile(r"^/sys/mounts$")),
    (frozenset({"GET", "POST", "DELETE"}), re.compile(rf"^/sys/mounts/{_MOUNT}(?:/tune)?$")),
    (frozenset({"POST"}), re.compile(r"^/sys/remount$")),
    (frozenset({"GET"}), re.compile(rf"^/sys/remount/status/{_UUID}$")),
)
_OPERATION_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,199}$")
_TEMPLATE_SEGMENT_RE = re.compile(r"^(?:[A-Za-z0-9._~-]+|\{[A-Za-z][A-Za-z0-9_]{0,63}\})$")
_MOUNT_PLACEHOLDER_RE = re.compile(r"^\{[A-Za-z0-9][A-Za-z0-9_./]{0,450}_mount_path\}$")
_ACTUAL_SEGMENT_RE = re.compile(r"^[A-Za-z0-9._~:@+-]{1,500}$")


def _validate_reviewed_proxy(arguments: dict, paths: tuple) -> None:
    method = arguments.get("method")
    path = arguments.get("path")
    payload = arguments.get("payload")
    material = arguments.get("material", False)
    if not isinstance(method, str) or not isinstance(path, str) or not isinstance(payload, dict):
        raise ValueError("The administration proxy arguments are invalid.")
    if not isinstance(material, bool):
        raise ValueError("The administration proxy arguments are invalid.")
    if "%" in path or "\\" in path or "//" in path or ".." in path or "?" in path or "#" in path:
        raise ValueError("The administration path is invalid.")
    if not any(method in methods and pattern.fullmatch(path) for methods, pattern in paths):
        raise ValueError("The administration path is outside the reviewed contract.")


def _validate_authentication_proxy(arguments: dict) -> None:
    _validate_reviewed_proxy(arguments, _AUTH_PATHS)
    token = arguments.get("token")
    submitted = any(pattern.fullmatch(arguments["path"]) for pattern in _SUBMITTED_TOKEN_PATHS)
    if submitted and (not isinstance(token, str) or not 1 <= len(token) <= 20_000):
        raise ValueError("The administration request-scoped token is invalid.")
    if not submitted and token is not None:
        raise ValueError("The administration request-scoped token is not allowed.")


def _validate_mounted_operation(arguments: dict) -> None:
    method = arguments.get("method")
    path = arguments.get("path")
    template = arguments.get("path_template")
    mount = arguments.get("mount_path")
    operation_id = arguments.get("operation_id")
    query = arguments.get("query")
    body = arguments.get("body")
    if method not in {"GET", "LIST", "POST", "PUT", "PATCH", "DELETE"}:
        raise ValueError("The mounted operation method is invalid.")
    if not isinstance(mount, str) or len(mount) > 500 or not _MOUNT_PATH_RE.fullmatch(mount):
        raise ValueError("The mounted operation mount is invalid.")
    if not isinstance(operation_id, str) or not _OPERATION_ID_RE.fullmatch(operation_id):
        raise ValueError("The mounted operation ID is invalid.")
    if not isinstance(query, dict) or not isinstance(body, dict):
        raise ValueError("The mounted operation payload is invalid.")
    template_segments = _mounted_template_segments(template)
    actual_segments = _mounted_actual_segments(path)
    _validate_mounted_segments(template_segments, actual_segments, mount)


def _mounted_template_segments(template: Any) -> list[str]:
    if not isinstance(template, str) or not template.startswith("/"):
        raise ValueError("The mounted operation template is invalid.")
    closing_brace = template.find("}")
    if closing_brace < 2:
        raise ValueError("The mounted operation template is invalid.")
    mount_placeholder = template[1 : closing_brace + 1]
    remainder = template[closing_brace + 1 :]
    if remainder and not remainder.startswith("/"):
        raise ValueError("The mounted operation template is invalid.")
    segments = [mount_placeholder, *remainder.removeprefix("/").split("/")]
    if segments[-1] == "":
        segments.pop()
    if not 1 <= len(segments) <= 20 or not all(
        _TEMPLATE_SEGMENT_RE.fullmatch(segment) for segment in segments[1:]
    ):
        raise ValueError("The mounted operation template is invalid.")
    if not _MOUNT_PLACEHOLDER_RE.fullmatch(segments[0]):
        raise ValueError("The mounted operation template is invalid.")
    return segments


def _mounted_actual_segments(path: Any) -> list[str]:
    if not isinstance(path, str) or any(token in path for token in ("%", "\\", "//", "..", "?", "#")):
        raise ValueError("The mounted operation path is invalid.")
    segments = path.removeprefix("/").split("/")
    if not segments or not all(_ACTUAL_SEGMENT_RE.fullmatch(segment) for segment in segments):
        raise ValueError("The mounted operation path is invalid.")
    return segments


def _validate_mounted_segments(template_segments: list[str], actual_segments: list[str], mount: str) -> None:
    expected_placeholder = "{" + mount.replace("-", "_") + "_mount_path}"
    if template_segments[0] != expected_placeholder:
        raise ValueError("The mounted operation template does not match its mount.")
    mount_segments = mount.split("/")
    if actual_segments[: len(mount_segments)] != mount_segments:
        raise ValueError("The mounted operation path does not match its template.")
    remaining_actual = actual_segments[len(mount_segments) :]
    remaining_template = template_segments[1:]
    if "{path}" in remaining_template:
        path_index = remaining_template.index("{path}")
        suffix_count = len(remaining_template) - path_index - 1
        path_count = len(remaining_actual) - path_index - suffix_count
        if path_count < 0:
            raise ValueError("The mounted operation path does not match its template.")
        expanded = (
            remaining_template[:path_index]
            + ["{segment}"] * path_count
            + remaining_template[path_index + 1 :]
        )
    else:
        expanded = remaining_template
    if len(expanded) != len(remaining_actual):
        raise ValueError("The mounted operation path does not match its template.")
    for expected, actual in zip(expanded, remaining_actual, strict=True):
        if not expected.startswith("{") and expected != actual:
            raise ValueError("The mounted operation path does not match its template.")


def _validate_operation_arguments(operation: str, arguments: dict) -> None:
    if operation == "remove_raft_peer" and not _SERVER_ID_RE.fullmatch(arguments["server_id"]):
        raise ValueError("The administration server ID is invalid.")
    validators = {
        "initialize": _validate_initialize,
        "join_raft": _validate_join,
        "unseal": _validate_unseal,
        "execute_authentication_operation": _validate_authentication_proxy,
        "execute_mounted_operation": _validate_mounted_operation,
    }
    reviewed_paths = {
        "execute_access_operation": _ACCESS_PATHS,
        "execute_final_operation": _FINAL_PATHS,
        "execute_secret_engine_operation": _SECRET_ENGINE_PATHS,
    }
    if operation in validators:
        validators[operation](arguments)
    if operation in reviewed_paths:
        _validate_reviewed_proxy(arguments, reviewed_paths[operation])
