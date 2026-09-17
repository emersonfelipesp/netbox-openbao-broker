"""
The OpenBao side of the broker.

This module is the only place the AppRole exists in the entire system. That is
the whole proposition: NetBox holds a client certificate that lets it *ask*,
and this process holds the credential that can actually *read*.

Mirrors `netbox-openbao`'s `SecretBackend` operations exactly, because the
plugin's `BrokerBackend` is a transport swap and nothing more. Any divergence
in semantics here would show up as behaviour that differs depending on whether
broker mode is switched on, which is the last thing you want from an optional
deployment mode.
"""

from __future__ import annotations

import json
import logging
import threading
from collections.abc import Iterator
from datetime import datetime

import requests

from .config import BrokerConfig, ConfigError, read_secret_env

__all__ = ("VaultError", "VaultMisconfigured", "VaultMutationUnknown", "VaultUnavailable", "VaultClient")

logger = logging.getLogger(__name__)

TOKEN_LEASE_FRACTION = 0.8
MAX_SNAPSHOT_BYTES = 512 * 1024 * 1024
SNAPSHOT_CHUNK_BYTES = 64 * 1024
MAX_ADMINISTRATION_RESPONSE_BYTES = 2_000_000
MAX_ADMINISTRATION_SCHEMA_ITEMS = 2_000


class SnapshotDownload:
    """A bounded, closeable streaming OpenBao snapshot response."""

    def __init__(self, response: requests.Response, declared_size: int | None):
        self.response = response
        self.declared_size = declared_size

    def chunks(self) -> Iterator[bytes]:
        observed = 0
        try:
            for chunk in self.response.iter_content(SNAPSHOT_CHUNK_BYTES):
                if not chunk:
                    continue
                observed += len(chunk)
                if observed > MAX_SNAPSHOT_BYTES:
                    raise VaultError("OpenBao returned an oversized snapshot.")
                yield chunk
            if observed == 0:
                raise VaultError("OpenBao returned an empty snapshot.")
            if self.declared_size is not None and observed != self.declared_size:
                raise VaultError("OpenBao returned an incomplete snapshot.")
        except requests.RequestException:
            raise VaultUnavailable() from None
        finally:
            self.response.close()

    def close(self) -> None:
        self.response.close()


class VaultError(Exception):
    """
    A failure talking to OpenBao, carrying no server-supplied text.

    OpenBao's error bodies can enumerate policy rules. Relaying one to the
    caller would hand a NetBox-side attacker a map of what this broker's
    AppRole is permitted to do — which is precisely the information the broker
    exists to keep on this side of the boundary.
    """

    default_message = "OpenBao request failed."
    status_code = 502

    def __init__(self, message: str | None = None):
        super().__init__(message or self.default_message)


class VaultNotFound(VaultError):
    default_message = "No secret at that path."
    status_code = 404


class VaultConflict(VaultError):
    default_message = "The secret was modified concurrently; the write was refused."
    status_code = 409


class VaultUnavailable(VaultError):
    default_message = "OpenBao is unreachable or sealed."
    status_code = 503


class VaultMutationUnknown(VaultError):
    """A mutation may have reached OpenBao, so automatic retry is unsafe."""

    default_message = "The OpenBao mutation outcome is unknown. Do not retry automatically."
    status_code = 503


class VaultMisconfigured(VaultError):
    """
    The broker's own credential material is missing or unreadable.

    Distinct from `VaultUnavailable` because the cause is entirely on this side
    of the connection — OpenBao may be perfectly healthy. The caller is told
    only that the broker cannot serve the request; the actual reason names an
    operator's file path and belongs in this process's log, not in a response
    to NetBox.
    """

    default_message = "The broker cannot authenticate to OpenBao."
    status_code = 503


class VaultClient:
    """Authenticated access to one KV mount, using the broker's AppRole."""

    def __init__(self, config: BrokerConfig):
        self.config = config
        self._client = None
        self._lock = threading.Lock()

    # -- authentication -------------------------------------------------

    def _login(self):
        import hvac

        prefix = self.config.env_prefix
        verify = self.config.ca_cert_path or self.config.tls_verify

        client = hvac.Client(
            url=self.config.openbao_url,
            namespace=self.config.namespace,
            verify=verify,
            timeout=30,
        )

        if self.config.auth_method == "token":
            token = read_secret_env(f"{prefix}_TOKEN")
            if not token:
                raise ConfigError(f"Token auth requires {prefix}_TOKEN in the environment.")
            client.token = token
            return client

        role_id = read_secret_env(f"{prefix}_ROLE_ID")
        secret_id = read_secret_env(f"{prefix}_SECRET_ID")
        if not role_id or not secret_id:
            raise ConfigError(
                f"AppRole auth requires {prefix}_ROLE_ID and {prefix}_SECRET_ID (or their _FILE "
                f"equivalents) in the environment."
            )

        try:
            response = client.auth.approle.login(role_id=role_id, secret_id=secret_id)
        except Exception as exc:
            raise self._translate(exc, "authentication") from None

        token = ((response or {}).get("auth") or {}).get("client_token")
        if not token:
            raise VaultError("OpenBao returned no client token.")
        client.token = token
        return client

    def check_credentials(self) -> None:
        """
        Verify the AppRole material is present and readable, without a network call.

        Called at startup. Authentication itself stays lazy — coupling process
        start to OpenBao's availability would mean a restart during a vault
        maintenance window leaves the broker down after the vault returns — but
        a *misconfiguration* has no reason to wait for the first request to
        surface. Before this existed, a broker with an unreadable SecretID
        started, reported healthy, and produced a 500 the first time NetBox
        asked for anything.

        Raises `ConfigError`.
        """
        prefix = self.config.env_prefix
        if self.config.auth_method == "token":
            names = (f"{prefix}_TOKEN",)
        else:
            names = (f"{prefix}_ROLE_ID", f"{prefix}_SECRET_ID")

        missing = [name for name in names if not read_secret_env(name)]
        if missing:
            raise ConfigError(
                f"{self.config.auth_method} auth requires {' and '.join(missing)} "
                f"(or the matching _FILE variable) in the environment."
            )

    def _get(self):
        # A single long-lived client under a lock. The broker is I/O-bound and
        # low-volume by design; a connection pool would be complexity without a
        # workload to justify it.
        with self._lock:
            if self._client is None:
                try:
                    self._client = self._login()
                except ConfigError as exc:
                    # Startup already checked this, so reaching here means the
                    # material became unreadable while running — a rotation that
                    # went wrong, most likely. That is a broker fault, and it
                    # must be reported and audited as one rather than escaping
                    # as an unhandled exception, which would produce a 500 with
                    # no audit record at all.
                    logger.error("Broker credential material is unusable: %s", exc)
                    raise VaultMisconfigured() from None
            return self._client

    def invalidate(self) -> None:
        with self._lock:
            self._client = None

    # -- error translation ----------------------------------------------

    def _translate(self, exc: Exception, context: str) -> VaultError:
        try:
            import hvac.exceptions as hvac_exc
        except ImportError:
            return VaultError()

        if isinstance(exc, (hvac_exc.Forbidden, hvac_exc.Unauthorized)):
            # The broker's own AppRole was refused. That is an operator
            # problem here, not something the caller can act on, so it is
            # logged locally and reported as a bare failure.
            logger.warning("OpenBao denied the broker AppRole during %s", context)
            self.invalidate()
            return VaultError("The broker could not authenticate to OpenBao.")

        if isinstance(exc, hvac_exc.InvalidPath):
            return VaultNotFound()

        if isinstance(exc, hvac_exc.InvalidRequest):
            text = str(exc).lower()
            if "check-and-set" in text or "cas" in text.split():
                return VaultConflict()
            logger.warning("OpenBao rejected a %s request", context)
            return VaultError("OpenBao rejected the request.")

        if isinstance(exc, (hvac_exc.VaultDown, hvac_exc.VaultNotInitialized)):
            return VaultUnavailable()

        logger.warning("OpenBao %s failed: %s", context, type(exc).__name__)
        return VaultUnavailable()

    # -- operations -----------------------------------------------------

    def read(self, path: str, version: int | None = None) -> dict:
        client = self._get()
        try:
            response = client.secrets.kv.v2.read_secret_version(
                path=path,
                version=version,
                mount_point=self.config.kv_mount,
                raise_on_deleted_version=True,
            )
        except Exception as exc:
            raise self._translate(exc, "read") from None
        return response["data"]["data"]

    def write(self, path: str, data: dict, cas: int | None = None) -> int:
        client = self._get()
        try:
            response = client.secrets.kv.v2.create_or_update_secret(
                path=path,
                secret=data,
                cas=cas,
                mount_point=self.config.kv_mount,
            )
        except Exception as exc:
            raise self._translate(exc, "write") from None
        return response["data"]["version"]

    def delete(self, path: str, versions: list[int] | None = None) -> None:
        client = self._get()
        try:
            if versions:
                client.secrets.kv.v2.delete_secret_versions(
                    path=path,
                    versions=versions,
                    mount_point=self.config.kv_mount,
                )
            else:
                client.secrets.kv.v2.delete_metadata_and_all_versions(
                    path=path,
                    mount_point=self.config.kv_mount,
                )
        except Exception as exc:
            raise self._translate(exc, "delete") from None

    def read_metadata(self, path: str) -> dict:
        client = self._get()
        try:
            response = client.secrets.kv.v2.read_secret_metadata(
                path=path,
                mount_point=self.config.kv_mount,
            )
        except Exception as exc:
            raise self._translate(exc, "metadata read") from None
        return response.get("data") or {}

    def set_metadata(self, path: str, custom_metadata: dict) -> None:
        client = self._get()
        try:
            client.secrets.kv.v2.update_metadata(
                path=path,
                custom_metadata=custom_metadata,
                mount_point=self.config.kv_mount,
            )
        except Exception as exc:
            raise self._translate(exc, "metadata write") from None

    def list_versions(self, path: str) -> list[dict]:
        metadata = self.read_metadata(path)
        versions = [
            {
                "version": int(number),
                "created_time": meta.get("created_time"),
                "deletion_time": meta.get("deletion_time") or None,
                "destroyed": bool(meta.get("destroyed")),
            }
            for number, meta in (metadata.get("versions") or {}).items()
        ]
        versions.sort(key=lambda v: v["version"], reverse=True)
        return versions

    def health(self) -> dict:
        import hvac

        client = hvac.Client(
            url=self.config.openbao_url,
            namespace=self.config.namespace,
            verify=self.config.ca_cert_path or self.config.tls_verify,
            timeout=10,
        )
        try:
            response = client.sys.read_health_status(method="GET")
        except Exception:
            return {"reachable": False, "sealed": None}

        payload = response if isinstance(response, dict) else {}
        if hasattr(response, "json"):
            try:
                payload = response.json()
            except ValueError:
                payload = {}
        return {
            "reachable": True,
            "sealed": bool(payload.get("sealed")),
            "version": payload.get("version"),
        }

    def _administration_headers(self, *, authenticated: bool, token: str = "") -> dict[str, str]:
        headers = {"Accept": "application/json"}
        if self.config.namespace:
            headers["X-Vault-Namespace"] = self.config.namespace
        if token:
            headers["X-Vault-Token"] = token
        elif authenticated:
            headers["X-Vault-Token"] = self._get().token
        return headers

    def _administration_request(
        self,
        method: str,
        path: str,
        *,
        authenticated: bool,
        payload: dict | None = None,
        params: dict | None = None,
        extra_headers: dict | None = None,
        token: str = "",
        mutation: bool = False,
    ) -> dict:
        url = f"{self.config.openbao_url.rstrip('/')}/v1{path}"
        try:
            headers = self._administration_headers(authenticated=authenticated, token=token)
            headers.update(extra_headers or {})
            response = requests.request(
                method,
                url,
                headers=headers,
                json=payload,
                params=params,
                timeout=30,
                verify=self.config.ca_cert_path or self.config.tls_verify,
                allow_redirects=False,
                stream=True,
            )
        except requests.RequestException:
            if mutation:
                raise VaultMutationUnknown() from None
            raise VaultUnavailable() from None
        try:
            if response.is_redirect:
                if mutation:
                    raise VaultMutationUnknown() from None
                raise VaultError("OpenBao redirects are refused.")
            if response.status_code >= 400:
                error = self._translate_http_status(response.status_code)
                if mutation and response.status_code >= 500:
                    raise VaultMutationUnknown() from None
                raise error
            return self._administration_json(response, mutation=mutation)
        finally:
            response.close()

    @staticmethod
    def _administration_json(response: requests.Response, *, mutation: bool) -> dict:
        if response.status_code == 204:
            return {}
        content = bytearray()
        try:
            for chunk in response.iter_content(SNAPSHOT_CHUNK_BYTES):
                content.extend(chunk)
                if len(content) > MAX_ADMINISTRATION_RESPONSE_BYTES:
                    break
        except requests.RequestException:
            if mutation:
                raise VaultMutationUnknown() from None
            raise VaultUnavailable() from None
        if not content:
            return {}
        if len(content) > MAX_ADMINISTRATION_RESPONSE_BYTES:
            if mutation:
                raise VaultMutationUnknown() from None
            raise VaultError("OpenBao returned an oversized response.")
        try:
            result = json.loads(content)
        except (TypeError, ValueError):
            if mutation:
                raise VaultMutationUnknown() from None
            raise VaultError("OpenBao returned an unreadable response.") from None
        if not isinstance(result, dict):
            if mutation:
                raise VaultMutationUnknown()
            raise VaultError("OpenBao returned an unreadable response.")
        return result

    def download_raft_snapshot(self) -> SnapshotDownload:
        """Open one bounded, uncompressed snapshot stream."""

        url = f"{self.config.openbao_url.rstrip('/')}/v1/sys/storage/raft/snapshot"
        headers = self._administration_headers(authenticated=True)
        headers["Accept-Encoding"] = "identity"
        try:
            response = requests.get(
                url,
                headers=headers,
                timeout=(30, 300),
                verify=self.config.ca_cert_path or self.config.tls_verify,
                allow_redirects=False,
                stream=True,
            )
        except requests.RequestException:
            raise VaultUnavailable() from None
        if response.is_redirect:
            response.close()
            raise VaultError("OpenBao redirects are refused.")
        if response.status_code >= 400:
            error = self._translate_http_status(response.status_code)
            response.close()
            raise error
        if response.headers.get("Content-Encoding", "").strip().lower() not in {"", "identity"}:
            response.close()
            raise VaultError("OpenBao returned an invalid snapshot response.")
        try:
            declared_size = self._snapshot_size(response.headers.get("Content-Length"))
        except VaultError:
            response.close()
            raise
        return SnapshotDownload(response, declared_size)

    def restore_raft_snapshot(self, stream, size: int, *, force: bool = False) -> None:
        """Send one already-bounded snapshot stream without automatic retry."""

        if isinstance(size, bool) or not 0 < size <= MAX_SNAPSHOT_BYTES:
            raise VaultError("The snapshot upload is outside the allowed size.")
        suffix = "-force" if force else ""
        url = f"{self.config.openbao_url.rstrip('/')}/v1/sys/storage/raft/snapshot{suffix}"
        headers = self._administration_headers(authenticated=True)
        headers.update({"Content-Type": "application/octet-stream", "Content-Length": str(size)})
        try:
            response = requests.post(
                url,
                headers=headers,
                data=stream,
                timeout=(30, 300),
                verify=self.config.ca_cert_path or self.config.tls_verify,
                allow_redirects=False,
            )
        except requests.RequestException:
            raise VaultMutationUnknown() from None
        try:
            if response.is_redirect or response.status_code >= 500:
                raise VaultMutationUnknown()
            if response.status_code >= 400:
                raise self._translate_http_status(response.status_code)
        finally:
            response.close()

    @staticmethod
    def _snapshot_size(raw_size: str | None) -> int | None:
        if raw_size is None:
            return None
        try:
            size = int(raw_size)
        except (TypeError, ValueError):
            raise VaultError("OpenBao returned an invalid snapshot response.") from None
        if not 0 < size <= MAX_SNAPSHOT_BYTES:
            raise VaultError("OpenBao returned an invalid snapshot response.")
        return size

    @staticmethod
    def _translate_http_status(status: int) -> VaultError:
        if status == 404:
            return VaultNotFound()
        if status == 409:
            return VaultConflict()
        if status in {429, 500, 502, 503, 504}:
            return VaultUnavailable()
        return VaultError("OpenBao rejected the request.")

    def execute_administration(self, operation: str, arguments: dict) -> dict:
        """Execute one closed cluster-family operation using server-owned paths."""

        if operation in {
            "execute_access_operation",
            "execute_authentication_operation",
            "execute_final_operation",
            "execute_secret_engine_operation",
        }:
            return self._execute_reviewed_proxy(operation, arguments)
        if operation == "execute_mounted_operation":
            return self._execute_mounted_operation(arguments)
        specifications = {
            "discover_capabilities": (
                "GET",
                "/sys/internal/specs/openapi",
                True,
                False,
                {"generic_mount_paths": "true"},
            ),
            "initialization_status": ("GET", "/sys/init", False, False, None),
            "seal_status": ("GET", "/sys/seal-status", False, False, None),
            "leader_status": ("GET", "/sys/leader", True, False, None),
            "ha_status": ("GET", "/sys/ha-status", True, False, None),
            "raft_configuration": ("GET", "/sys/storage/raft/configuration", True, False, None),
            "initialize": ("PUT", "/sys/init", False, True, None),
            "join_raft": ("POST", "/sys/storage/raft/join", False, True, None),
            "unseal": ("PUT", "/sys/unseal", False, True, None),
            "seal": ("PUT", "/sys/seal", True, True, None),
            "remove_raft_peer": ("POST", "/sys/storage/raft/remove-peer", True, True, None),
        }
        try:
            method, path, authenticated, mutation, params = specifications[operation]
        except KeyError:
            raise VaultError("The administration operation is unsupported.") from None
        return self._administration_request(
            method,
            path,
            authenticated=authenticated,
            payload=arguments if method in {"POST", "PUT"} else None,
            params=params,
            mutation=mutation,
        )

    def _execute_reviewed_proxy(self, operation: str, arguments: dict) -> dict:
        method = arguments["method"]
        path = arguments["path"]
        payload = arguments["payload"]
        request_method = "GET" if method == "LIST" else method
        params = {"list": "true"} if method == "LIST" else None
        extra_headers = None
        token = arguments.get("token", "")
        authenticated = (
            operation != "execute_authentication_operation" or not self._is_unauthenticated_auth_path(path)
        )
        if token:
            authenticated = False
        if operation == "execute_final_operation" and path == "/sys/wrapping/wrap":
            payload = arguments["payload"]["data"]
            ttl = arguments["payload"].get("ttl")
            extra_headers = {"X-Vault-Wrap-TTL": ttl} if ttl else None
        if (
            operation == "execute_final_operation"
            and method == "GET"
            and path.startswith("/sys/config/ui/headers/")
        ):
            params = {"multivalue": "true"}
        mutation = method in {"POST", "DELETE"}
        return self._administration_request(
            request_method,
            path,
            authenticated=authenticated,
            payload=payload if method == "POST" else None,
            params=params,
            extra_headers=extra_headers,
            token=token,
            mutation=mutation,
        )

    def _execute_mounted_operation(self, arguments: dict) -> dict:
        document = self._administration_request(
            "GET",
            "/sys/internal/specs/openapi",
            authenticated=True,
            params={"generic_mount_paths": "true"},
        )
        placeholder_end = arguments["path_template"].find("}")
        placeholder = arguments["path_template"][2:placeholder_end]
        expected_placeholder = arguments["mount_path"].replace("-", "_") + "_mount_path"
        if placeholder != expected_placeholder:
            raise VaultError("The mounted operation template does not match its mount.")
        paths = document.get("paths")
        path_item = paths.get(arguments["path_template"]) if isinstance(paths, dict) else None
        raw_method = "get" if arguments["method"] == "LIST" else arguments["method"].lower()
        advertised = path_item.get(raw_method) if isinstance(path_item, dict) else None
        if not isinstance(advertised, dict) or advertised.get("operationId") != arguments["operation_id"]:
            raise VaultError("The mounted operation is not advertised by OpenBao.")
        self._validate_advertised_mount(path_item, advertised, placeholder, arguments["mount_path"])
        self._validate_advertised_arguments(document, path_item, advertised, arguments)
        method = arguments["method"]
        query = dict(arguments["query"])
        if method == "LIST":
            query["list"] = "true"
        extra_headers = {"Content-Type": "application/merge-patch+json"} if method == "PATCH" else None
        return self._administration_request(
            "GET" if method == "LIST" else method,
            arguments["path"],
            authenticated=True,
            payload=arguments["body"] if method in {"POST", "PUT", "PATCH"} else None,
            params=query or None,
            extra_headers=extra_headers,
            mutation=method in {"POST", "PUT", "PATCH", "DELETE"},
        )

    @staticmethod
    def _validate_advertised_mount(
        path_item: dict, advertised: dict, placeholder: str, mount_path: str
    ) -> None:
        inherited = path_item.get("parameters", [])
        operation_parameters = advertised.get("parameters", [])
        if not isinstance(inherited, list) or not isinstance(operation_parameters, list):
            raise VaultError("OpenBao advertised an invalid mounted operation.")
        parameters = [*inherited, *operation_parameters]
        matching = [
            item
            for item in parameters
            if isinstance(item, dict) and item.get("in") == "path" and item.get("name") == placeholder
        ]
        if len(matching) != 1:
            raise VaultError("OpenBao advertised an invalid mounted operation.")
        parameter = matching[0]
        if parameter.get("required") is not True:
            raise VaultError("OpenBao advertised an invalid mounted operation.")
        schema = parameter.get("schema")
        default = schema.get("default") if isinstance(schema, dict) else None
        if (
            not isinstance(schema, dict)
            or schema.get("type") != "string"
            or not isinstance(default, str)
            or default.rstrip("/") != mount_path.rstrip("/")
        ):
            raise VaultError("The mounted operation template does not match its mount.")

    @staticmethod
    def _validate_advertised_arguments(
        document: dict, path_item: dict, advertised: dict, arguments: dict
    ) -> None:
        """Reject caller fields that the live OpenAPI operation does not declare."""

        inherited = path_item.get("parameters", [])
        operation_parameters = advertised.get("parameters", [])
        if not isinstance(inherited, list) or not isinstance(operation_parameters, list):
            raise VaultError("OpenBao advertised an invalid mounted operation.")
        parameters = inherited + operation_parameters
        if not all(isinstance(item, dict) for item in parameters):
            raise VaultError("OpenBao advertised an invalid mounted operation.")
        query = dict(arguments["query"])
        if arguments["method"] == "LIST":
            query["list"] = "true"
        VaultClient._validate_advertised_query(document, parameters, query)
        VaultClient._validate_advertised_body(document, advertised, arguments["body"])

    @staticmethod
    def _validate_advertised_query(document: dict, parameters: list[dict], query: dict) -> None:
        declared = {
            item["name"]: item
            for item in parameters
            if item.get("in") == "query" and isinstance(item.get("name"), str)
        }
        declared_count = sum(
            item.get("in") == "query" and isinstance(item.get("name"), str) for item in parameters
        )
        if declared_count != len(declared):
            raise VaultError("OpenBao advertised an invalid mounted operation.")
        if not set(query) <= set(declared):
            raise VaultError("The mounted query is not advertised by OpenBao.")
        required = {name for name, item in declared.items() if item.get("required") is True}
        if not required <= set(query):
            raise VaultError("The mounted query is missing a required field.")
        for name, value in query.items():
            schema = declared[name].get("schema") or declared[name]
            VaultClient._validate_openapi_value(document, schema, value)

    @staticmethod
    def _validate_advertised_body(document: dict, advertised: dict, body: dict) -> None:
        request_body = advertised.get("requestBody")
        if request_body is None:
            if body:
                raise VaultError("The mounted body is not advertised by OpenBao.")
            return
        if not isinstance(request_body, dict):
            raise VaultError("OpenBao advertised an invalid mounted operation.")
        content = request_body.get("content")
        media = content.get("application/json") if isinstance(content, dict) else None
        schema = media.get("schema") if isinstance(media, dict) else None
        VaultClient._validate_openapi_value(document, schema, body)

    @staticmethod
    def _resolve_advertised_schema(document: dict, schema) -> dict | None:
        if not isinstance(schema, dict) or "$ref" not in schema:
            return schema
        reference = schema.get("$ref")
        prefix = "#/components/schemas/"
        if not isinstance(reference, str) or not reference.startswith(prefix):
            return None
        schemas = (document.get("components") or {}).get("schemas")
        return schemas.get(reference.removeprefix(prefix)) if isinstance(schemas, dict) else None

    @staticmethod
    def _validate_openapi_value(document: dict, schema, value, *, depth: int = 0) -> None:
        if depth > 8:
            raise VaultError("OpenBao advertised an invalid mounted operation.")
        schema = VaultClient._resolve_advertised_schema(document, schema)
        if not isinstance(schema, dict):
            raise VaultError("OpenBao advertised an invalid mounted operation.")
        if value is None and schema.get("nullable") is True:
            return
        VaultClient._validate_openapi_common_keywords(document, schema, value, depth)
        one_of = schema.get("oneOf")
        any_of = schema.get("anyOf")
        if one_of is not None and any_of is not None:
            raise VaultError("OpenBao advertised an invalid mounted operation.")
        if one_of is not None:
            VaultClient._validate_openapi_alternatives(document, one_of, value, depth, exact=True)
            return
        if any_of is not None:
            VaultClient._validate_openapi_alternatives(document, any_of, value, depth, exact=False)
            return
        VaultClient._validate_openapi_typed_value(document, schema, value, depth)

    @staticmethod
    def _validate_openapi_common_keywords(document: dict, schema: dict, value, depth: int) -> None:
        choices = schema.get("enum")
        if choices is not None:
            if not isinstance(choices, list) or not choices:
                raise VaultError("OpenBao advertised an invalid mounted operation.")
            if value not in choices:
                raise VaultError("The mounted value violates the OpenBao schema.")
        combined = schema.get("allOf", [])
        if not isinstance(combined, list):
            raise VaultError("OpenBao advertised an invalid mounted operation.")
        for member in combined:
            VaultClient._validate_openapi_value(document, member, value, depth=depth + 1)

    @staticmethod
    def _validate_openapi_typed_value(document: dict, schema: dict, value, depth: int) -> None:
        expected = schema.get("type")
        if expected is not None and expected not in {
            "object",
            "array",
            "string",
            "boolean",
            "integer",
            "number",
            "null",
        }:
            raise VaultError("OpenBao advertised an invalid mounted operation.")
        if expected == "object" or "properties" in schema:
            VaultClient._validate_openapi_object(document, schema, value, depth)
        elif expected == "array":
            VaultClient._validate_openapi_array(document, schema, value, depth)
        elif not VaultClient._openapi_scalar_matches(expected, value):
            raise VaultError("The mounted value violates the OpenBao schema.")
        else:
            VaultClient._validate_openapi_scalar_constraints(schema, value)

    @staticmethod
    def _validate_openapi_alternatives(
        document: dict, alternatives, value, depth: int, *, exact: bool
    ) -> None:
        if not isinstance(alternatives, list) or not alternatives:
            raise VaultError("OpenBao advertised an invalid mounted operation.")
        matches = 0
        for alternative in alternatives:
            try:
                VaultClient._validate_openapi_value(document, alternative, value, depth=depth + 1)
            except VaultError:
                continue
            matches += 1
        if matches == 0 or (exact and matches != 1):
            raise VaultError("The mounted value violates the OpenBao schema.")

    @staticmethod
    def _validate_openapi_object(document: dict, schema: dict, value, depth: int) -> None:
        if not isinstance(value, dict):
            raise VaultError("The mounted value violates the OpenBao schema.")
        properties = schema.get("properties", {})
        required = schema.get("required", [])
        if (
            not isinstance(properties, dict)
            or not isinstance(required, list)
            or not all(isinstance(name, str) for name in required)
        ):
            raise VaultError("OpenBao advertised an invalid mounted operation.")
        if not set(required) <= set(value):
            raise VaultError("The mounted body is missing a required field.")
        additional = schema.get("additionalProperties", False)
        if not isinstance(additional, (bool, dict)):
            raise VaultError("OpenBao advertised an invalid mounted operation.")
        for name, item in value.items():
            child = properties.get(name)
            if child is None:
                if additional is True:
                    continue
                if not isinstance(additional, dict):
                    raise VaultError("The mounted body is not advertised by OpenBao.")
                child = additional
            VaultClient._validate_openapi_value(document, child, item, depth=depth + 1)

    @staticmethod
    def _validate_openapi_array(document: dict, schema: dict, value, depth: int) -> None:
        if not isinstance(value, list):
            raise VaultError("The mounted value violates the OpenBao schema.")
        items = schema.get("items")
        if not isinstance(items, dict):
            raise VaultError("OpenBao advertised an invalid mounted operation.")
        minimum = schema.get("minItems", 0)
        maximum = schema.get("maxItems", MAX_ADMINISTRATION_SCHEMA_ITEMS)
        if (
            not isinstance(minimum, int)
            or not isinstance(maximum, int)
            or not minimum <= len(value) <= maximum
        ):
            raise VaultError("The mounted value violates the OpenBao schema.")
        for item in value:
            VaultClient._validate_openapi_value(document, items, item, depth=depth + 1)

    @staticmethod
    def _openapi_scalar_matches(expected, value) -> bool:
        if expected is None:
            return True
        if expected == "string":
            return isinstance(value, str)
        if expected == "boolean":
            return isinstance(value, bool)
        if expected == "integer":
            return isinstance(value, int) and not isinstance(value, bool)
        if expected == "number":
            return isinstance(value, (int, float)) and not isinstance(value, bool)
        if expected == "null":
            return value is None
        return False

    @staticmethod
    def _validate_openapi_scalar_constraints(schema: dict, value) -> None:
        if isinstance(value, str):
            VaultClient._validate_openapi_string(schema, value)
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            VaultClient._validate_openapi_number(schema, value)

    @staticmethod
    def _validate_openapi_string(schema: dict, value: str) -> None:
        minimum = schema.get("minLength", 0)
        maximum = schema.get("maxLength", MAX_ADMINISTRATION_RESPONSE_BYTES)
        if not isinstance(minimum, int) or not isinstance(maximum, int):
            raise VaultError("OpenBao advertised an invalid mounted operation.")
        if not minimum <= len(value) <= maximum:
            raise VaultError("The mounted value violates the OpenBao schema.")
        value_format = schema.get("format")
        if value_format is not None and not isinstance(value_format, str):
            raise VaultError("OpenBao advertised an invalid mounted operation.")
        if value_format == "uuid":
            import uuid

            try:
                uuid.UUID(value)
            except ValueError:
                raise VaultError("The mounted value violates the OpenBao schema.") from None
        if value_format == "date-time":
            try:
                datetime.fromisoformat(value.replace("Z", "+00:00"))
            except ValueError:
                raise VaultError("The mounted value violates the OpenBao schema.") from None

    @staticmethod
    def _validate_openapi_number(schema: dict, value: int | float) -> None:
        minimum = schema.get("minimum")
        maximum = schema.get("maximum")
        if minimum is not None and not isinstance(minimum, (int, float)):
            raise VaultError("OpenBao advertised an invalid mounted operation.")
        if maximum is not None and not isinstance(maximum, (int, float)):
            raise VaultError("OpenBao advertised an invalid mounted operation.")
        if minimum is not None and value < minimum:
            raise VaultError("The mounted value violates the OpenBao schema.")
        if maximum is not None and value > maximum:
            raise VaultError("The mounted value violates the OpenBao schema.")

    @staticmethod
    def _is_unauthenticated_auth_path(path: str) -> bool:
        return (
            path == "/sys/mfa/validate"
            or "/login" in path
            or "/oidc/auth_url" in path
            or "/oidc/poll" in path
            or path.endswith(("-self", "/totp/generate"))
        )
