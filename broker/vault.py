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

import logging
import threading

from .config import BrokerConfig, ConfigError, read_secret_env

__all__ = ('VaultError', 'VaultMisconfigured', 'VaultUnavailable', 'VaultClient')

logger = logging.getLogger(__name__)

TOKEN_LEASE_FRACTION = 0.8


class VaultError(Exception):
    """
    A failure talking to OpenBao, carrying no server-supplied text.

    OpenBao's error bodies can enumerate policy rules. Relaying one to the
    caller would hand a NetBox-side attacker a map of what this broker's
    AppRole is permitted to do — which is precisely the information the broker
    exists to keep on this side of the boundary.
    """

    default_message = 'OpenBao request failed.'
    status_code = 502

    def __init__(self, message: str | None = None):
        super().__init__(message or self.default_message)


class VaultNotFound(VaultError):
    default_message = 'No secret at that path.'
    status_code = 404


class VaultConflict(VaultError):
    default_message = 'The secret was modified concurrently; the write was refused.'
    status_code = 409


class VaultUnavailable(VaultError):
    default_message = 'OpenBao is unreachable or sealed.'
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

    default_message = 'The broker cannot authenticate to OpenBao.'
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

        if self.config.auth_method == 'token':
            token = read_secret_env(f'{prefix}_TOKEN')
            if not token:
                raise ConfigError(f'Token auth requires {prefix}_TOKEN in the environment.')
            client.token = token
            return client

        role_id = read_secret_env(f'{prefix}_ROLE_ID')
        secret_id = read_secret_env(f'{prefix}_SECRET_ID')
        if not role_id or not secret_id:
            raise ConfigError(
                f'AppRole auth requires {prefix}_ROLE_ID and {prefix}_SECRET_ID (or their _FILE '
                f'equivalents) in the environment.'
            )

        try:
            response = client.auth.approle.login(role_id=role_id, secret_id=secret_id)
        except Exception as exc:
            raise self._translate(exc, 'authentication') from None

        token = ((response or {}).get('auth') or {}).get('client_token')
        if not token:
            raise VaultError('OpenBao returned no client token.')
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
        if self.config.auth_method == 'token':
            names = (f'{prefix}_TOKEN',)
        else:
            names = (f'{prefix}_ROLE_ID', f'{prefix}_SECRET_ID')

        missing = [name for name in names if not read_secret_env(name)]
        if missing:
            raise ConfigError(
                f'{self.config.auth_method} auth requires {" and ".join(missing)} '
                f'(or the matching _FILE variable) in the environment.'
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
                    logger.error('Broker credential material is unusable: %s', exc)
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
            logger.warning('OpenBao denied the broker AppRole during %s', context)
            self.invalidate()
            return VaultError('The broker could not authenticate to OpenBao.')

        if isinstance(exc, hvac_exc.InvalidPath):
            return VaultNotFound()

        if isinstance(exc, hvac_exc.InvalidRequest):
            text = str(exc).lower()
            if 'check-and-set' in text or 'cas' in text.split():
                return VaultConflict()
            logger.warning('OpenBao rejected a %s request', context)
            return VaultError('OpenBao rejected the request.')

        if isinstance(exc, (hvac_exc.VaultDown, hvac_exc.VaultNotInitialized)):
            return VaultUnavailable()

        logger.warning('OpenBao %s failed: %s', context, type(exc).__name__)
        return VaultUnavailable()

    # -- operations -----------------------------------------------------

    def read(self, path: str, version: int | None = None) -> dict:
        client = self._get()
        try:
            response = client.secrets.kv.v2.read_secret_version(
                path=path, version=version,
                mount_point=self.config.kv_mount, raise_on_deleted_version=True,
            )
        except Exception as exc:
            raise self._translate(exc, 'read') from None
        return response['data']['data']

    def write(self, path: str, data: dict, cas: int | None = None) -> int:
        client = self._get()
        try:
            response = client.secrets.kv.v2.create_or_update_secret(
                path=path, secret=data, cas=cas, mount_point=self.config.kv_mount,
            )
        except Exception as exc:
            raise self._translate(exc, 'write') from None
        return response['data']['version']

    def delete(self, path: str, versions: list[int] | None = None) -> None:
        client = self._get()
        try:
            if versions:
                client.secrets.kv.v2.delete_secret_versions(
                    path=path, versions=versions, mount_point=self.config.kv_mount,
                )
            else:
                client.secrets.kv.v2.delete_metadata_and_all_versions(
                    path=path, mount_point=self.config.kv_mount,
                )
        except Exception as exc:
            raise self._translate(exc, 'delete') from None

    def read_metadata(self, path: str) -> dict:
        client = self._get()
        try:
            response = client.secrets.kv.v2.read_secret_metadata(
                path=path, mount_point=self.config.kv_mount,
            )
        except Exception as exc:
            raise self._translate(exc, 'metadata read') from None
        return response.get('data') or {}

    def set_metadata(self, path: str, custom_metadata: dict) -> None:
        client = self._get()
        try:
            client.secrets.kv.v2.update_metadata(
                path=path, custom_metadata=custom_metadata, mount_point=self.config.kv_mount,
            )
        except Exception as exc:
            raise self._translate(exc, 'metadata write') from None

    def list_versions(self, path: str) -> list[dict]:
        metadata = self.read_metadata(path)
        versions = [
            {
                'version': int(number),
                'created_time': meta.get('created_time'),
                'deletion_time': meta.get('deletion_time') or None,
                'destroyed': bool(meta.get('destroyed')),
            }
            for number, meta in (metadata.get('versions') or {}).items()
        ]
        versions.sort(key=lambda v: v['version'], reverse=True)
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
            response = client.sys.read_health_status(method='GET')
        except Exception:
            return {'reachable': False, 'sealed': None}

        payload = response if isinstance(response, dict) else {}
        if hasattr(response, 'json'):
            try:
                payload = response.json()
            except ValueError:
                payload = {}
        return {
            'reachable': True,
            'sealed': bool(payload.get('sealed')),
            'version': payload.get('version'),
        }
