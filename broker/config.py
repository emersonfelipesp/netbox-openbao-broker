"""
Broker configuration.

Two rules shape everything here:

* **No secret material in tracked configuration.** The AppRole's RoleID and
  SecretID come from the environment, or a file the environment points at. The
  whole point of this service is that the SecretID never exists on the NetBox
  host; putting it in a config file that gets copied around would relocate the
  problem rather than solve it.
* **Instances are declared, never inferred.** A client certificate that is
  cryptographically valid but not in the instance list is refused. Trusting any
  cert your CA happened to sign turns one CA mistake into full vault access.
"""

from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

__all__ = ('BrokerConfig', 'InstancePolicy', 'load_config')

DEFAULT_CONFIG_PATH = '/etc/netbox-openbao-broker/config.toml'


class ConfigError(Exception):
    """Configuration is wrong. Raised at startup, never at request time."""


@dataclass(frozen=True)
class InstancePolicy:
    """
    What one NetBox instance is permitted to do.

    Authorization here is per *instance*, not per user. Enforcing per-user
    would mean shipping NetBox's object permissions, constraints, and group
    membership to the broker — a second implementation of the authorization
    model this whole project exists to keep singular. NetBox remains the
    authority on who may ask; the broker decides only what this instance may
    ask about.
    """

    name: str
    path_prefixes: tuple[str, ...]
    may_write: bool = False
    may_delete: bool = False

    def permits_path(self, path: str) -> bool:
        """
        Whether `path` falls inside a permitted prefix.

        `normalize_path` has already rejected traversal, so this is a plain
        prefix test on a known-clean value rather than a guess about what the
        string might mean.
        """
        return any(
            path == prefix or path.startswith(prefix.rstrip('/') + '/')
            for prefix in self.path_prefixes
        )


@dataclass(frozen=True)
class BrokerConfig:
    openbao_url: str
    kv_mount: str = 'secret'
    namespace: str | None = None
    auth_method: str = 'approle'
    env_prefix: str = 'BROKER_BAO'
    tls_verify: bool = True
    ca_cert_path: str | None = None
    instances: dict[str, InstancePolicy] = field(default_factory=dict)

    def instance(self, name: str) -> InstancePolicy | None:
        return self.instances.get(name)


def normalize_path(raw: str) -> str:
    """
    Reduce a client-supplied secret path to a safe canonical form, or refuse it.

    A prefix check that `..` can walk out of is not a check: an instance
    confined to `netbox/` could otherwise reach `netbox/../production/` and the
    startswith test would still pass. Rather than try to out-clever the input,
    anything containing a traversal segment, a leading slash, a backslash, or a
    null byte is rejected outright — none of them has a legitimate meaning in a
    KV path.

    **Percent-encoding is rejected for the same reason, and the reason is not
    theoretical.** `requests` — which `hvac` uses — runs every URL through
    `requote_uri`, and that calls `unquote_unreserved`, which decodes any escape
    whose character is unreserved. `.` is unreserved, so `%2e%2e/` becomes `../`
    *after* this function has approved the path. The literal check above would
    have passed and the URL leaving the process would contain a traversal.

    Whether that traversal then resolves is up to the server: OpenBao 2.6.0 does
    not collapse dot-segments and refuses it. That is a fine thing to be true and
    a terrible thing to depend on — it makes the boundary a property of the
    server's routing rather than of this check, and a proxy, a version bump, or a
    different KV implementation silently removes it. So `%` is refused here.

    Characters outside printable ASCII go with it. Nothing the plugin generates
    needs them — its paths are `<prefix>/<uuid>` — and admitting them means
    admitting whatever some later layer's Unicode normalization decides
    `U+FF0F FULLWIDTH SOLIDUS` ought to become.

    Raises `ValueError` for anything unacceptable.
    """
    if not raw or not isinstance(raw, str):
        raise ValueError('path must be a non-empty string')

    if '\\' in raw:
        raise ValueError('path contains an illegal character')

    if '%' in raw:
        raise ValueError('path must not be percent-encoded')

    if any(not ('\x21' <= character <= '\x7e') for character in raw):
        raise ValueError('path must be printable ASCII without spaces')

    if raw.startswith('/'):
        raise ValueError('path must be relative to the KV mount')

    segments = raw.split('/')
    if any(segment in ('.', '..') for segment in segments):
        raise ValueError('path must not contain relative segments')
    if any(not segment for segment in segments):
        raise ValueError('path must not contain empty segments')

    return raw


def load_config(path: str | None = None) -> BrokerConfig:
    """
    Load configuration from TOML, with the OpenBao URL overridable by env.

    Fails loudly at startup rather than degrading. A broker that starts with no
    instances configured would accept a connection and then refuse every
    request, which reads as a bug in the caller rather than as a
    misconfiguration here.
    """
    config_path = Path(path or os.environ.get('BROKER_CONFIG', DEFAULT_CONFIG_PATH))
    if not config_path.is_file():
        raise ConfigError(f'No configuration at {config_path}. Set BROKER_CONFIG.')

    with config_path.open('rb') as handle:
        raw = tomllib.load(handle)

    openbao = raw.get('openbao') or {}
    url = os.environ.get('BROKER_OPENBAO_URL') or openbao.get('url')
    if not url:
        raise ConfigError('openbao.url is required (or set BROKER_OPENBAO_URL).')

    instances = {}
    for name, spec in (raw.get('instances') or {}).items():
        prefixes = spec.get('path_prefixes') or []
        if not prefixes:
            raise ConfigError(
                f'Instance "{name}" declares no path_prefixes. An instance permitted to read '
                f'everything is the situation this broker exists to prevent.'
            )
        for prefix in prefixes:
            try:
                normalize_path(prefix)
            except ValueError as exc:
                raise ConfigError(f'Instance "{name}" has an invalid prefix "{prefix}": {exc}') from None

        instances[name] = InstancePolicy(
            name=name,
            path_prefixes=tuple(prefixes),
            may_write=bool(spec.get('may_write', False)),
            may_delete=bool(spec.get('may_delete', False)),
        )

    if not instances:
        raise ConfigError('No instances configured. The broker would refuse every request.')

    return BrokerConfig(
        openbao_url=url.rstrip('/'),
        kv_mount=openbao.get('kv_mount', 'secret'),
        namespace=openbao.get('namespace') or None,
        auth_method=openbao.get('auth_method', 'approle'),
        env_prefix=openbao.get('env_prefix', 'BROKER_BAO'),
        tls_verify=bool(openbao.get('tls_verify', True)),
        ca_cert_path=openbao.get('ca_cert_path') or None,
        instances=instances,
    )


def read_secret_env(name: str) -> str | None:
    """
    Read `name`, or the contents of the file `name`_FILE points at.

    The `_FILE` indirection is how a container or systemd unit supplies the
    AppRole SecretID without it appearing in the process environment, which is
    readable through `/proc/<pid>/environ`.
    """
    value = os.environ.get(name)
    if value:
        return value.strip()

    path = os.environ.get(f'{name}_FILE')
    if path:
        try:
            return Path(path).read_text().strip()
        except OSError as exc:
            # The path is operator-supplied configuration, not a secret, so
            # naming it makes the misconfiguration diagnosable.
            raise ConfigError(f'Cannot read {name}_FILE ({path}): {exc.strerror}') from None
    return None
