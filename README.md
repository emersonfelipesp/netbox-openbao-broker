# netbox-openbao-broker

An optional service that holds the OpenBao AppRole so that
[`netbox-openbao`](https://git.nmulti.cloud/emersonfelipesp/netbox-openbao) —
and therefore NetBox — never possesses credentials able to read production
secret material directly.

```
NetBox ──mTLS──▶ Broker ──AppRole──▶ OpenBao
       ◀── material ──
```

NetBox holds a client certificate that lets it **ask**. This process holds the
credential that can actually **read**.

## What this buys, stated honestly

This is the part that must not be oversold, because an operator would relax
controls elsewhere on the strength of a guarantee that does not hold.

**It does not make "NetBox compromise ≠ secret compromise" true.** An attacker
with code execution in NetBox can still *ask* the broker for material, and the
broker will answer for anything NetBox is authorized to request.

What it actually buys:

- Stealing NetBox's **database or configuration** no longer yields credentials
  that read the vault directly.
- The broker's **audit log sits outside NetBox's blast radius**, so a compromise
  cannot erase the record of what it read.
- The AppRole's SecretID **never exists on the NetBox host at all**.

That is a real improvement against offline compromise, backup theft, and config
leakage. It is not the stronger claim.

Two further limits are worth naming explicitly:

- **Authorization is per instance, not per user.** Enforcing per-user would mean
  shipping NetBox's object permissions, constraints, and group membership to the
  broker — a second implementation of the authorization model `netbox-openbao`
  exists to keep singular. NetBox remains the authority on *who* may ask; the
  broker decides only what an *instance* may ask about.
- **A path prefix is the whole boundary.** Confining an instance to
  `netbox/credentials` means a NetBox compromise reaches every secret under that
  prefix and nothing above it. Separate what genuinely must not fall together
  into separate prefixes with separate instances, or it will not be separate.

## Scope: deliberately small

Six endpoints mirroring `netbox-openbao`'s `SecretBackend` ABC exactly, plus
health. No user model. No RBAC. No database. One authorization rule: does this
client certificate's identity permit this path?

That smallness is a design constraint, not an unfinished state — a broker with a
rich API is just NetBox again, with a second authorization model to drift out of
step with the first.

| Endpoint | Body | Returns |
|---|---|---|
| `POST /v1/secret/read` | `path`, optional `version` | `{"data": {...}}` |
| `POST /v1/secret/write` | `path`, `data`, optional `cas` | `{"version": N}` |
| `POST /v1/secret/delete` | `path`, optional `versions` | `{"deleted": true}` |
| `POST /v1/secret/versions` | `path` | `{"versions": [...]}` |
| `POST /v1/secret/metadata/read` | `path` | `{"metadata": {...}}` |
| `POST /v1/secret/metadata/write` | `path`, `custom_metadata` | `{"updated": true}` |
| `GET /healthz` | — | `{"ok": true, "openbao": {...}}` |

Interactive docs and the OpenAPI schema are **not served**. They are a second,
differently-shaped surface on a service whose value is being small and
predictable, and the schema enumerates the API for anyone who reaches the port.

## Authentication

Identity comes from the **peer certificate presented during the TLS handshake**
and from nowhere else. The subject CN is the instance name.

There is deliberately **no header-based fallback, and running the broker behind
a terminating proxy is unsupported rather than half-supported.** A trusted
header is only trustworthy if every path to the socket is controlled, and the
first person to put a debugging proxy in front — or to expose the port for a
health check — silently converts an authentication mechanism into a
self-declared identity. mTLS was chosen precisely so no such mode exists.

A certificate signed by the configured CA is **not** authorization. An instance
that is cryptographically valid but absent from the configuration is refused,
so one mis-issued certificate is not full vault access.

The broker refuses to start unless `BROKER_TLS_CERT`, `BROKER_TLS_KEY`, and
`BROKER_TLS_CLIENT_CA` are all set. Serving without client certificates would
leave every request unauthenticated while looking healthy.

## Configuration

TOML at `/etc/netbox-openbao-broker/config.toml`, or wherever `BROKER_CONFIG`
points. **No secret material lives in it** — the AppRole comes from the
environment.

```toml
[openbao]
url = "https://bao.example.net:8200"
kv_mount = "secret"
# namespace = "admin"           # OpenBao/Vault Enterprise namespaces
auth_method = "approle"         # or "token", for development only
env_prefix = "BROKER_BAO"       # names the credential env vars, below
tls_verify = true
# ca_cert_path = "/etc/ssl/certs/internal-ca.pem"

[instances.netbox-prod]
path_prefixes = ["netbox/credentials"]
may_write = true
may_delete = false

[instances.netbox-staging]
path_prefixes = ["netbox-staging/credentials"]
may_write = true
may_delete = true
```

The instance key is matched against the client certificate's subject CN. An
instance declaring no `path_prefixes` is a startup error, not an instance
permitted to read everything.

`may_write` also gates metadata writes. Metadata is not material, but it is
still a mutation of the vault by a caller the operator declared read-only.

### Environment

| Variable | Purpose |
|---|---|
| `BROKER_CONFIG` | Path to the TOML above. Default `/etc/netbox-openbao-broker/config.toml`. |
| `BROKER_OPENBAO_URL` | Overrides `openbao.url`. |
| `BROKER_TLS_CERT` | Server certificate. **Required.** |
| `BROKER_TLS_KEY` | Server private key. **Required.** |
| `BROKER_TLS_CLIENT_CA` | CA that client certificates are verified against. **Required.** |
| `BROKER_BAO_ROLE_ID` | AppRole RoleID. |
| `BROKER_BAO_SECRET_ID` | AppRole SecretID. |
| `BROKER_BAO_TOKEN` | Token, when `auth_method = "token"`. |
| `BROKER_HOST` | Listen address. Default `0.0.0.0`. |
| `BROKER_PORT` | Listen port. Default `8201`. |
| `BROKER_LOG_LEVEL` | Default `INFO`. |

The `BROKER_BAO_` prefix follows `openbao.env_prefix`.

Every credential variable also accepts a **`_FILE` form** —
`BROKER_BAO_SECRET_ID_FILE=/run/secrets/secret_id` — which is how a container or
systemd unit supplies the SecretID without it appearing in the process
environment, where `/proc/<pid>/environ` exposes it to anything running as the
same user. Prefer it.

## Audit log

One JSON object per line on stdout, so the collector is whatever reads the
stream. Refusals are logged too — a denied request is the entry an operator most
wants to find, and a log that records only successes is a log of the wrong half.

```json
{"instance":"netbox-prod","operation":"read","outcome":"denied","path":"production/root","reason":"outside permitted prefixes","request_id":"…","ts":"…","version":null}
```

`AuditLog.record()` takes named non-secret fields and nothing else. There is no
parameter a payload could be passed through, which is a stronger guarantee than
remembering not to pass one.

## Running it

See [`docs/deployment.md`](docs/deployment.md) for the container, compose, and
systemd paths, including certificate issuance and the healthcheck caveat.

```bash
pip install .
BROKER_CONFIG=/etc/netbox-openbao-broker/config.toml \
BROKER_TLS_CERT=/etc/…/server.pem \
BROKER_TLS_KEY=/etc/…/server.key \
BROKER_TLS_CLIENT_CA=/etc/…/client-ca.pem \
BROKER_BAO_ROLE_ID_FILE=/run/secrets/role_id \
BROKER_BAO_SECRET_ID_FILE=/run/secrets/secret_id \
netbox-openbao-broker
```

## Development

```bash
pip install -e '.[dev]'
pytest        # 27 tests
ruff check .
```

The mTLS suite generates its own CA and runs the broker as a **subprocess** — as
it runs in production. Running uvicorn in a thread alongside the test client
produced connection resets unrelated to the code under test; that is a poor
thing to debug and a worse thing to leave in a suite as a flake.

Every denial test asserts on the fake vault's **call log**, not merely on the
status code. A broker that reads a secret and then declines to return it has
already defeated its own purpose: the material left the vault, the vault's audit
log records a read nobody authorized, and only a bug stands between that and
disclosure.

## License

Apache-2.0.
