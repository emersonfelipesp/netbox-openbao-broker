# netbox-openbao-broker

An optional service that holds the OpenBao AppRole so that
[`netbox-openbao`](https://github.com/emersonfelipesp/netbox-openbao) —
and therefore NetBox — never possesses credentials able to read production
secret material directly.

Install the released service from PyPI with
`pip install netbox-openbao-broker`. Release maintainers should follow the
[package release procedure](docs/releasing.md); published changes are recorded
in the [changelog](CHANGELOG.md).

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

## Scope: deliberately bounded

The six secret endpoints mirror `netbox-openbao`'s `SecretBackend` ABC exactly.
The optional administration surface consists of one contract-discovery route,
one versioned typed request envelope, and two bounded Raft snapshot streaming
routes. There is no user model, RBAC implementation, or database. NetBox remains
the authority for user and object permissions; the broker grants only
instance-level path prefixes and administration families.

The broker owns a closed operation registry. It never accepts an arbitrary
OpenBao system path. Mounted secret operations must match the live OpenBao
OpenAPI path template, method, operation ID, query fields, and body fields before
the target request is sent. A refused request never reaches its target endpoint.

| Endpoint | Body | Returns |
|---|---|---|
| `POST /v1/secret/read` | `path`, optional `version` | `{"data": {...}}` |
| `POST /v1/secret/write` | `path`, `data`, optional `cas` | `{"version": N}` |
| `POST /v1/secret/delete` | `path`, optional `versions` | `{"deleted": true}` |
| `POST /v1/secret/versions` | `path` | `{"versions": [...]}` |
| `POST /v1/secret/metadata/read` | `path` | `{"metadata": {...}}` |
| `POST /v1/secret/metadata/write` | `path`, `custom_metadata` | `{"updated": true}` |
| `GET /v1/administration/contract` | — | Enabled contract version, digest, families, and operations |
| `POST /v1/administration/request` | Contract digest, operation, and typed arguments | `{"data": {...}}` |
| `GET /v1/administration/snapshot` | Contract digest header | Bounded Raft snapshot stream |
| `POST /v1/administration/snapshot` | Contract digest header and raw snapshot body | `{"restored": true}` |
| `GET /healthz` | — | `{"ok": true, "openbao": {...}}` |

Administration is disabled by default. Enable only the families an instance
needs:

```toml
[instances.netbox-prod]
path_prefixes = ["netbox/credentials"]
may_write = true
may_delete = false
administration_families = [
  "access",
  "authentication",
  "cluster",
  "finalization",
  "mounted-secrets",
  "secret-engines",
]
```

The families are an instance boundary, not a replacement for NetBox permissions.
The broker authenticates the NetBox instance through mTLS and records only
non-secret operation metadata. The caller must first discover the contract and
send its exact digest with every administration request; stale clients fail
closed. Snapshot restores are single-attempt mutations whose uncertain transport
outcome is returned as `X-OpenBao-Outcome: unknown`.

Paths are restricted to printable ASCII with no spaces and **no
percent-encoding**. That last one is not fussiness: `requests`, which `hvac`
uses, decodes `%2e` back to `.` while building the URL, so a path checked as
`netbox/credentials/%2e%2e/%2e%2e/production/root` leaves this process as
`.../netbox/credentials/../../production/root`. OpenBao 2.6.0 declines to
resolve that, which is a fine thing to be true and a poor thing to depend on —
so the broker refuses it rather than leaving the boundary to someone else's
routing.

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
may_delete = false        # see "Choosing may_delete" below — this has a cost

[instances.netbox-staging]
path_prefixes = ["netbox-staging/credentials"]
may_write = true
may_delete = true

[instances.reporting]
path_prefixes = ["netbox/credentials"]
may_write = false
may_delete = false
```

The instance key is matched against the client certificate's subject CN. An
instance declaring no `path_prefixes` is a startup error, not an instance
permitted to read everything.

`may_write` also gates metadata writes. Metadata is not material, but it is
still a mutation of the vault by a caller the operator declared read-only.

### Choosing `may_delete`, and what it costs either way

Both settings cost something. Neither is the free least-privilege win it looks
like, and the examples above previously showed `false` for production with no
explanation at all — which is how an operator ends up with residue they were
never told to expect.

**With `false`, deleting a credential leaves its material behind.** The plugin
calls delete on three paths that are not operator-initiated destruction, and
only one of them can be refused quietly:

| When the plugin deletes | Refused under `may_delete = false` |
|---|---|
| A credential is deleted in NetBox | **Leaves material behind, silently.** The destroy runs from a `post_delete` signal deferred to `transaction.on_commit`, so by the time it runs the row is gone and raising could not undo it. The plugin logs `ORPHANED SECRET` and continues. |
| A credential write is rolled back | **Leaves material behind, but fails loudly.** The write happens inside a database transaction and the plugin compensates by deleting what it wrote when that transaction unwinds. A refused compensation is logged and the original failure re-raised, so the operation does fail — just not for this reason. |
| A staged rotation is discarded | **Fails loudly, leaves nothing behind.** `discard_staged` re-raises; the staged version stays and the credential still points at it. |

The residue is **findable, but not through the broker and not automatically.**
Both halves of that matter:

- Every credential the plugin writes carries KV v2 `custom_metadata` with
  `managed_by: netbox-openbao` and the NetBox credential's UUID, so an entry that
  matches no `Credential` row is identifiable by listing the prefix and reading
  metadata. No secret value need be read to do it.
- **The baseline secret surface cannot run that listing.** An instance with the
  optional administration families may be able to enumerate mounts through the
  reviewed administration contract. A secret-only deployment still needs a
  separate, read-only identity talking to OpenBao directly — see
  [An identity for reconciliation](docs/deployment.md#an-identity-for-reconciliation)
  for the policy and the procedure. Choosing `may_delete = false` without
  provisioning that identity leaves you with residue you have no way to find.
- **Nothing runs it for you.** `CredentialVerifyJob` iterates existing credential
  rows and asks whether each one's material is present, which makes it
  structurally blind to material whose row is gone. The plugin tracks automating
  the other direction; until then this is a procedure someone schedules.

So: recoverable, at the cost of one more identity and a periodic job someone
writes. That is a real cost and it is smaller than an irreversible deletion — but
it is not zero, and a deployment that skips it has chosen the worst of both.

**With `true`, a NetBox compromise becomes destructive.** An attacker with code
execution in NetBox can already ask the broker to read anything the instance is
authorized to read — that limit is inherent to the design and stated at the top
of this file. Granting delete adds the ability to *destroy*: a version-less
delete maps to `delete_metadata_and_all_versions`, which is permanent. Every
credential under the instance's prefix can be erased, and KV v2 does not undo it.

The two capabilities are not the same shape, which matters when writing the
OpenBao policy. Removing specific versions (`secret/delete/…`) is a soft delete
that can be undeleted. Removing a path's metadata (`secret/metadata/…`) destroys
every version irreversibly. The plugin uses both.

**So: `false` is the right default**, and the examples above keep it — provided
you provision the reconciliation identity alongside it. A recoverable,
enumerable residue is a smaller problem than an irreversible one, and refusing
delete does not stop NetBox working; it only removes the automatic cleanup after
a credential is deleted. What it asks of you in exchange is one read-only OpenBao
identity and a scheduled run of the listing procedure.

Choose `true` deliberately, when automatic cleanup is worth the destruction
capability — a lower-tier instance, a short prefix, an estate where an
unreconciled secret is the greater operational risk. If you do, bound it: keep
the instance's `path_prefixes` as narrow as possible, so what a compromise can
destroy is limited by the prefix rather than by the mount, and keep OpenBao's
audit device and your backups outside NetBox's reach.

For an instance that genuinely never deletes — a reporting or automation
consumer that only resolves credentials — `false` costs nothing at all, because
none of the three rows above ever runs. The `reporting` instance above is that
case, and note that it is **a separate client identity, not a second block for
the same one**: the broker selects an instance by the subject CN of the client
certificate, so a reporting consumer needs its own CA-signed certificate with
`CN=reporting`. Presenting `netbox-prod`'s certificate selects `netbox-prod`,
write and delete permissions included, and the read-only block protects nothing.

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

Every request that reaches a secret operation leaves a record, including ones
that never reached a handler: body validation runs before the caller is
identified, so a malformed request is audited as `operation=malformed` rather
than disappearing into a 422. An attempt to read a secret is what an operator
reconstructing an incident wants to find, whether or not it parsed.

### The denied-delete record, and what not to do with it

```
operation=delete  outcome=denied  reason="instance may not delete"
```

**Do not page on this.** On a `may_delete = false` instance it is an ordinary
consequence of normal plugin cleanup, so an alert on it fires routinely, gets
muted, and takes the genuinely interesting cases with it when it goes.

Four things produce it, and the broker cannot tell them apart — it sees a
refused request, not the intent behind it:

1. A credential deletion in NetBox — leaves residue, silently.
2. A rolled-back credential write — leaves residue, and the caller's operation
   fails anyway with the original error.
3. A discarded staged rotation — fails loudly and leaves nothing behind.
4. Anything else holding that client certificate, calling `/v1/secret/delete`
   directly.

Keep it as an **informational correlation event**: the record that tells you
*when* something tried to clean up and could not, useful when you are already
investigating. Route it to the log store, not to a pager.

What is worth alerting on is the plugin's own `ORPHANED SECRET` line, which names
an actual path that was left behind, and the output of the reconciliation run —
a non-empty result means residue exists right now. Those two are actionable; this
one is context.

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
