# Deploying the broker

One page, deliberately. The service has six endpoints, no database, and no user
model; a deployment guide that sprawls is a sign the service has.

Read [the threat model in the README](../README.md#what-this-buys-stated-honestly)
first. If you are deploying this expecting that a NetBox compromise can no
longer reach secret material, you are deploying it for a guarantee it does not
provide.

## 1. Certificates

Two identities and one CA. The broker verifies clients against
`BROKER_TLS_CLIENT_CA`; NetBox verifies the broker against whatever signed
`BROKER_TLS_CERT`. They may be the same CA or different ones — separate is
better, because then the CA that can mint a NetBox identity is not the CA that
can impersonate the broker.

Use your existing internal PKI if you have one. If you do not, the shape is:

```bash
# Client CA — the only thing that decides who may talk to the broker.
openssl req -x509 -newkey rsa:4096 -nodes -days 3650 \
  -keyout client-ca.key -out client-ca.pem \
  -subj '/CN=netbox-openbao client CA'

# NetBox's identity. The CN is the instance name in config.toml.
openssl req -newkey rsa:4096 -nodes -keyout netbox-prod.key -out netbox-prod.csr \
  -subj '/CN=netbox-prod'
openssl x509 -req -in netbox-prod.csr -CA client-ca.pem -CAkey client-ca.key \
  -CAcreateserial -days 825 -out netbox-prod.pem \
  -extfile <(printf 'extendedKeyUsage=clientAuth\nbasicConstraints=CA:FALSE\n')
```

Two things that produce a bare connection reset with nothing logged on either
side if you get them wrong, so they are worth stating plainly:

- **`extendedKeyUsage` must be present and correct** — `clientAuth` on the
  NetBox certificate, `serverAuth` on the broker's. OpenSSL refuses a
  certificate presented for a usage it does not assert.
- **The broker's certificate needs a `subjectAltName`** matching the name
  NetBox connects to. A CN alone has not been sufficient for years.

The subject **CN of the client certificate is the instance identity**. Issuing
two certificates with the same CN gives two hosts the same authorization, which
may be what you want for a NetBox cluster and is a mistake otherwise.

It follows that **every instance block needs its own certificate**. A read-only
consumer configured as a separate instance is only read-only if it presents its
own identity:

```bash
openssl req -newkey rsa:4096 -nodes -keyout reporting.key -out reporting.csr \
  -subj '/CN=reporting'
openssl x509 -req -in reporting.csr -CA client-ca.pem -CAkey client-ca.key \
  -CAcreateserial -days 825 -out reporting.pem \
  -extfile <(printf 'extendedKeyUsage=clientAuth\nbasicConstraints=CA:FALSE\n')
```

Hand that consumer `reporting.pem` and `reporting.key`. If it presents
`netbox-prod.pem` instead, the broker selects the `netbox-prod` instance — write
and delete permissions included — and the read-only block in `config.toml`
protects nothing at all.

## 2. Configure OpenBao

Create a policy scoped to exactly the prefixes the instance will declare, and an
AppRole bound to it. The broker's AppRole should be able to reach nothing the
policy in `config.toml` does not also permit — two independent limits, so a
mistake in either one is not sufficient on its own.

For an instance with `may_delete = false`, which is the recommended default:

```hcl
path "secret/data/netbox/credentials/*"     { capabilities = ["create", "read", "update"] }
path "secret/metadata/netbox/credentials/*" { capabilities = ["create", "read", "update", "list"] }
```

`create` on the metadata path is there deliberately even though the plugin has
not needed it. `store_credential` writes the data path first, which creates the
metadata entry implicitly, so the `update_metadata` call that follows has always
found an existing path and `update` alone has sufficed. That is an ordering
dependency, not a guarantee — grant `create` so the policy does not silently
depend on which of two writes happens first.

Add these two only for an instance you have deliberately given
`may_delete = true`:

```hcl
path "secret/metadata/netbox/credentials/*" { capabilities = ["create", "read", "update", "list", "delete"] }
path "secret/delete/netbox/credentials/*"   { capabilities = ["update"] }
```

### An identity for reconciliation

`list` above lets the **broker's** AppRole enumerate the prefix. That is not the
same as letting *you* enumerate it, and the difference matters: the broker
exposes six endpoints and none of them lists a mount, so its AppRole cannot be
driven to walk the prefix from outside. The SecretID is deliberately unreachable
outside the broker process, which is the entire point of this service.

So the reconciliation procedure the [README describes](../README.md#choosing-may_delete-and-what-it-costs-either-way)
needs **its own identity**, talking to OpenBao directly rather than through the
broker. Give it read and list on metadata and nothing else — it never needs to
read a secret value, only the `custom_metadata` that names which NetBox
credential each path belongs to:

```hcl
# Policy: netbox-openbao-reconcile
path "secret/metadata/netbox/credentials"   { capabilities = ["list"] }
path "secret/metadata/netbox/credentials/*" { capabilities = ["read", "list"] }
```

Note the two paths. KV v2 lists the *directory*, so the un-suffixed path is what
`list` operates on; the wildcard is what reads each entry's metadata.

Bind that policy to whatever identity your operators already use — it does not
need an AppRole of its own, and giving it one creates another long-lived
credential to manage. Then:

```bash
# Every path the plugin manages under this prefix.
bao kv metadata list -mount=secret netbox/credentials

# For each, the metadata that says which NetBox credential it belongs to.
bao kv metadata get -mount=secret -format=json netbox/credentials/<uuid> \
  | jq '.data.custom_metadata'
```

An entry whose `managed_by` is `netbox-openbao` and whose
`netbox_credential_uuid` matches no `Credential` row in NetBox is residue. Report
it; do not script its deletion. Material NetBox cannot account for is exactly
the thing a human should authorise removing — the row may be missing because of
a restore, a partial migration, or a bug in the plugin.

This is a manual procedure today. The plugin tracks automating it, and until that
lands, "run this periodically" is the honest instruction rather than an implied
background job.

The two extra capabilities are separate because the KV v2 API splits them across
separate paths, and they are **not** the same operation:

| Capability | Operation | Reversible? |
|---|---|---|
| `update` on `secret/delete/…` | Soft-delete specific versions | Yes — undelete restores them |
| `delete` on `secret/metadata/…` | Destroy the path, every version, and its metadata | **No** |

> **Granting delete makes a NetBox compromise destructive.**
>
> An attacker with code execution in NetBox can already ask the broker to read
> anything the instance is authorized to read; that limit is inherent to the
> design. Granting the metadata-delete capability adds the ability to
> **permanently erase every credential under the instance's prefix**, and KV v2
> does not undo it.
>
> Bound it: keep each instance's `path_prefixes` as narrow as the deployment
> allows, so what a compromise can destroy is limited by the prefix rather than
> by the mount, and keep OpenBao's audit device and your backups outside
> NetBox's reach.

Withholding them is not free either, which is why the README discusses the trade
rather than asserting an answer. Without delete, removing a credential in NetBox
leaves its material on the mount: the destroy runs from a `post_delete` signal
deferred to `transaction.on_commit`, where the row is already gone and raising
could not undo it, so the plugin logs `ORPHANED SECRET` and continues. That
residue is enumerable — every credential carries `managed_by: netbox-openbao`
metadata and the `list` capability above is what lets you walk the mount — but no
job reconciles it for you today.

The default recommendation is `may_delete = false` with that procedure run
periodically, because an enumerable residue is a smaller problem than an
irreversible deletion. See
[Choosing `may_delete`](../README.md#choosing-may_delete-and-what-it-costs-either-way)
for the full comparison.

**Keep the two limits aligned.** Refusing delete at the OpenBao policy while
permitting it at `may_delete` produces exactly the same residue as refusing it at
both, with the added confusion of a configuration that says otherwise.

## 3. Configure the broker

Copy [`config.toml.example`](../deploy/config.toml.example) and edit it. The
instance keys must match the client certificate CNs from step 1.

An instance declaring no `path_prefixes` is a startup error rather than an
instance permitted to read everything, and the broker refuses to start with no
instances at all — it would otherwise accept connections and refuse every
request, which reads as a bug in the caller.

## 4. Run it

### Container

```bash
cd deploy
cp config.toml.example config.toml && $EDITOR config.toml
mkdir -p tls && cp /path/to/{server.pem,server.key,client-ca.pem} tls/

printf '%s' "$ROLE_ID"   | docker secret create broker_role_id -
printf '%s' "$SECRET_ID" | docker secret create broker_secret_id -

docker compose up -d --build
```

The compose file runs the container unprivileged, read-only, with all
capabilities dropped and `no-new-privileges`. The AppRole arrives as a Docker
secret and is named through `BROKER_BAO_*_FILE`, so it never enters the process
environment.

### systemd

```bash
python3 -m venv /opt/netbox-openbao-broker/venv
/opt/netbox-openbao-broker/venv/bin/pip install netbox-openbao-broker

groupadd --system netbox-openbao-broker
install -d -m 0750 -g netbox-openbao-broker /etc/netbox-openbao-broker/tls
install -m 0640 -g netbox-openbao-broker config.toml /etc/netbox-openbao-broker/
install -m 0600 role_id secret_id /etc/netbox-openbao-broker/

install -m 0644 deploy/netbox-openbao-broker.service /etc/systemd/system/
systemctl daemon-reload && systemctl enable --now netbox-openbao-broker
```

The unit uses `LoadCredential=` for the AppRole — systemd places it in a
per-invocation directory readable only by this service, and
`BROKER_BAO_*_FILE=%d/...` names it from there. It never appears in the unit
file, in `systemctl show`, or in `/proc/<pid>/environ`.

`DynamicUser=yes` means an unpredictable UID, which is why the certificates are
read through a supplementary group rather than by owner. If you would rather use
a fixed account, replace `DynamicUser=yes` with `User=`/`Group=` and keep the
rest.

## 5. Point NetBox at it

In `PLUGINS_CONFIG`:

```python
'netbox_openbao': {
    'backend': 'broker',
    'broker_url': 'https://broker.internal:8201',
    'broker_client_cert': '/etc/netbox/openbao/netbox-prod.pem',
    'broker_client_key': '/etc/netbox/openbao/netbox-prod.key',
    'broker_ca_cert': '/etc/netbox/openbao/broker-ca.pem',
}
```

Then remove the OpenBao AppRole from the NetBox host entirely. Leaving it in
place means the broker is an extra hop rather than a boundary, and the
deployment has the operational cost of this design with none of its benefit.

## Health checks

`/healthz` reports whether OpenBao answers and whether it is sealed, and nothing
about instances, paths, or policy.

It is unauthenticated at the **application** layer only. `ssl_cert_reqs` is a
property of the listening socket rather than of a route, so **a probe with no
client certificate never completes the handshake and never reaches the
endpoint.** Either check that the TCP port accepts a connection — which is what
the container's `HEALTHCHECK` does — or issue the prober a CA-signed certificate
of its own. A `curl https://broker:8201/healthz` without one will report the
service down while it is running perfectly.

## Audit

One JSON object per line on stdout: container logs, or the journal under
systemd. Ship it somewhere NetBox cannot write, because that separation is one
of the three things this design actually buys.

Entries worth alerting on:

- `outcome=denied` with `reason=outside permitted prefixes` — an instance asking
  for something it was never configured to have. Either the policy is too narrow
  for legitimate use, or something is probing.
- `outcome=denied` with `reason=instance not configured` — a certificate from
  the trusted CA naming an unknown instance. Check whether the CA issued it.
- `outcome=denied` with `reason=invalid path: …` — traversal or an encoded
  path, refused before OpenBao was contacted.
- `operation=malformed` — a request that failed validation before it reached a
  handler. Ordinarily a client bug; in volume, someone mapping the API.

## Secret paths

Printable ASCII, no spaces, no percent-encoding, no `..` or `.` segments, no
leading slash. `netbox-openbao` generates `<prefix>/<uuid>`, which satisfies all
of it; the restriction only bites if you hand-write a prefix.

The percent-encoding rule is worth understanding before relaxing it. `requests`
decodes `%2e` to `.` while building the URL, so an encoded traversal passes a
literal `..` check and then reappears in the request. OpenBao 2.6.0 refuses to
resolve it — but that puts the boundary in the server's routing rather than in
the broker, where a proxy or a version bump removes it without anything failing
visibly.

## Upgrading

Stateless, so replace the process. The one thing to check on any dependency
upgrade is that the mTLS suite still passes: identity extraction depends on
uvicorn internals that the ASGI TLS extension does not yet cover natively (see
`broker/tls_scope.py`). That is exactly the kind of thing that breaks silently,
which is why it is tested against a real handshake rather than a stub.
