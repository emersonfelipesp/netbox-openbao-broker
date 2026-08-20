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

## 2. Configure OpenBao

Create a policy scoped to exactly the prefixes the instance will declare, and an
AppRole bound to it. The broker's AppRole should be able to reach nothing the
policy in `config.toml` does not also permit — two independent limits, so a
mistake in either one is not sufficient on its own.

```hcl
path "secret/data/netbox/credentials/*"     { capabilities = ["create", "read", "update"] }
path "secret/metadata/netbox/credentials/*" { capabilities = ["read", "update", "list"] }
```

Note that `delete` is absent above. Grant it only if an instance sets
`may_delete = true`, and prefer leaving destruction to a human with a different
credential.

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
- `outcome=denied` with `reason=invalid path: …` — path traversal, refused
  before OpenBao was contacted.

## Upgrading

Stateless, so replace the process. The one thing to check on any dependency
upgrade is that the mTLS suite still passes: identity extraction depends on
uvicorn internals that the ASGI TLS extension does not yet cover natively (see
`broker/tls_scope.py`). That is exactly the kind of thing that breaks silently,
which is why it is tested against a real handshake rather than a stub.
