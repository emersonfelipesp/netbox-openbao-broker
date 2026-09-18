# Working on netbox-openbao-broker

Read [`README.md`](README.md) first — particularly the threat model, which
constrains what may be claimed anywhere else in this repository.

## The one rule

**Keep it bounded.** The secret endpoints, health route, one versioned
administration envelope, and bounded snapshot routes are the complete surface.
There is no database or user model. A broker with an open-ended proxy is just
NetBox again, with a second authorization model to drift out of step with the
first. Adding a capability here needs a reason that survives that sentence.

## Traps that have already cost time

Each of these looks like a mistake and is not. Verify before "fixing".

- **`broker/tls_scope.py` exists because uvicorn does not implement the ASGI TLS
  extension.** `scope['transport']` is never populated. The subclass captures
  `ssl_object` in `connection_made` and injects `scope['extensions']['tls']`
  through a property setter. Overriding `handle_events()` instead means copying
  uvicorn's request loop and re-copying it on every upgrade. If uvicorn ever
  implements the extension natively, the application code keeps working and this
  module simply becomes unnecessary.

- **`tests/test_mtls.py` runs the broker as a subprocess, not a thread.**
  uvicorn in a thread alongside the test client produced SSL EOF errors
  unrelated to the code under test. Do not "simplify" it back.

- **Test certificates need `ExtendedKeyUsage`** — `clientAuth` or `serverAuth`.
  The test CA also needs `SubjectKeyIdentifier`, every leaf needs a matching
  `AuthorityKeyIdentifier`, and CA/leaf `BasicConstraints` and `KeyUsage` must
  describe their actual roles. Strict OpenSSL versions refuse an incomplete
  chain with a bare connection reset before the broker sees a request.

- **`docs_url=None` alone does not stop FastAPI serving `/openapi.json`.**
  `openapi_url=None` is what does. CI greps for this as well as testing it.

- **`normalize_path` refuses `%`, and this is load-bearing.** `requests` runs
  every URL through `requote_uri` → `unquote_unreserved`, which decodes escapes
  for unreserved characters. `.` is unreserved, so `%2e%2e/` becomes `../`
  *after* the check has passed. OpenBao 2.6.0 does not resolve the resulting
  dot-segments, so the live attempt 404s — do not read that as "the encoding
  rule is unnecessary". It means the boundary would otherwise live in OpenBao's
  routing rather than in this repository.
  `tests/test_encoded_traversal.py` pins both the refusal and the underlying
  property: whatever the check accepts must still be inside the prefix after
  `requote_uri` has rewritten it.

- **`ssl_cert_reqs=CERT_REQUIRED` is a property of the socket, so it gates
  `/healthz` too.** The endpoint is unauthenticated only at the application
  layer. Health probes must be a TCP connect or must carry a client certificate.

## Invariants the tests exist to protect

- **A refused request never reaches OpenBao.** Every denial test asserts on the
  fake vault's call log, not merely the status code. A broker that reads a
  secret and then declines to return it has already defeated its own purpose.
- **Every request is audited, refusals and unexpected errors included.**
  `run()` has a blanket `except Exception` for exactly this reason, and a
  `RequestValidationError` handler covers requests that never reach a handler
  at all — body validation runs before the identifying dependency.
- **Identity comes from the peer certificate and nowhere else.** No
  header-based fallback, no "trusted proxy" mode. Adding one would undo the
  design decision rather than extend it.
- **`AuditLog.record()` has no parameter a payload could travel through.** Keep
  it that way; a structural guarantee beats remembering not to pass one.
- **No test may be skipped in CI.** A skip would let a broken environment green
  the pipeline with the security tests never having run. The mTLS fixture fails
  rather than skips, and CI checks the JUnit report as a backstop.

## Contract with the plugin

`broker/vault.py` mirrors `netbox-openbao`'s `SecretBackend` ABC exactly,
because the plugin's `BrokerBackend` is a transport swap and nothing more. Any
divergence in semantics shows up as behaviour that differs depending on whether
broker mode is switched on. If the ABC changes, this changes with it.

**`may_delete` is a two-sided trade, and the documentation must state both
sides.** It was wrong in one direction (recommending `false` for production
without saying it orphans material), and correcting it invited being wrong in
the other (recommending `true` without saying what it hands a compromised
NetBox). Verify any change to this text against `netbox-openbao/services.py`
rather than against the previous paragraph:

Every claim below describes what happens when the delete is **refused** — by
`may_delete = false`, or equivalently by an OpenBao policy that withholds the
capability. With `true`, the delete proceeds and none of this arises.

- **Deleting a credential** runs `delete_material` from a `post_delete` signal
  deferred to `transaction.on_commit`. The signal handler swallows the failure,
  because the row is already gone and raising could not undo it. This is the
  only path that leaves material behind **silently**.
- **A rolled-back write** compensates in `store_credential`'s `except` block and
  then **re-raises the original exception**. The caller's operation fails. Do
  not describe this one as silent.
- **`discard_staged`** also deletes, and **re-raises**. It leaves nothing behind.
- **`true` makes a NetBox compromise destructive.** A version-less delete maps to
  `delete_metadata_and_all_versions`, which is permanent — every credential under
  the instance's prefix. Reading was already reachable; destroying was not.

**Do not write that the residue cannot be found — and do not write that finding
it is free.** Both errors were made in successive revisions of this file.

It *is* identifiable: every credential carries KV v2 `custom_metadata` with
`managed_by: netbox-openbao` and its NetBox UUID, so an entry matching no
`Credential` row can be picked out by listing the prefix and reading metadata,
without reading a single secret value. Say "no automatic reconciler", never
"unrecoverable".

The baseline secret surface cannot run that listing. An instance explicitly
granted administration families may enumerate only through the reviewed closed
contract. A secret-only deployment needs a *separate* read-only identity talking
to OpenBao directly, which `docs/deployment.md` provisions. Any future text
recommending `may_delete = false` must distinguish those deployment modes.

The denied-delete audit record is **an informational correlation event, not an
alert**. On a `may_delete = false` instance it is an ordinary consequence of
normal cleanup, so paging on it produces noise that gets muted — taking the
interesting cases with it. It is emitted for all three plugin paths above and for
any direct call by a certificate holder, and the broker cannot distinguish them.
Alert on the plugin's `ORPHANED SECRET` line and on a non-empty reconciliation
result; those name something actionable.

**Every instance block is a separate client identity.** The broker selects by
subject CN, so a read-only consumer needs its own certificate. A documentation
example that adds a read-only instance without saying so describes a protection
that does not exist.

Keep the `may_delete` values in the README, `deploy/config.toml.example`, and
the OpenBao policy in `docs/deployment.md` aligned — refusing delete at either
limit produces the same residue, with the added confusion of configuration that
says otherwise.

## Development

```bash
pip install -e '.[dev]'
pytest && ruff check .
```

The whole suite is self-contained — no NetBox, no database, no live OpenBao —
so there is no excuse for pushing without running it.

The supported CI matrix is Python 3.11, 3.12, and 3.14. Every leg must run a
non-empty suite with zero skips. Package releases additionally follow
[`docs/releasing.md`](docs/releasing.md); public artifacts must be built from a
validated existing tag on canonical `main`, never from a working checkout.

For an end-to-end check against a real OpenBao, build the image and run it with
`deploy/docker-compose.yml`; that is what surfaced the startup-credential and
unaudited-500 defects that in-process tests had passed straight over.
