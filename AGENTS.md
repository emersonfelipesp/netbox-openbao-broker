# Working on netbox-openbao-broker

Read [`README.md`](README.md) first — particularly the threat model, which
constrains what may be claimed anywhere else in this repository.

## The one rule

**Keep it small.** Six endpoints plus health, no database, no user model, one
authorization rule. A broker with a rich API is just NetBox again, with a second
authorization model to drift out of step with the first. Adding a capability
here needs a reason that survives that sentence.

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
  Without it OpenSSL refuses with a bare connection reset and nothing logged on
  either side.

- **`docs_url=None` alone does not stop FastAPI serving `/openapi.json`.**
  `openapi_url=None` is what does. CI greps for this as well as testing it.

- **`ssl_cert_reqs=CERT_REQUIRED` is a property of the socket, so it gates
  `/healthz` too.** The endpoint is unauthenticated only at the application
  layer. Health probes must be a TCP connect or must carry a client certificate.

## Invariants the tests exist to protect

- **A refused request never reaches OpenBao.** Every denial test asserts on the
  fake vault's call log, not merely the status code. A broker that reads a
  secret and then declines to return it has already defeated its own purpose.
- **Every request is audited, refusals and unexpected errors included.**
  `run()` has a blanket `except Exception` for exactly this reason.
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

## Development

```bash
pip install -e '.[dev]'
pytest && ruff check .
```

The whole suite is self-contained — no NetBox, no database, no live OpenBao —
so there is no excuse for pushing without running it.

For an end-to-end check against a real OpenBao, build the image and run it with
`deploy/docker-compose.yml`; that is what surfaced the startup-credential and
unaudited-500 defects that in-process tests had passed straight over.
