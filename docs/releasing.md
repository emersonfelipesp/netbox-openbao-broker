# Releasing packages

`netbox-openbao-broker` uses reviewed tags and immutable package versions. The
Gitea package registry is the internal package authority. TestPyPI and PyPI are
public validation and distribution channels. Never upload a local working tree
or replace an existing version.

## Supported Python versions

The package declares Python 3.11 or newer. CI validates the complete suite on
Python 3.11, 3.12, and 3.14. The matrix deliberately includes 3.14 because its
stricter OpenSSL certificate-chain validation exercises the test PKI used to
prove the broker's mTLS identity boundary. Every matrix leg must execute a
non-empty suite with zero skipped tests.

## Publication contract

1. Complete review, security checks, the per-function complexity audit, and all
   local and hosted CI gates on canonical `main`.
2. Create an annotated tag whose version exactly matches `[project].version`.
   Release candidates use `vX.Y.ZrcN`; final and repair releases use `vX.Y.Z`
   and `vX.Y.Z.postN`.
3. Dispatch the Gitea package workflow on `main` with that existing tag. It
   validates the tag against canonical `main`, builds from a clean `git archive`,
   checks exactly one wheel and one source distribution, and publishes with the
   repository-scoped `PACKAGE_WRITE_TOKEN`.
4. Push an RC tag to GitHub. The `v*rc*` trigger validates and publishes it only
   to TestPyPI with `TEST_PYPI_USERNAME` and `TEST_PYPI_TOKEN`.
5. Download both TestPyPI artifacts, verify their recorded sizes and SHA256
   digests, install the wheel in a clean environment, and run the smoke tests.
6. Publish the final GitHub Release only after the same final version exists in
   the Gitea registry. The `release: published` event validates that the final
   tag equals canonical `main` and publishes only to PyPI with `PYPI_TOKEN`.
7. Reconcile the Gitea package, GitHub tag and Release, TestPyPI, and PyPI. Record
   each artifact digest and preserve the successful workflow runs.

The manual GitHub dispatch accepts only an existing final or `.postN` tag and an
explicit `testpypi` or `pypi` target. It is a recovery route for a failed upload,
not a way to select different source. The validation job receives no publishing
credential. It transfers one checked artifact set to the isolated publish job,
whose conditional steps expose only the selected index's token. OIDC and trusted
publishing are intentionally not enabled while scoped API tokens are in use.

## Validation commands

```bash
ruff check .
pytest -q -ra --junitxml=results.xml
python -m build
python -m twine check dist/*
python scripts/validate_distributions.py \
  --dist dist --version 0.1.0 --source-sha "$(git rev-parse HEAD)" \
  --output release-manifest.json
radon cc -s -a broker scripts
```

Install the built wheel into a new environment with dependencies and import
`broker` from that environment, not from the repository working directory.
Confirm the distribution metadata reports the intended version. A build,
manifest, workflow, or test that cannot run is a failure, never a skip.
