# Changelog

All notable changes to `netbox-openbao-broker` are documented here. Published
versions are immutable; corrections use a new release or `.postN` version.

## 0.1.0 — 2026-09-18

Initial public release.

- Added an mTLS-authenticated broker that keeps OpenBao credentials outside the
  NetBox host while preserving instance-scoped secret access.
- Added six bounded credential endpoints and an opt-in, digest-bound
  administration contract backed by a closed operation registry.
- Added strict path, schema, response-size, redirect, timeout, audit, and Raft
  snapshot boundaries.
- Added container, systemd, certificate, OpenBao policy, reconciliation, and
  incident guidance.
- Added package validation and immutable publication workflows for the Gitea
  package registry, TestPyPI, and PyPI.
