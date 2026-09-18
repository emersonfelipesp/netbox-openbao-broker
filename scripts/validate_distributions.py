#!/usr/bin/env python3
"""Validate and record the exact wheel and source distribution pair."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path

SHA_RE = re.compile(r"^[a-f0-9]{40}$")
VERSION_RE = re.compile(
    r"^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
    r"(?:rc[1-9][0-9]*|\.post[1-9][0-9]*)?$"
)


class DistributionError(ValueError):
    """The built distribution pair violates the release contract."""


def _validate_identity(version: str, source_sha: str) -> None:
    if VERSION_RE.fullmatch(version) is None or SHA_RE.fullmatch(source_sha) is None:
        raise DistributionError("Release identity is invalid")


def _release_files(dist: Path, version: str) -> list[Path]:
    files = sorted(path for path in dist.iterdir() if path.is_file())
    wheels = [path for path in files if path.name.endswith(".whl")]
    sdists = [path for path in files if path.name.endswith(".tar.gz")]
    if len(files) != 2 or len(wheels) != 1 or len(sdists) != 1:
        raise DistributionError("Release must contain exactly one wheel and one sdist")
    normalized_version = version.replace("-", "_")
    expected = {
        f"netbox_openbao_broker-{normalized_version}-py3-none-any.whl",
        f"netbox_openbao_broker-{normalized_version}.tar.gz",
    }
    if {path.name for path in files} != expected or any(path.is_symlink() for path in files):
        raise DistributionError("Release artifact identity is invalid")
    return files


def _artifact_record(path: Path) -> dict[str, object]:
    content = path.read_bytes()
    if not content:
        raise DistributionError("Release artifact is empty")
    return {"name": path.name, "sha256": hashlib.sha256(content).hexdigest(), "size": len(content)}


def create_manifest(dist: Path, version: str, source_sha: str) -> dict[str, object]:
    _validate_identity(version, source_sha)
    artifacts = [_artifact_record(path) for path in _release_files(dist, version)]
    return {
        "artifacts": artifacts,
        "package": "netbox-openbao-broker",
        "schema": 1,
        "source_sha": source_sha,
        "version": version,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dist", type=Path, required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    manifest = create_manifest(args.dist, args.version, args.source_sha)
    args.output.write_text(
        json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8"
    )


if __name__ == "__main__":
    main()
