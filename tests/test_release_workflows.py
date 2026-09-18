"""Executable release-policy and workflow-shape contracts."""

from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
GIT = Path("/usr/bin/git")
PUBLIC = ROOT / ".github/workflows/publish.yml"
GITEA = ROOT / ".gitea/workflows/publish-package.yml"
CI = ROOT / ".github/workflows/ci.yml"
REF_VALIDATOR = ROOT / "scripts/validate_release_ref.py"
ROUTE_SELECTOR = ROOT / "scripts/select_public_release_target.py"
DIST_VALIDATOR = ROOT / "scripts/validate_distributions.py"


def _module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _git(repository: Path, *arguments: str) -> str:
    return subprocess.run(
        [str(GIT), "-C", str(repository), *arguments],
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    ).stdout.strip()


def _commit_version(repository: Path, version: str, message: str) -> str:
    (repository / "pyproject.toml").write_text(
        f'[project]\nname = "netbox-openbao-broker"\nversion = "{version}"\n',
        encoding="utf-8",
    )
    _git(repository, "add", "pyproject.toml")
    _git(repository, "commit", "-m", message)
    return _git(repository, "rev-parse", "HEAD")


def _repository(tmp_path: Path) -> Path:
    repository = tmp_path / "repository"
    repository.mkdir()
    _git(repository, "init", "-b", "main")
    _git(repository, "config", "user.email", "release-test@example.invalid")
    _git(repository, "config", "user.name", "Release Test")
    return repository


@pytest.mark.parametrize("path", [PUBLIC, GITEA, CI])
def test_workflow_yaml_and_shell_blocks_parse(path: Path) -> None:
    workflow = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert isinstance(workflow, dict)
    for job in workflow["jobs"].values():
        for step in job.get("steps", []):
            script = step.get("run")
            if not isinstance(script, str):
                continue
            result = subprocess.run(
                ["/bin/bash", "-n"], input=script, capture_output=True, text=True, timeout=10
            )
            assert result.returncode == 0, f"{path}: {step.get('name')}: {result.stderr}"


def test_all_actions_are_immutable_sha_pinned() -> None:
    for path in (PUBLIC, GITEA, CI):
        for line in path.read_text(encoding="utf-8").splitlines():
            if "uses:" not in line:
                continue
            revision = line.split("uses:", 1)[1].split("#", 1)[0].strip().rsplit("@", 1)[1]
            assert len(revision) == 40
            assert all(character in "0123456789abcdef" for character in revision)


def test_public_trigger_and_source_policy_is_closed() -> None:
    text = PUBLIC.read_text(encoding="utf-8")
    assert 'tags: ["v*rc*"]' in text
    assert "types: [published]" in text
    assert "workflow_dispatch:" in text
    assert "+refs/heads/main:refs/release-policy/main" in text
    assert "+refs/tags/${tag}:refs/release-policy/candidate" in text
    assert "scripts/validate_release_ref.py" in text
    assert "scripts/validate_distributions.py" in text
    assert 'tags: ["v*"]' not in text
    assert "id-token: write" not in text
    assert text.count("actions/upload-artifact@") == 1
    assert text.count("actions/download-artifact@") == 1


def test_public_credentials_are_target_isolated() -> None:
    text = PUBLIC.read_text(encoding="utf-8").split("  publish:", 1)[1]
    assert text.count("pypa/gh-action-pypi-publish@") == 2
    assert "secrets.TEST_PYPI_USERNAME" in text
    assert "secrets.TEST_PYPI_TOKEN" in text
    assert "secrets.PYPI_TOKEN" in text
    assert "secrets.PYPI_USERNAME" not in text
    assert "needs.validate-build.outputs.target == 'testpypi'" in text
    assert "needs.validate-build.outputs.target == 'pypi'" in text
    assert text.count("attestations: false") == 2


def test_gitea_publication_uses_only_package_write_token() -> None:
    text = GITEA.read_text(encoding="utf-8")
    assert text.count("secrets.PACKAGE_WRITE_TOKEN") == 1
    assert "secrets.PYPI_TOKEN" not in text
    assert "secrets.TEST_PYPI_TOKEN" not in text
    assert "scripts/validate_release_ref.py" in text
    assert "python3 -m build" not in text
    assert '"$release_root/.venv/bin/python" -m build' in text


def test_ci_covers_supported_interpreters_and_refuses_skips() -> None:
    text = CI.read_text(encoding="utf-8")
    assert 'python-version: ["3.11", "3.12", "3.14"]' in text
    assert "--junitxml=results.xml" in text
    assert 'suite.get("skipped", "0")' in text
    assert "if not total or skipped:" in text


@pytest.mark.parametrize(
    ("event", "target", "expected"),
    [
        ("push", "", ("rc", "testpypi", "https://test.pypi.org/legacy/")),
        ("release", "", ("final", "pypi", "https://upload.pypi.org/legacy/")),
        (
            "workflow_dispatch",
            "testpypi",
            ("final", "testpypi", "https://test.pypi.org/legacy/"),
        ),
        (
            "workflow_dispatch",
            "pypi",
            ("final", "pypi", "https://upload.pypi.org/legacy/"),
        ),
    ],
)
def test_release_route_matrix(event: str, target: str, expected: tuple[str, str, str]) -> None:
    selector = _module("route_selector", ROUTE_SELECTOR)
    assert selector.select_release_route(event, target) == expected


@pytest.mark.parametrize(
    ("event", "target"),
    [("workflow_dispatch", ""), ("workflow_dispatch", "other"), ("pull_request", "pypi")],
)
def test_release_route_rejects_every_unreviewed_path(event: str, target: str) -> None:
    selector = _module("route_selector_invalid", ROUTE_SELECTOR)
    with pytest.raises(ValueError, match="Unsupported public release event or target"):
        selector.select_release_route(event, target)


def test_final_tag_must_equal_canonical_main(tmp_path: Path) -> None:
    validator = _module("ref_validator_final", REF_VALIDATOR)
    repository = _repository(tmp_path)
    _commit_version(repository, "0.1.0", "release")
    _git(repository, "tag", "-a", "v0.1.0", "-m", "Release 0.1.0")
    _commit_version(repository, "0.1.0.post1", "main advanced")
    _git(repository, "update-ref", "refs/release-policy/candidate", "v0.1.0")
    _git(repository, "update-ref", "refs/release-policy/main", "main")
    with pytest.raises(validator.ReleaseRefError, match="must equal canonical main"):
        validator.validate_release_ref(repository=repository, tag="v0.1.0", event="final")


def test_rc_tag_may_be_an_ancestor_of_canonical_main(tmp_path: Path) -> None:
    validator = _module("ref_validator_rc", REF_VALIDATOR)
    repository = _repository(tmp_path)
    tagged = _commit_version(repository, "0.1.0rc1", "candidate")
    _git(repository, "tag", "-a", "v0.1.0rc1", "-m", "Release 0.1.0rc1")
    _commit_version(repository, "0.1.0", "main advanced")
    _git(repository, "update-ref", "refs/release-policy/candidate", "v0.1.0rc1")
    _git(repository, "update-ref", "refs/release-policy/main", "main")
    result = validator.validate_release_ref(repository=repository, tag="v0.1.0rc1", event="rc")
    assert result["source_sha"] == tagged


def test_release_ref_rejects_version_mismatch(tmp_path: Path) -> None:
    validator = _module("ref_validator_version", REF_VALIDATOR)
    repository = _repository(tmp_path)
    _commit_version(repository, "0.1.1", "wrong version")
    _git(repository, "tag", "-a", "v0.1.0", "-m", "Release 0.1.0")
    _git(repository, "update-ref", "refs/release-policy/candidate", "v0.1.0")
    _git(repository, "update-ref", "refs/release-policy/main", "main")
    with pytest.raises(validator.ReleaseRefError, match="differs from the tag"):
        validator.validate_release_ref(repository=repository, tag="v0.1.0", event="final")


def test_release_ref_rejects_lightweight_tag(tmp_path: Path) -> None:
    validator = _module("ref_validator_lightweight", REF_VALIDATOR)
    repository = _repository(tmp_path)
    _commit_version(repository, "0.1.0", "release")
    _git(repository, "tag", "v0.1.0")
    _git(repository, "update-ref", "refs/release-policy/candidate", "v0.1.0")
    _git(repository, "update-ref", "refs/release-policy/main", "main")
    with pytest.raises(validator.ReleaseRefError, match="must be annotated"):
        validator.validate_release_ref(repository=repository, tag="v0.1.0", event="final")


@pytest.mark.parametrize("tag", ["v0.1", "v0.1.0rc0", "v0.1.0;touch-pwned", "refs/heads/main"])
def test_release_ref_rejects_hostile_or_ambiguous_tags(tmp_path: Path, tag: str) -> None:
    validator = _module(f"ref_validator_bad_{len(tag)}", REF_VALIDATOR)
    repository = _repository(tmp_path)
    _commit_version(repository, "0.1.0", "release")
    with pytest.raises(validator.ReleaseRefError, match="does not match"):
        validator.validate_release_ref(repository=repository, tag=tag, event="final")


def test_distribution_manifest_binds_exact_pair_and_bytes(tmp_path: Path) -> None:
    validator = _module("dist_validator", DIST_VALIDATOR)
    wheel = tmp_path / "netbox_openbao_broker-0.1.0-py3-none-any.whl"
    sdist = tmp_path / "netbox_openbao_broker-0.1.0.tar.gz"
    wheel.write_bytes(b"wheel")
    sdist.write_bytes(b"sdist")
    manifest = validator.create_manifest(tmp_path, "0.1.0", "a" * 40)
    assert manifest["package"] == "netbox-openbao-broker"
    assert {item["name"] for item in manifest["artifacts"]} == {wheel.name, sdist.name}


def test_distribution_manifest_fails_closed_on_extra_file(tmp_path: Path) -> None:
    validator = _module("dist_validator_extra", DIST_VALIDATOR)
    for name in (
        "netbox_openbao_broker-0.1.0-py3-none-any.whl",
        "netbox_openbao_broker-0.1.0.tar.gz",
        "unexpected.txt",
    ):
        (tmp_path / name).write_bytes(b"x")
    with pytest.raises(validator.DistributionError, match="exactly one"):
        validator.create_manifest(tmp_path, "0.1.0", "b" * 40)


def test_distribution_manifest_rejects_another_project(tmp_path: Path) -> None:
    validator = _module("dist_validator_wrong_project", DIST_VALIDATOR)
    for name in (
        "totally_different_project-0.1.0-py3-none-any.whl",
        "totally_different_project-0.1.0.tar.gz",
    ):
        (tmp_path / name).write_bytes(b"not the broker")
    with pytest.raises(validator.DistributionError, match="identity is invalid"):
        validator.create_manifest(tmp_path, "0.1.0", "c" * 40)


def test_release_ref_cli_writes_only_validated_outputs(tmp_path: Path) -> None:
    repository = _repository(tmp_path)
    source_sha = _commit_version(repository, "0.1.0", "release")
    _git(repository, "tag", "-a", "v0.1.0", "-m", "Release 0.1.0")
    _git(repository, "update-ref", "refs/release-policy/candidate", "v0.1.0")
    _git(repository, "update-ref", "refs/release-policy/main", "main")
    output = tmp_path / "github-output"
    result = subprocess.run(
        [
            sys.executable,
            str(REF_VALIDATOR),
            "--repository",
            str(repository),
            "--tag",
            "v0.1.0",
            "--event",
            "final",
            "--expected-head",
            source_sha,
            "--github-output",
            str(output),
        ],
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 0, result.stderr
    assert f"source_sha={source_sha}" in output.read_text(encoding="utf-8")
