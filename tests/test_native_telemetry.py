"""Verify public opt-in and real native exports in isolated processes."""

import os
import subprocess
import sys
from pathlib import Path

import pytest

from broker.app import create_app
from broker.config import BrokerConfig


@pytest.mark.parametrize(
    "mode",
    [
        "enabled",
        "disabled",
        "empty",
        "absent",
        "signals",
        "metrics-disabled",
        "logs-only",
        "override",
        "explicit",
        "empty-caller",
        "custom",
        "raw",
    ],
)
def test_native_otlp_in_fresh_process(mode: str) -> None:
    environment = {key: value for key, value in os.environ.items() if not key.startswith("OTEL_")}
    result = subprocess.run(
        [sys.executable, str(Path(__file__).with_name("telemetry_probe.py")), mode],
        env=environment,
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert f"Native actual OTLP signals, privacy, and lifecycle verified: {mode}" in result.stdout


def test_public_configuration_is_opt_in(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("OTEL_SERVICE_NAME", raising=False)
    monkeypatch.delenv("OTEL_EXPORTER_OTLP_ENDPOINT", raising=False)
    create_app(BrokerConfig(openbao_url="https://vault.invalid", instances={}))
    assert "OTEL_SERVICE_NAME" not in os.environ
    assert "OTEL_EXPORTER_OTLP_ENDPOINT" not in os.environ


def test_operator_configuration_is_preserved(monkeypatch: pytest.MonkeyPatch) -> None:
    controls = {
        "OTEL_SERVICE_NAME": "operator",
        "OTEL_EXPORTER_OTLP_ENDPOINT": "",
        "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT": "http://localhost:4318/traces",
        "OTEL_TRACES_EXPORTER": "none",
        "OTEL_SDK_DISABLED": "true",
    }
    for key, value in controls.items():
        monkeypatch.setenv(key, value)
    create_app(BrokerConfig(openbao_url="https://vault.invalid", instances={}))
    assert all(os.environ[key] == value for key, value in controls.items())


@pytest.mark.parametrize(
    "tracing,logs,automatic",
    [(False, False, True), (True, False, True), (False, True, True), (True, True, False)],
)
def test_native_signal_flags_gate_only_implicit_provider_creation(
    tracing: bool, logs: bool, automatic: bool
) -> None:
    program = r"""
import os
import sys
from fastapi.testclient import TestClient
from opentelemetry import trace, _logs
os.environ["OTEL_SDK_DISABLED"] = "true"
os.environ["OTEL_EXPORTER_OTLP_ENDPOINT"] = "http://127.0.0.1:1"
from broker.app import create_app
from broker.config import BrokerConfig
before = (trace.get_tracer_provider(), _logs.get_logger_provider())
os.environ["OTEL_SDK_DISABLED"] = "false"
os.environ["FASTAPI_OTEL_AUTO_CONFIGURE"] = "true"
tracing, logs, automatic = (value == "true" for value in sys.argv[1:])
application = create_app(BrokerConfig(openbao_url="https://vault.invalid", instances={}), telemetry={
    "tracing": tracing, "logs": logs, "metrics": False, "auto_configure": automatic,
})
after = (trace.get_tracer_provider(), _logs.get_logger_provider())
assert (after[0] is not before[0]) is (tracing and automatic)
assert (after[1] is not before[1]) is (logs and automatic)
if not tracing and not logs:
    @application.get("/__native_flags")
    def status():
        return {"ready": True}
    with TestClient(application) as client:
        assert client.get("/__native_flags").status_code == 200
    assert trace.get_tracer_provider() is before[0]
    assert _logs.get_logger_provider() is before[1]
print("Native signal flags preserve disabled implicit providers.")
"""
    environment = {key: value for key, value in os.environ.items() if not key.startswith("OTEL_")}
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            program,
            *[str(value).lower() for value in (tracing, logs, automatic)],
        ],
        env=environment,
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "Native signal flags preserve disabled implicit providers." in result.stdout
