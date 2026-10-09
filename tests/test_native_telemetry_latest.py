"""Exercise native 0.143.0 precedence and excluded request context in real factories."""

import asyncio
import os
from typing import Any

import httpx
import pytest
from fastapi import FastAPI
from fastapi.telemetry import TelemetryConfig
from opentelemetry import context as otel_context
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.sampling import ALWAYS_ON
from opentelemetry.trace import SpanKind

TARGETS = ["broker"]


def application(target: str, config: TelemetryConfig, monkeypatch: pytest.MonkeyPatch) -> FastAPI:
    from broker.app import create_app
    from broker.config import BrokerConfig

    return create_app(BrokerConfig(openbao_url="https://vault.invalid", instances={}), telemetry=config)


def auto_configuration(environment: str | None, explicit: bool | None) -> bool:
    if explicit is not None:
        return explicit
    return (environment or "").lower() == "true"


def explicit_config(explicit: bool | None) -> TelemetryConfig:
    return {} if explicit is None else {"auto_configure": explicit}


@pytest.mark.parametrize("target", TARGETS)
@pytest.mark.parametrize("environment", [None, "", "false", "true", "TRUE"])
@pytest.mark.parametrize("explicit", [None, False, True])
def test_native_auto_configuration_precedence(
    target: str,
    environment: str | None,
    explicit: bool | None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("OTEL_SDK_DISABLED", raising=False)
    for name in ("OTEL_SERVICE_NAME", "OTEL_EXPORTER_OTLP_ENDPOINT", "FASTAPI_OTEL_AUTO_CONFIGURE"):
        monkeypatch.delenv(name, raising=False)
    if environment is not None:
        monkeypatch.setenv("FASTAPI_OTEL_AUTO_CONFIGURE", environment)
    config = explicit_config(explicit)
    original = dict(config)
    app = application(target, config, monkeypatch)
    expected = auto_configuration(environment, explicit)
    assert app._telemetry["auto_configure"] is expected
    assert config == original
    assert "OTEL_SERVICE_NAME" not in os.environ
    assert "OTEL_EXPORTER_OTLP_ENDPOINT" not in os.environ
    assert os.getenv("FASTAPI_OTEL_AUTO_CONFIGURE") == environment


async def exercise_context(app: FastAPI, fail: bool) -> list[Any]:
    from fastapi.telemetry._api import _REQUEST_TELEMETRY_KEY

    observations: list[Any] = []

    @app.get("/excluded-native-context")
    async def excluded() -> dict[str, bool]:
        observations.append(otel_context.get_value(_REQUEST_TELEMETRY_KEY))
        if fail:
            raise RuntimeError("The nested excluded-request failure is intentional.")
        return {"excluded": True}

    @app.get("/parent-native-context")
    async def parent() -> dict[str, int]:
        inherited = otel_context.get_value(_REQUEST_TELEMETRY_KEY)
        assert inherited is not None
        transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
        async with httpx.AsyncClient(transport=transport, base_url="http://local.test") as client:
            response = await client.get("/excluded-native-context")
        assert otel_context.get_value(_REQUEST_TELEMETRY_KEY) is inherited
        return {"nested_status": response.status_code}

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://local.test") as client:
        response = await client.get("/parent-native-context")
    assert response.json() == {"nested_status": 500 if fail else 200}
    return observations


@pytest.mark.parametrize("target", TARGETS)
@pytest.mark.parametrize("fail", [False, True])
def test_excluded_nested_context_restoration(
    target: str,
    fail: bool,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from fastapi.telemetry._api import _REQUEST_TELEMETRY_KEY

    monkeypatch.delenv("OTEL_SDK_DISABLED", raising=False)
    from opentelemetry.sdk.trace.export import SimpleSpanProcessor
    from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

    exporter = InMemorySpanExporter()
    provider = TracerProvider(sampler=ALWAYS_ON)
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    original = otel_context.get_value(_REQUEST_TELEMETRY_KEY)
    config: TelemetryConfig = {
        "auto_configure": False,
        "tracer_provider": provider,
        "operation_spans": True,
        "exclude": lambda scope: scope["path"] == "/excluded-native-context",
    }
    try:
        app = application(target, config, monkeypatch)
        assert asyncio.run(exercise_context(app, fail)) == [None]
        assert otel_context.get_value(_REQUEST_TELEMETRY_KEY) is original
        assert config["tracer_provider"] is provider
        spans = exporter.get_finished_spans()
        assert_native_parent_spans(spans)
    finally:
        provider.shutdown()


def assert_native_parent_spans(spans: Any) -> None:
    """Verify every enabled native child and its originating parent endpoint."""
    assert [span.name for span in spans] == [
        "fastapi.dependencies",
        "fastapi.endpoint",
        "fastapi.serialization",
        "GET /parent-native-context",
    ]
    parent_span = spans[-1]
    assert parent_span.kind is SpanKind.SERVER
    assert parent_span.parent is None
    for child in spans[:-1]:
        assert child.kind is SpanKind.INTERNAL
        assert child.context.trace_id == parent_span.context.trace_id
        assert child.parent.span_id == parent_span.context.span_id
    assert spans[1].attributes["code.function.name"] == (f"{__name__}.exercise_context.<locals>.parent")
