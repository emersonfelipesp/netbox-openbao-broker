"""Verify real native OTLP export against an isolated loopback collector."""

from __future__ import annotations

import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from fastapi import Body, FastAPI, WebSocket
from fastapi.testclient import TestClient
from opentelemetry import _logs, metrics, trace
from opentelemetry.proto.collector.logs.v1.logs_service_pb2 import ExportLogsServiceRequest
from opentelemetry.proto.collector.metrics.v1.metrics_service_pb2 import ExportMetricsServiceRequest
from opentelemetry.proto.collector.trace.v1.trace_service_pb2 import ExportTraceServiceRequest
from opentelemetry.sdk._logs import LoggerProvider
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider

payloads: dict[str, list[bytes]] = {}
headers: list[str | None] = []


class Collector(BaseHTTPRequestHandler):
    def do_POST(self) -> None:
        payloads.setdefault(self.path, []).append(self.rfile.read(int(self.headers["Content-Length"])))
        headers.append(self.headers.get("X-Probe-Token"))
        self.send_response(200)
        self.end_headers()

    def log_message(self, *_args: object) -> None:
        pass


os.environ["FASTAPI_OTEL_AUTO_CONFIGURE"] = "true"
mode = sys.argv[1]
server = ThreadingHTTPServer(("127.0.0.1", 0), Collector)
thread = threading.Thread(target=server.serve_forever, daemon=True)
thread.start()
endpoint = f"http://127.0.0.1:{server.server_port}"
os.environ["OTEL_EXPORTER_OTLP_ENDPOINT"] = endpoint
if mode == "absent":
    os.environ.pop("OTEL_EXPORTER_OTLP_ENDPOINT")
os.environ["OTEL_EXPORTER_OTLP_HEADERS"] = "x-probe-token=collector-header-canary"
os.environ["OTEL_SERVICE_NAME"] = "broker-probe"
if mode == "disabled":
    os.environ["OTEL_SDK_DISABLED"] = "true"
if mode == "empty":
    os.environ["OTEL_EXPORTER_OTLP_ENDPOINT"] = ""
if mode == "signals":
    os.environ["OTEL_TRACES_EXPORTER"] = "none"
    os.environ["OTEL_LOGS_EXPORTER"] = "none"
    os.environ["OTEL_EXPORTER_OTLP_METRICS_ENDPOINT"] = endpoint + "/custom/metrics"
if mode == "metrics-disabled":
    os.environ["OTEL_METRICS_EXPORTER"] = "none"
if mode == "logs-only":
    os.environ["OTEL_EXPORTER_OTLP_ENDPOINT"] = ""
    os.environ["OTEL_EXPORTER_OTLP_LOGS_ENDPOINT"] = endpoint + "/v1/logs"
    os.environ["OTEL_TRACES_EXPORTER"] = "none"
    os.environ["OTEL_METRICS_EXPORTER"] = "none"
if mode == "override":
    os.environ["OTEL_EXPORTER_OTLP_TRACES_ENDPOINT"] = endpoint + "/custom/traces"

providers = {}
if mode in {"explicit", "custom", "empty-caller"}:
    resource = Resource.create({"service.name": "operator-provider"})
    providers = {
        "tracer_provider": TracerProvider(resource=resource),
        "meter_provider": MeterProvider(resource=resource),
        "logger_provider": LoggerProvider(resource=resource),
    }
    if mode == "custom":
        trace.set_tracer_provider(providers["tracer_provider"])
        metrics.set_meter_provider(providers["meter_provider"])
        _logs.set_logger_provider(providers["logger_provider"])

if mode == "raw":
    app = FastAPI()
else:
    from broker.app import create_app  # noqa: E402
    from broker.config import BrokerConfig

    config = BrokerConfig(openbao_url="https://vault.invalid", instances={})
    configuration = providers if mode in {"explicit", "empty-caller"} else None
    if mode == "empty-caller":
        configuration = {**providers, "auto_configure": False}
        for signal in ("", "_TRACES", "_LOGS", "_METRICS"):
            os.environ[f"OTEL_EXPORTER_OTLP{signal}_ENDPOINT"] = ""
    app = create_app(config, telemetry=configuration)

if mode == "empty-caller":
    from opentelemetry.exporter.otlp.proto.http._log_exporter import OTLPLogExporter
    from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
    from opentelemetry.sdk._logs.export import SimpleLogRecordProcessor
    from opentelemetry.sdk.trace.export import SimpleSpanProcessor

    # Caller exporters follow privacy registration; the application does not own them.
    providers["tracer_provider"].add_span_processor(
        SimpleSpanProcessor(OTLPSpanExporter(endpoint=endpoint + "/v1/traces"))
    )
    providers["logger_provider"].add_log_record_processor(
        SimpleLogRecordProcessor(OTLPLogExporter(endpoint=endpoint + "/v1/logs"))
    )


@app.get("/__probe/{number}")
def read_number(number: int) -> dict[str, int]:
    return {"number": number}


@app.post("/__body")
def read_body(password: int = Body(embed=True)) -> dict[str, int]:
    return {"password": password}


@app.get("/__failure")
def error() -> None:
    raise RuntimeError("exception-secret-canary")


@app.websocket("/__socket")
async def socket(connection: WebSocket) -> None:
    await connection.accept()
    await connection.send_text("ready")
    await connection.close()


@app.websocket("/__socket_failure")
async def socket_failure(connection: WebSocket) -> None:
    await connection.accept()
    raise RuntimeError("websocket-exception-secret-canary")


def run_requests() -> None:
    for _ in range(2):
        with TestClient(app, raise_server_exceptions=False) as client:
            assert client.get("/__probe/7").json() == {"number": 7}
            assert client.get("/__probe/invalid").status_code == 422
            assert (
                client.get(
                    "/__probe/path-secret-canary?streamToken=query-secret-canary",
                    headers={
                        "Authorization": "Bearer authorization-secret-canary",
                        "Cookie": "session=cookie-secret-canary",
                    },
                ).status_code
                == 422
            )
            assert (
                client.post("/__body", json={"password": "validation-body-secret-canary"}).status_code == 422
            )
            assert client.get("/__failure").status_code == 500
            with client.websocket_connect("/__socket") as connection:
                assert connection.receive_text() == "ready"
            try:
                with client.websocket_connect("/__socket_failure") as connection:
                    connection.receive_text()
            except RuntimeError as exc:
                assert str(exc) == "websocket-exception-secret-canary"


def decode_payloads() -> tuple[list, list, set[str], set[str]]:
    specifications = {
        "/v1/traces": (ExportTraceServiceRequest, "resource_spans", "scope_spans", "spans", "traces"),
        "/custom/traces": (ExportTraceServiceRequest, "resource_spans", "scope_spans", "spans", "traces"),
        "/v1/metrics": (
            ExportMetricsServiceRequest,
            "resource_metrics",
            "scope_metrics",
            "metrics",
            "metrics",
        ),
        "/custom/metrics": (
            ExportMetricsServiceRequest,
            "resource_metrics",
            "scope_metrics",
            "metrics",
            "metrics",
        ),
        "/v1/logs": (ExportLogsServiceRequest, "resource_logs", "scope_logs", "log_records", "logs"),
    }
    records: dict[str, list] = {"traces": [], "metrics": [], "logs": []}
    resource_names: set[str] = set()
    for path, batches in payloads.items():
        decoder, resource_field, scope_field, record_field, signal = specifications[path]
        for payload in batches:
            decoded = decoder.FromString(payload)
            assert decoded.ListFields()
            for resource in getattr(decoded, resource_field):
                resource_names.update(
                    value.value.string_value
                    for value in resource.resource.attributes
                    if value.key == "service.name"
                )
                for scope in getattr(resource, scope_field):
                    records[signal].extend(getattr(scope, record_field))
    return records["traces"], records["logs"], {metric.name for metric in records["metrics"]}, resource_names


try:
    run_requests()
    if mode in {"disabled", "empty", "absent"}:
        assert not payloads, payloads.keys()
    elif mode == "signals":
        assert set(payloads) == {"/custom/metrics"}, payloads.keys()
        assert "http.server.request.duration" in decode_payloads()[2]
    elif mode == "metrics-disabled":
        assert set(payloads) == {"/v1/traces", "/v1/logs"}, payloads.keys()
        assert decode_payloads()[0]
        assert decode_payloads()[1]
        assert not decode_payloads()[2]
    elif mode == "logs-only":
        assert set(payloads) == {"/v1/logs"}, payloads.keys()
        assert decode_payloads()[1]
        assert b"exception-secret-canary" not in b"".join(payloads["/v1/logs"])
    else:
        trace_path = "/custom/traces" if mode == "override" else "/v1/traces"
        expected_paths = {trace_path, "/v1/logs"}
        if mode != "empty-caller":
            expected_paths.add("/v1/metrics")
        assert set(payloads) == expected_paths, payloads.keys()
        spans, logs, metric_names, resource_names = decode_payloads()
        assert resource_names == ({"operator-provider"} if providers else {"broker-probe"})
        assert sum(span.name == "GET /__probe/{number}" for span in spans) == 6
        assert sum(span.name == "WS /__socket" for span in spans) == 2
        assert sum(span.name == "WS /__socket_failure" for span in spans) == 2
        if mode != "empty-caller":
            assert "http.server.request.duration" in metric_names
        assert len(logs) == 10, len(logs)
        assert any(record.event_name == "fastapi.validation.failed" for record in logs)
        assert any(record.event_name == "fastapi.websocket.exception" for record in logs)
        assert any(attribute.key == "exception.type" for record in logs for attribute in record.attributes)
        exported = b"".join(payload for batches in payloads.values() for payload in batches)
        for canary in [
            b"authorization-secret-canary",
            b"cookie-secret-canary",
            b"validation-body-secret-canary",
            b"collector-header-canary",
        ]:
            assert canary not in exported
        for canary in [
            b"path-secret-canary",
            b"query-secret-canary",
            b"exception-secret-canary",
            b"websocket-exception-secret-canary",
        ]:
            assert (canary in exported) is (mode == "raw"), canary
        from fastapi.telemetry import _runtime

        assert len(_runtime._configured) == (0 if mode == "empty-caller" else 3)
        if mode == "custom":
            assert trace.get_tracer_provider() is providers["tracer_provider"]
            assert metrics.get_meter_provider() is providers["meter_provider"]
            assert _logs.get_logger_provider() is providers["logger_provider"]
        if providers:
            with (
                providers["tracer_provider"]
                .get_tracer("ownership-probe")
                .start_as_current_span("still-owned") as span
            ):
                assert span.is_recording()
    assert all(value == "collector-header-canary" for value in headers)
finally:
    from fastapi.telemetry import _runtime

    _runtime._shutdown()
    for provider in providers.values():
        provider.shutdown()
    server.shutdown()
    server.server_close()
    thread.join(timeout=5)
    assert not thread.is_alive()
print(f"Native actual OTLP signals, privacy, and lifecycle verified: {mode}")
