"""Protect native FastAPI telemetry exports without enabling remote export."""

import os
from weakref import WeakSet

from opentelemetry import _logs, trace
from opentelemetry._logs._internal import ProxyLoggerProvider
from opentelemetry.context import Context
from opentelemetry.sdk._logs import LoggerProvider, LogRecordProcessor, ReadWriteLogRecord
from opentelemetry.sdk.trace import Span, SpanProcessor, TracerProvider

_configured: WeakSet[LoggerProvider] = WeakSet()
_tracers: WeakSet[TracerProvider] = WeakSet()


class ExceptionPrivacyProcessor(LogRecordProcessor):
    """Keep native error classification without arbitrary exception content."""

    def on_emit(self, log_record: ReadWriteLogRecord) -> None:
        """Remove arbitrary exception content from native FastAPI log attributes."""
        if log_record.instrumentation_scope and log_record.instrumentation_scope.name == "fastapi":
            attributes = dict(log_record.log_record.attributes or {})
            attributes.pop("exception.message", None)
            attributes.pop("exception.stacktrace", None)
            log_record.log_record.attributes = attributes

    def shutdown(self) -> None:
        """No resources are owned by this processor."""

    def force_flush(self, timeout_millis: int = 30000) -> bool:  # noqa: ARG002
        """Report successful flushing because this processor owns no buffer."""
        return True


def _environment_export(signal: str) -> bool:
    """Create default providers only when native environment export is enabled."""
    if os.getenv("OTEL_SDK_DISABLED", "").lower() == "true":
        return False
    return (os.getenv(f"OTEL_{signal}_EXPORTER") or "otlp").strip().lower() != "none" and bool(
        os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT") or os.getenv(f"OTEL_EXPORTER_OTLP_{signal}_ENDPOINT")
    )


def configure_log_privacy(
    provider: _logs.LoggerProvider | None = None, *, auto_configure: bool = True
) -> None:
    """Register before FastAPI attaches native exporters at lifespan startup."""
    explicit = provider is not None
    if provider is None:
        provider = _logs.get_logger_provider()
    if (
        isinstance(provider, ProxyLoggerProvider)
        and not explicit
        and auto_configure
        and _environment_export("LOGS")
    ):
        provider = LoggerProvider()
        _logs.set_logger_provider(provider)
    if isinstance(provider, LoggerProvider) and provider not in _configured:
        provider.add_log_record_processor(ExceptionPrivacyProcessor())
        _configured.add(provider)


class QueryPrivacyProcessor(SpanProcessor):
    """Remove query values before any span exporter can observe them."""

    def on_start(self, span: Span, parent_context: Context | None = None) -> None:  # noqa: ARG002
        """Redact native request metadata before any exporter can observe it."""
        scope = span.instrumentation_scope
        if not scope or scope.name != "fastapi":
            return
        for attribute in ("url.path", "url.query"):
            if attribute in (span.attributes or {}):
                span.set_attribute(attribute, "REDACTED")


def configure_trace_privacy(
    provider: trace.TracerProvider | None = None, *, auto_configure: bool = True
) -> None:
    """Keep native spans without exporting caller-controlled query values."""
    explicit = provider is not None
    if provider is None:
        provider = trace.get_tracer_provider()
    if (
        isinstance(provider, trace.ProxyTracerProvider)
        and not explicit
        and auto_configure
        and _environment_export("TRACES")
    ):
        provider = TracerProvider()
        trace.set_tracer_provider(provider)
    if isinstance(provider, TracerProvider) and provider not in _tracers:
        provider.add_span_processor(QueryPrivacyProcessor())
        _tracers.add(provider)
