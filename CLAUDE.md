@AGENTS.md

### Caller-managed telemetry privacy

Sanitize selected real SDK providers even when all endpoint environment values are
empty or auto_configure=False. Gate only Proxy-to-SDK creation on endpoint and
signal exporter eligibility. Preserve caller identity and shutdown ownership,
and register privacy processors before caller log exporters. The actual
empty-caller loopback regression must retain path, query and exception redaction.

Native `tracing=False` and `logs=False` also prevent creation of the corresponding
implicit SDK provider, independently of environment endpoint eligibility. Existing
selected SDK providers retain scoped sanitation and caller ownership.
