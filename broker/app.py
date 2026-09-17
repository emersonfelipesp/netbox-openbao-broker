"""
The broker's HTTP surface.

The secret operations mirror `netbox-openbao`'s `SecretBackend` ABC. A separate,
opt-in administration transport uses one versioned closed operation registry
and two bounded snapshot-streaming routes. Keeping those surfaces fixed and
policy-gated is a design constraint: the broker must not become a second user
authorization model that can drift out of step with NetBox.

Every request follows the same three steps, in this order:

1. **Identify** the caller from its TLS client certificate.
2. **Authorize** the path against that instance's declared prefixes —
   *before OpenBao is contacted*, so a refused request never becomes a vault
   read that merely was not returned.
3. **Audit** the outcome, refusals included.
"""

from __future__ import annotations

import logging
import tempfile
import uuid

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel, Field
from starlette.background import BackgroundTask
from starlette.concurrency import run_in_threadpool

from .administration import CONTRACT_DIGEST, contract_document, operation_contract, validate_arguments
from .audit import AuditLog
from .config import BrokerConfig, InstancePolicy, normalize_path
from .identity import IdentityError, identity_from_scope
from .vault import MAX_SNAPSHOT_BYTES, VaultClient, VaultError, VaultMutationUnknown

__all__ = ("create_app",)

logger = logging.getLogger(__name__)


class PathRequest(BaseModel):
    path: str = Field(..., max_length=500)


class ReadRequest(PathRequest):
    version: int | None = Field(default=None, ge=1)


class WriteRequest(PathRequest):
    data: dict = Field(...)
    cas: int | None = Field(default=None, ge=0)


class DeleteRequest(PathRequest):
    versions: list[int] | None = None


class MetadataRequest(PathRequest):
    custom_metadata: dict = Field(default_factory=dict)


class AdministrationRequest(BaseModel):
    contract_digest: str = Field(..., min_length=64, max_length=64, pattern=r"^[0-9a-f]{64}$")
    operation: str = Field(..., min_length=1, max_length=100, pattern=r"^[a-z][a-z0-9_]*$")
    arguments: dict = Field(default_factory=dict)


class FinalizedStreamingResponse(StreamingResponse):
    """Run cleanup even when ASGI fails before body iteration or background tasks."""

    def __init__(self, *args, finalizer, **kwargs):
        super().__init__(*args, **kwargs)
        self.finalizer = finalizer

    async def __call__(self, scope, receive, send) -> None:
        try:
            await super().__call__(scope, receive, send)
        finally:
            self.finalizer()


class Caller:
    """A resolved, authorized caller for one request."""

    def __init__(self, instance: InstancePolicy, request_id: str):
        self.instance = instance
        self.request_id = request_id


def create_app(config: BrokerConfig, vault: VaultClient | None = None, audit: AuditLog | None = None):
    app = FastAPI(
        title="netbox-openbao broker",
        description=(
            "Holds the OpenBao AppRole so NetBox never possesses credentials able to read "
            "production secret material. Note that this does not make a NetBox compromise "
            "harmless: an attacker with code execution there can still ask this service for "
            "anything the instance is authorized to request."
        ),
        version="0.1.0",
        # No interactive docs, and no schema either. They are a second,
        # differently-shaped surface on a service whose entire value is being
        # small and predictable, and the schema enumerates the API for anyone
        # who reaches the port. `docs_url=None` alone is not enough — FastAPI
        # keeps serving /openapi.json until openapi_url is disabled as well,
        # which a test caught after this comment first claimed otherwise.
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    vault = vault or VaultClient(config)
    audit = audit or AuditLog()

    @app.exception_handler(RequestValidationError)
    async def malformed_request(request: Request, exc: RequestValidationError):
        """
        Audit a request that never reached a handler.

        Body validation runs before the dependency that identifies the caller,
        so without this a malformed request to a secret route produces a 422 and
        no audit record at all — and an attempt to read a secret is exactly the
        thing an operator reconstructing an incident wants to find, whether or
        not it parsed.

        The response is deliberately generic. FastAPI's default 422 echoes the
        offending input, which for `/v1/secret/write` is the material itself;
        the caller sent it, so this is not a disclosure, but it puts secret data
        into a response body and from there into whatever logs it. The same
        reasoning keeps `input` and `msg` out of the local log below — the
        field locations say where the request was wrong without repeating what
        was in it.
        """
        try:
            name = identity_from_scope(request.scope)
        except IdentityError:
            name = None

        locations = [" -> ".join(str(part) for part in error.get("loc", ())) for error in exc.errors()]
        logger.info("Rejected a malformed request: %s", "; ".join(locations) or "unparseable")

        audit.record(
            instance=name,
            operation="malformed",
            path=None,
            outcome="denied",
            reason="request failed validation",
            request_id=str(uuid.uuid4()),
        )
        return JSONResponse(status_code=422, content={"detail": "Invalid request."})

    def caller(request: Request) -> Caller:
        request_id = str(uuid.uuid4())
        try:
            name = identity_from_scope(request.scope)
        except IdentityError as exc:
            audit.record(
                instance=None,
                operation="identify",
                path=None,
                outcome="denied",
                reason=str(exc),
                request_id=request_id,
            )
            raise HTTPException(status_code=401, detail=str(exc)) from None

        policy = config.instance(name)
        if policy is None:
            # A valid certificate from the right CA is not authorization. If it
            # were, one mis-issued cert would be full vault access.
            audit.record(
                instance=name,
                operation="identify",
                path=None,
                outcome="denied",
                reason="instance not configured",
                request_id=request_id,
            )
            raise HTTPException(status_code=403, detail="This client is not a configured instance.")

        return Caller(policy, request_id)

    def authorize(who: Caller, raw_path: str, operation: str, *, write=False, delete=False) -> str:
        """Normalize, then check. Refusal happens before OpenBao is touched."""
        try:
            path = normalize_path(raw_path)
        except ValueError as exc:
            audit.record(
                instance=who.instance.name,
                operation=operation,
                path=None,
                outcome="denied",
                reason=f"invalid path: {exc}",
                request_id=who.request_id,
            )
            raise HTTPException(status_code=400, detail=f"Invalid path: {exc}") from None

        if not who.instance.permits_path(path):
            audit.record(
                instance=who.instance.name,
                operation=operation,
                path=path,
                outcome="denied",
                reason="outside permitted prefixes",
                request_id=who.request_id,
            )
            raise HTTPException(status_code=403, detail="Path is outside this instance's prefixes.")

        if write and not who.instance.may_write:
            audit.record(
                instance=who.instance.name,
                operation=operation,
                path=path,
                outcome="denied",
                reason="instance is read-only",
                request_id=who.request_id,
            )
            raise HTTPException(status_code=403, detail="This instance may not write.")

        if delete and not who.instance.may_delete:
            audit.record(
                instance=who.instance.name,
                operation=operation,
                path=path,
                outcome="denied",
                reason="instance may not delete",
                request_id=who.request_id,
            )
            raise HTTPException(status_code=403, detail="This instance may not delete.")

        return path

    def run(who: Caller, operation: str, path: str, action, version=None, version_from_result=False):
        """
        Execute an authorized operation, auditing every outcome.

        `version_from_result` covers the write case, where the version is not
        known until OpenBao has assigned it. Without it the one operation that
        actually produces a version is the one whose audit record never has one.
        """
        try:
            result = action()
        except VaultMutationUnknown as exc:
            audit.record(
                instance=who.instance.name,
                operation=operation,
                path=path,
                outcome="unknown",
                reason="mutation outcome unknown",
                request_id=who.request_id,
                version=version,
            )
            raise HTTPException(
                status_code=exc.status_code,
                detail=str(exc),
                headers={"X-OpenBao-Outcome": "unknown"},
            ) from None
        except VaultError as exc:
            audit.record(
                instance=who.instance.name,
                operation=operation,
                path=path,
                outcome="error",
                reason=str(exc),
                request_id=who.request_id,
                version=version,
            )
            raise HTTPException(status_code=exc.status_code, detail=str(exc)) from None
        except Exception:
            # A blanket catch, deliberately. The audit record is the thing this
            # service exists to produce, and "every request is audited" cannot
            # hold if an unforeseen exception unwinds past the only place that
            # writes one. The traceback still reaches this process's log; what
            # the caller gets is a bare 500, and what the audit gets is the
            # fact that the request happened.
            logger.exception("Unhandled error during %s", operation)
            audit.record(
                instance=who.instance.name,
                operation=operation,
                path=path,
                outcome="error",
                reason="internal error",
                request_id=who.request_id,
                version=version,
            )
            raise HTTPException(status_code=500, detail="Internal error.") from None

        if version_from_result and isinstance(result, int):
            version = result

        audit.record(
            instance=who.instance.name,
            operation=operation,
            path=path,
            outcome="ok",
            request_id=who.request_id,
            version=version,
        )
        return result

    # -- operations -----------------------------------------------------

    @app.post("/v1/secret/read")
    def read_secret(body: ReadRequest, who: Caller = Depends(caller)):
        path = authorize(who, body.path, "read")
        data = run(who, "read", path, lambda: vault.read(path, body.version), version=body.version)
        return {"data": data}

    @app.post("/v1/secret/write")
    def write_secret(body: WriteRequest, who: Caller = Depends(caller)):
        path = authorize(who, body.path, "write", write=True)
        version = run(
            who,
            "write",
            path,
            lambda: vault.write(path, body.data, body.cas),
            version_from_result=True,
        )
        return {"version": version}

    @app.post("/v1/secret/delete")
    def delete_secret(body: DeleteRequest, who: Caller = Depends(caller)):
        path = authorize(who, body.path, "delete", delete=True)
        run(who, "delete", path, lambda: vault.delete(path, body.versions))
        return {"deleted": True}

    @app.post("/v1/secret/versions")
    def list_versions(body: PathRequest, who: Caller = Depends(caller)):
        path = authorize(who, body.path, "versions")
        versions = run(who, "versions", path, lambda: vault.list_versions(path))
        return {"versions": versions}

    @app.post("/v1/secret/metadata/read")
    def read_metadata(body: PathRequest, who: Caller = Depends(caller)):
        path = authorize(who, body.path, "metadata_read")
        metadata = run(who, "metadata_read", path, lambda: vault.read_metadata(path))
        return {"metadata": metadata}

    @app.post("/v1/secret/metadata/write")
    def write_metadata(body: MetadataRequest, who: Caller = Depends(caller)):
        path = authorize(who, body.path, "metadata_write", write=True)
        run(who, "metadata_write", path, lambda: vault.set_metadata(path, body.custom_metadata))
        return {"updated": True}

    @app.get("/healthz")
    def healthz():
        """
        Liveness plus OpenBao reachability.

        Deliberately unauthenticated and deliberately uninformative: it reports
        whether OpenBao answers and whether it is sealed, and nothing about
        instances, paths, or policy.

        Unauthenticated at the *application* layer only. `ssl_cert_reqs` is a
        property of the listening socket, not of a route, so a probe with no
        client certificate never completes the handshake and never reaches
        here. Container and load-balancer health checks must therefore be a TCP
        connect, or must present a CA-signed certificate of their own.
        """
        status = vault.health()
        return {"ok": True, "openbao": status}

    @app.get("/v1/administration/contract")
    def administration_contract(who: Caller = Depends(caller)):
        """Advertise only the reviewed families enabled for this mTLS identity."""

        families = who.instance.administration_families
        if not families:
            audit.record(
                instance=who.instance.name,
                operation="administration_contract",
                path=None,
                outcome="denied",
                reason="administration disabled",
                request_id=who.request_id,
            )
            raise HTTPException(status_code=403, detail="Administration is disabled for this instance.")
        result = contract_document(families)
        audit.record(
            instance=who.instance.name,
            operation="administration_contract",
            path=None,
            outcome="ok",
            request_id=who.request_id,
        )
        return result

    @app.post("/v1/administration/request")
    def administration_request(body: AdministrationRequest, who: Caller = Depends(caller)):
        """Execute one typed operation from the broker-owned closed registry."""

        if body.contract_digest != CONTRACT_DIGEST:
            audit.record(
                instance=who.instance.name,
                operation="administration_request",
                path=None,
                outcome="denied",
                reason="contract digest mismatch",
                request_id=who.request_id,
            )
            raise HTTPException(status_code=409, detail="The administration contract is stale.")
        try:
            contract = operation_contract(body.operation)
            arguments = validate_arguments(body.operation, body.arguments)
        except ValueError:
            audit.record(
                instance=who.instance.name,
                operation="administration_request",
                path=None,
                outcome="denied",
                reason="invalid administration operation",
                request_id=who.request_id,
            )
            raise HTTPException(status_code=422, detail="Invalid administration request.") from None
        if not who.instance.permits_administration(contract.family):
            audit.record(
                instance=who.instance.name,
                operation=f"administration.{body.operation}",
                path=None,
                outcome="denied",
                reason="administration family denied",
                request_id=who.request_id,
            )
            raise HTTPException(status_code=403, detail="The administration family is disabled.")
        result = run(
            who,
            f"administration.{body.operation}",
            "",
            lambda: vault.execute_administration(body.operation, arguments),
        )
        return {"data": result}

    def authorize_snapshot(who: Caller, digest: str, operation: str) -> None:
        if digest != CONTRACT_DIGEST:
            audit.record(
                instance=who.instance.name,
                operation=operation,
                path=None,
                outcome="denied",
                reason="contract digest mismatch",
                request_id=who.request_id,
            )
            raise HTTPException(status_code=409, detail="The administration contract is stale.")
        if not who.instance.permits_administration("cluster"):
            audit.record(
                instance=who.instance.name,
                operation=operation,
                path=None,
                outcome="denied",
                reason="administration family denied",
                request_id=who.request_id,
            )
            raise HTTPException(status_code=403, detail="The administration family is disabled.")

    @app.get("/v1/administration/snapshot")
    def download_snapshot(
        who: Caller = Depends(caller),
        contract_digest: str = Header(..., alias="X-Administration-Contract-Digest"),
    ):
        operation = "administration.download_raft_snapshot"
        authorize_snapshot(who, contract_digest, operation)
        try:
            snapshot = vault.download_raft_snapshot()
        except VaultError as exc:
            audit.record(
                instance=who.instance.name,
                operation=operation,
                path=None,
                outcome="error",
                reason=str(exc),
                request_id=who.request_id,
            )
            raise HTTPException(status_code=exc.status_code, detail=str(exc)) from None

        terminal = {"recorded": False}

        def record_stream(outcome: str, reason: str | None = None) -> None:
            if terminal["recorded"]:
                return
            terminal["recorded"] = True
            audit.record(
                instance=who.instance.name,
                operation=operation,
                path=None,
                outcome=outcome,
                reason=reason,
                request_id=who.request_id,
            )

        def stream():
            try:
                yield from snapshot.chunks()
            except VaultError as exc:
                record_stream("error", str(exc))
                raise
            except BaseException:
                snapshot.close()
                record_stream("error", "snapshot stream interrupted")
                raise
            else:
                record_stream("ok")

        def close_pending_stream() -> None:
            if terminal["recorded"]:
                return
            snapshot.close()
            record_stream("error", "snapshot stream not completed")

        headers = {}
        if snapshot.declared_size is not None:
            headers["Content-Length"] = str(snapshot.declared_size)
        return FinalizedStreamingResponse(
            stream(),
            media_type="application/octet-stream",
            headers=headers,
            background=BackgroundTask(close_pending_stream),
            finalizer=close_pending_stream,
        )

    @app.post("/v1/administration/snapshot")
    async def restore_snapshot(
        request: Request,
        force: bool = Query(default=False),
        who: Caller = Depends(caller),
        contract_digest: str = Header(..., alias="X-Administration-Contract-Digest"),
        content_length: int = Header(..., alias="Content-Length", ge=1, le=MAX_SNAPSHOT_BYTES),
        content_type: str = Header(..., alias="Content-Type"),
    ):
        operation = "administration.restore_raft_snapshot"
        authorize_snapshot(who, contract_digest, operation)
        if content_type.lower() != "application/octet-stream":
            audit.record(
                instance=who.instance.name,
                operation=operation,
                path=None,
                outcome="denied",
                reason="invalid snapshot media type",
                request_id=who.request_id,
            )
            raise HTTPException(status_code=415, detail="The snapshot media type is invalid.")
        observed = 0
        with tempfile.SpooledTemporaryFile(max_size=8 * 1024 * 1024) as snapshot:
            try:
                async for chunk in request.stream():
                    observed += len(chunk)
                    if observed > content_length or observed > MAX_SNAPSHOT_BYTES:
                        audit.record(
                            instance=who.instance.name,
                            operation=operation,
                            path=None,
                            outcome="denied",
                            reason="snapshot exceeds declared size",
                            request_id=who.request_id,
                        )
                        raise HTTPException(status_code=413, detail="The snapshot upload is too large.")
                    snapshot.write(chunk)
            except HTTPException:
                raise
            except BaseException:
                audit.record(
                    instance=who.instance.name,
                    operation=operation,
                    path=None,
                    outcome="error",
                    reason="snapshot upload interrupted",
                    request_id=who.request_id,
                )
                raise
            if observed != content_length:
                audit.record(
                    instance=who.instance.name,
                    operation=operation,
                    path=None,
                    outcome="denied",
                    reason="snapshot size mismatch",
                    request_id=who.request_id,
                )
                raise HTTPException(
                    status_code=400, detail="The snapshot size does not match its declaration."
                )
            snapshot.seek(0)
            await run_in_threadpool(
                run,
                who,
                operation,
                "",
                lambda: vault.restore_raft_snapshot(snapshot, observed, force=force),
            )
        return {"restored": True}

    return app
