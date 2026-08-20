"""
Audit log.

The reason this service is worth running at all is partly that its record sits
**outside NetBox's blast radius**: an attacker with code execution in NetBox can
still ask the broker for material, but cannot erase the broker's record of
having been asked.

That only holds if the log is complete and if it never contains material. Both
are enforced here rather than left to the caller's discipline:

* `record()` takes named non-secret fields and nothing else. There is no
  parameter a payload could be passed through, which is a stronger guarantee
  than remembering not to pass one.
* Refusals are logged too. A denied request is the entry an operator most wants
  to find, and a log that only records successes is a log of the wrong half.
"""

from __future__ import annotations

import json
import logging
import sys
from datetime import datetime, timezone

__all__ = ('AuditLog', 'configure_logging')

AUDIT_LOGGER = 'netbox_openbao_broker.audit'


def configure_logging(level: str = 'INFO') -> None:
    """
    Send audit records to stdout as one JSON object per line.

    stdout because the deployment target is a container, where the collector is
    whatever reads the stream. A file would need rotation this service has no
    business owning.
    """
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter('%(message)s'))

    audit = logging.getLogger(AUDIT_LOGGER)
    audit.setLevel(logging.INFO)
    audit.handlers = [handler]
    audit.propagate = False

    logging.basicConfig(level=level, stream=sys.stderr, format='%(levelname)s %(name)s: %(message)s')


class AuditLog:
    """Append-only record of what was asked, by whom, and how it went."""

    def __init__(self, logger: logging.Logger | None = None):
        self._logger = logger or logging.getLogger(AUDIT_LOGGER)

    def record(
        self,
        *,
        instance: str | None,
        operation: str,
        path: str | None,
        outcome: str,
        reason: str = '',
        request_id: str = '',
        version: int | None = None,
    ) -> None:
        """
        Write one audit record.

        Every parameter is non-secret by construction: an identity, an
        operation name, a KV path, an outcome, and a reason drawn from this
        service's own fixed strings. There is deliberately no field that a
        secret payload could be routed through — the guarantee is structural
        rather than a convention to remember.
        """
        self._logger.info(json.dumps({
            'ts': datetime.now(timezone.utc).isoformat(),
            'instance': instance or '-',
            'operation': operation,
            'path': path or '-',
            'outcome': outcome,
            'reason': reason,
            'request_id': request_id,
            'version': version,
        }, separators=(',', ':'), sort_keys=True))
