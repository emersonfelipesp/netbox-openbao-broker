#!/usr/bin/env python3
"""Select the only public package route permitted for a GitHub event."""

from __future__ import annotations

import argparse
from typing import NamedTuple


class ReleaseRoute(NamedTuple):
    event: str
    target: str
    repository_url: str


_ROUTES = {
    ("push", ""): ReleaseRoute("rc", "testpypi", "https://test.pypi.org/legacy/"),
    ("release", ""): ReleaseRoute("final", "pypi", "https://upload.pypi.org/legacy/"),
    ("workflow_dispatch", "pypi"): ReleaseRoute(
        "final", "pypi", "https://upload.pypi.org/legacy/"
    ),
    ("workflow_dispatch", "testpypi"): ReleaseRoute(
        "final", "testpypi", "https://test.pypi.org/legacy/"
    ),
}


def select_release_route(event_name: str, dispatch_target: str = "") -> ReleaseRoute:
    """Return a closed routing decision for one supported event and target."""
    target = dispatch_target if event_name == "workflow_dispatch" else ""
    try:
        return _ROUTES[(event_name, target)]
    except KeyError as error:
        raise ValueError("Unsupported public release event or target") from error


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--event-name", required=True)
    parser.add_argument("--dispatch-target", default="")
    args = parser.parse_args()
    print("\t".join(select_release_route(args.event_name, args.dispatch_target)))


if __name__ == "__main__":
    main()
