"""
Traversal that survives the literal check.

`normalize_path` originally rejected `..` as a path segment, which is the right
idea and was not sufficient. `hvac` builds its URL with `requests`, and
`requests` runs every URL through `requote_uri` → `unquote_unreserved`, which
**decodes any percent-escape whose character is unreserved**. `.` is unreserved.
So `netbox/credentials/%2e%2e/%2e%2e/production/root` contains no `..` segment
when it is checked, and contains two by the time it leaves the process:

    http://bao/v1/secret/data/netbox/credentials/../../production/root

Whether that resolves is the *server's* business. OpenBao 2.6.0 does not
collapse dot-segments, so the live attempt returns 404 rather than the target
secret — which is a fine thing to be true and a terrible thing to depend on. It
puts the boundary in OpenBao's routing rather than in the broker's check, where
a proxy, a version bump, or a different KV implementation removes it silently.

The first test class pins the refusal. The second pins the *property*, which is
what actually protects this: whatever `normalize_path` accepts must still be
inside the permitted prefix after the HTTP client has finished rewriting it.
That one keeps holding if someone loosens the character rules later.
"""

from __future__ import annotations

import pytest
from requests.utils import requote_uri

from broker.config import InstancePolicy, normalize_path

PREFIX = 'netbox/credentials'
POLICY = InstancePolicy(name='netbox-prod', path_prefixes=(PREFIX,))

# Every one of these passed the original check and every one of them is an
# attempt to leave the prefix.
ENCODED_TRAVERSALS = [
    'netbox/credentials/%2e%2e/%2e%2e/production/root',
    'netbox/credentials/%2E%2E/%2E%2E/production/root',
    'netbox/credentials/%2e%2e%2f%2e%2e%2fproduction/root',
    'netbox/credentials/..%2f..%2fproduction/root',
    'netbox/credentials/%252e%252e/production/root',
    'netbox/credentials/%2e/%2e%2e/production/root',
]

OTHER_HOSTILE_INPUT = [
    'netbox/credentials/\nforged',        # one JSON object per audit line
    'netbox/credentials/\r\nforged',
    'netbox/credentials/\x7f',
    'netbox/credentials/．．/production',   # NFKC-normalizes to '..'
    'netbox/credentials/x／production',         # NFKC-normalizes to '/'
    'netbox/credentials/ leading-space',
]


class TestEncodedTraversalIsRefused:

    @pytest.mark.parametrize('path', ENCODED_TRAVERSALS)
    def test_percent_encoding_is_refused(self, path):
        with pytest.raises(ValueError, match='percent-encoded'):
            normalize_path(path)

    @pytest.mark.parametrize('path', OTHER_HOSTILE_INPUT)
    def test_non_printable_and_non_ascii_are_refused(self, path):
        with pytest.raises(ValueError):
            normalize_path(path)

    def test_what_the_plugin_actually_generates_still_works(self):
        """
        The rules are only worth having if they do not break the real client.
        `netbox-openbao` writes `<prefix>/<uuid>`.
        """
        path = normalize_path('netbox/credentials/0f4a2c1e-9d3b-4e7a-8c11-2b6d5f0a7e93')
        assert POLICY.permits_path(path)


class TestTheUrlThatActuallyLeaves:
    """
    The property, rather than a list of known attacks: an accepted path must
    still be inside the prefix once `requests` has rewritten it. A list of
    attacks goes stale; this does not.
    """

    @pytest.mark.parametrize('candidate', ENCODED_TRAVERSALS + OTHER_HOSTILE_INPUT + [
        'netbox/credentials/abc',
        'netbox/credentials',
        'netbox/credentials/deeply/nested/thing',
        "netbox/credentials/quote'and(parens)",
        'netbox/credentials/plus+and=equals',
    ])
    def test_an_accepted_path_cannot_escape_after_url_encoding(self, candidate):
        try:
            path = normalize_path(candidate)
        except ValueError:
            return  # Refused outright; nothing leaves the process.

        assert POLICY.permits_path(path), 'accepted a path outside the prefix'

        # Exactly what hvac hands to the transport.
        sent = requote_uri(f'http://bao.invalid/v1/secret/data/{path}')
        expected_root = f'http://bao.invalid/v1/secret/data/{PREFIX}'

        assert sent.startswith(expected_root), (
            f'{candidate!r} was accepted, but the URL sent was {sent!r}'
        )
        assert '/../' not in sent and not sent.endswith('/..'), (
            f'{candidate!r} produced a dot-segment in the URL: {sent!r}'
        )
