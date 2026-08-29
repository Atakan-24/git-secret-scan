"""The single place in this repository that holds credential-shaped strings.

Every value here is synthetic: structurally valid once assembled, so the
patterns treat it exactly as they would a live credential, but never
issued by anyone and matching no real account.

Two deliberate design choices:

**They live under tests/fixtures/.** scan.py skips that path by
convention — a directory whose entire purpose is fake data. Keeping them
anywhere else would make the tool report findings against its own source,
and the fix for that must not be to weaken the tool: a scanner that learns
to ignore `tests/` would miss the real key someone pastes into a test.

**No complete credential literal appears in any file.** Each value is
assembled from a prefix and a body at import time. This is not
obfuscation — the assembled values are identical and fully exercised. It
exists because GitHub's own push protection scans source text and
(correctly) could not tell a realistic synthetic Slack token from a live
one, and it blocked this repository's first push. Splitting the literals
means every downstream scanner sees what it should: no credential-shaped
string at rest, and a test suite that still tests the real thing.

Both the test suite and the benchmark import from here, so a sample is
defined once and cannot drift between them.
"""


def _build(prefix: bytes, body: bytes) -> bytes:
    """Assemble a synthetic credential from parts. See module docstring."""
    return prefix + body


# label (as reported by scan.py) -> synthetic value
SYNTHETIC = {
    'OpenAI key':         _build(b'sk-' b'proj-', b'Ab3xY9zQ1mN4pR7sT2uV5wX8kL6dF0gH'),
    'Anthropic key':      _build(b'sk-' b'ant-', b'Ab3xY9zQ1mN4pR7sT2uV5wX8kL6dF0gH'),
    'GitHub token':       _build(b'ghp' b'_', b'ab3xy9zq1mn4pr7st2uv5wx8kl6df0gh12'),
    'Slack token':        _build(b'xox' b'b-', b'1234567890-abcdefghijklmnop'),
    'AWS access key id':  _build(b'AKI' b'A', b'2X4YQZ7NPLMV3RTB'),
    'Google OAuth token': _build(b'AQ' b'.', b'Ab3xY9zQ1mN4pR7sT2uV5wX8kL6dF0gH1jK2lM'),
    # Google API keys are exactly 39 characters: the AIza prefix plus 35.
    'Google API key':     _build(b'AIz' b'a', b'SyA3xY9zQ1mN4pR7sT2uV5wX8kL6dF0gH1j'),
    'Telegram bot token': _build(b'123456789:' b'AA', b'xY9zQ1mN4pR7sT2uV5wX8kL6dF0gH1jK2'),
    'JWT (Supabase, n8n, …)': _build(
        b'eyJhbGciOi' b'JIUzI1NiIsInR5cCI6IkpXVCJ9.',
        b'eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4ifQ.'
        b'dQw4w9WgXcQ1mN4pR7sT2uV5wX8kL6dF0gH1jK2lM3n'),
    'private key block':  _build(b'-----BEGIN ', b'RSA PRIVATE KEY-----'),
}

# Short keys used by the benchmark corpus, mapped to the same values.
BY_KIND = {
    'openai':    SYNTHETIC['OpenAI key'],
    'anthropic': SYNTHETIC['Anthropic key'],
    'github':    SYNTHETIC['GitHub token'],
    'slack':     SYNTHETIC['Slack token'],
    'aws':       SYNTHETIC['AWS access key id'],
    'gcp_oauth': SYNTHETIC['Google OAuth token'],
    'gcp_api':   SYNTHETIC['Google API key'],
    'telegram':  SYNTHETIC['Telegram bot token'],
    'jwt':       SYNTHETIC['JWT (Supabase, n8n, …)'],
    'pem':       SYNTHETIC['private key block'],
}

# Placeholder values that must be suppressed by the allow-list.
PLACEHOLDERS = {
    'replace_me': _build(b'sk-' b'proj-', b'REPLACE_ME_WITH_YOUR_KEY'),
    'x_padding':  _build(b'sk-' b'proj-', b'xxxxxxxxxxxxxxxxxxxxxxxxxx'),
    'your_key':   _build(b'AKI' b'A', b'YOUR_ACCESS_KEY'),
}
