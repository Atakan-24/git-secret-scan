"""Every pattern must actually fire.

A scanner is judged by what it catches, so this is the suite that matters
most. It is parametrised over the pattern table itself, which means adding
a pattern to scan.py without a synthetic sample fails the build rather
than shipping untested.
"""

import pytest
from conftest import SYNTHETIC


def test_every_pattern_has_a_sample(scan):
    """Guard against a pattern being added with no test coverage."""
    labels = {label for label, _, _ in scan.PATTERNS}
    assert labels == set(SYNTHETIC), (
        'PATTERNS and SYNTHETIC drifted apart: '
        f'missing sample for {labels - set(SYNTHETIC)}, '
        f'stale sample for {set(SYNTHETIC) - labels}'
    )


@pytest.mark.parametrize('label', sorted(SYNTHETIC))
def test_pattern_detects_its_own_secret(scan, label):
    hits = scan.scan_blob('config.py', b'value = "' + SYNTHETIC[label] + b'"\n')
    assert [h[2] for h in hits] == [label] or label in [h[2] for h in hits], (
        f'{label} not detected'
    )


@pytest.mark.parametrize('label', sorted(SYNTHETIC))
def test_detection_survives_realistic_context(scan, label):
    """Secrets appear mid-file, indented, in assignments — not alone."""
    blob = (b'import os\n'
            b'\n'
            b'class Config:\n'
            b'    DEBUG = False\n'
            b'    TOKEN = "' + SYNTHETIC[label] + b'"\n'
            b'    TIMEOUT = 30\n')
    hits = scan.scan_blob('app/config.py', blob)
    assert hits, f'{label} missed in realistic context'
    assert hits[0][1] == 5, 'line number must point at the secret'


def test_multiple_secrets_all_reported(scan):
    blob = (b'a = "' + SYNTHETIC['AWS access key id'] + b'"\n'
            b'b = "' + SYNTHETIC['Slack token'] + b'"\n')
    hits = scan.scan_blob('c.py', blob)
    assert len(hits) == 2
    assert {h[1] for h in hits} == {1, 2}


def test_clean_file_produces_nothing(scan):
    blob = (b'def add(a, b):\n'
            b'    """Return the sum."""\n'
            b'    return a + b\n')
    assert scan.scan_blob('math.py', blob) == []
