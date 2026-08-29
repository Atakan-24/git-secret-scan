"""Precision: the things that must NOT be reported.

A scanner that cries wolf gets disabled, and a disabled scanner protects
nothing. These cases are all drawn from shapes that occur in ordinary
repositories.
"""

import pytest
from conftest import SYNTHETIC

BENIGN = [
    ('uuid',            b'id = "550e8400-e29b-41d4-a716-446655440000"'),
    ('sha256',          b'digest = "e3b0c44298fc1c149afbf4c8996fb'
                        b'92427ae41e4649b934ca495991b7852b855"'),
    ('git sha',         b'commit = "dae166f8c2b1490aa7f3e5d1c9b8a4e6f2d0c3b7"'),
    ('semver',          b'version = "1.24.0-beta.3"'),
    ('base64 data',     b'blob = "SGVsbG8gd29ybGQsIHRoaXMgaXMganVzdCB0ZXh0Lg=="'),
    ('css class',       b'className = "flex-row items-center justify-between"'),
    ('kebab config',    b'mode: ask-before-high-impact-changes'),
    ('import path',     b'from my_package.sub_module import something_useful'),
    ('url',             b'url = "https://api.example.com/v2/resource/12345"'),
    ('prose sentence',  b'# This function takes a key and returns a value.'),
]


@pytest.mark.parametrize('name,blob', BENIGN, ids=[n for n, _ in BENIGN])
def test_benign_content_is_not_flagged(scan, name, blob):
    assert scan.scan_blob('file.py', blob + b'\n') == [], f'false positive on {name}'


@pytest.mark.parametrize('placeholder', [
    b'sk-proj-REPLACE_ME_WITH_YOUR_REAL_KEY',
    b'sk-proj-xxxxxxxxxxxxxxxxxxxxxxxxxxxx',
    b'sk-proj-0000000000000000000000000000',
    b'AKIAYOUR_ACCESS_KEY',
])
def test_placeholders_are_suppressed(scan, placeholder):
    assert scan.scan_blob('c.py', b'k = "' + placeholder + b'"\n') == []


@pytest.mark.parametrize('filename', [
    '.env.example', '.env.sample', 'config.template',
    'settings.dist', 'tests/fixtures/creds.json', 'testdata/keys.py',
])
def test_placeholder_files_are_skipped_entirely(scan, filename):
    blob = b'key = "' + SYNTHETIC['OpenAI key'] + b'"\n'
    assert scan.scan_blob(filename, blob) == [], (
        f'{filename} exists to hold fake values; scanning it only trains '
        'people to ignore the tool'
    )


def test_real_env_file_is_still_scanned(scan):
    """`.env.example` is exempt; `.env` most certainly is not."""
    blob = b'OPENAI_KEY=' + SYNTHETIC['OpenAI key'] + b'\n'
    assert scan.scan_blob('.env', blob), '.env must never be exempt'


def test_inline_ignore_is_explicit_and_scoped(scan):
    hit = b'k = "' + SYNTHETIC['OpenAI key'] + b'"  # secret-scan: ignore\n'
    miss = b'k = "' + SYNTHETIC['OpenAI key'] + b'"\n'
    assert scan.scan_blob('c.py', hit) == []
    assert scan.scan_blob('c.py', miss), 'ignore must not leak to other lines'


def test_secret_value_is_masked_not_printed(scan):
    secret = SYNTHETIC['OpenAI key']
    hits = scan.scan_blob('c.py', b'k = "' + secret + b'"\n')
    reported = hits[0][3]
    assert '…' in reported
    assert secret.decode() not in reported, 'the tool must not leak what it finds'
    assert len(reported) < len(secret.decode())
