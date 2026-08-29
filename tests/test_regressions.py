"""One test per bug that was actually found in this tool.

These are not hypothetical. Each was measured against the previous
version of scan.py before the fix, and each is a *false negative* — the
failure mode that matters for a security tool, because it looks like
success.
"""

import os
import subprocess
import sys
from pathlib import Path

import pytest
from conftest import SYNTHETIC

SCAN = Path(__file__).resolve().parent.parent / 'scan.py'


# --------------------------------------------------------------------------
# Bug 1 — the prose guard silently ate real tokens
#
# looks_like_prose() used to ask "does this contain both an uppercase
# letter and a digit?". Slack and GitHub tokens are routinely
# all-lowercase-plus-digits, so the answer was no and they were dropped.
# Measured on the old version: 2 of 10 token types were undetectable.
# --------------------------------------------------------------------------

@pytest.mark.parametrize('label', ['Slack token', 'GitHub token'])
def test_lowercase_tokens_are_not_mistaken_for_prose(scan, label):
    hits = scan.scan_blob('c.py', b'tok = "' + SYNTHETIC[label] + b'"\n')
    assert hits, (
        f'{label} is all-lowercase-plus-digits and was dropped by the old '
        'prose guard — the exact regression this test exists for'
    )


def test_prose_guard_only_applies_where_declared(scan):
    """Structurally rigid prefixes must not be prose-filtered at all."""
    for label, _, prose_prone in scan.PATTERNS:
        if label.startswith(('OpenAI', 'Anthropic')):
            assert prose_prone, f'{label} needs the guard: sk- occurs in text'
        else:
            assert not prose_prone, (
                f'{label} has an unambiguous prefix; guarding it only costs recall'
            )


def test_prose_guard_still_catches_kebab_case(scan):
    """The guard must keep doing its one real job."""
    assert scan.looks_like_prose(b'sk-before-high-impact-changes')
    assert not scan.looks_like_prose(SYNTHETIC['OpenAI key'])
    # lowercase+digits is a key shape, not prose — the old guard got this wrong
    assert not scan.looks_like_prose(SYNTHETIC['GitHub token'])


# --------------------------------------------------------------------------
# Bug 2 — a placeholder anywhere on the line suppressed a real secret
#
# allowed() matched against the whole line, so a trailing comment
# containing "EXAMPLE" disabled detection for that line entirely.
# --------------------------------------------------------------------------

def test_placeholder_word_in_comment_does_not_hide_a_real_secret(scan):
    blob = b'key = "' + SYNTHETIC['OpenAI key'] + b'"  # see EXAMPLE in docs\n'
    hits = scan.scan_blob('c.py', blob)
    assert hits, 'a real key must still be reported when a comment says EXAMPLE'


def test_placeholder_as_the_value_is_still_suppressed(scan):
    """The legitimate case must keep working."""
    assert scan.scan_blob('c.py', b'key = "sk-proj-YOUR_KEY_HERE_REPLACE_ME_NOW"\n') == []


# --------------------------------------------------------------------------
# Bug 3 — a broken git environment reported "clean"
#
# git()'s exit code was ignored, so outside a repository every mode
# produced no output, no findings, and exit 0. A hook that passes when it
# cannot see anything is worse than no hook, because it is trusted.
# --------------------------------------------------------------------------

@pytest.mark.parametrize('mode', ['--staged', '--tracked', '--history'])
def test_broken_git_environment_fails_loudly(tmp_path, mode):
    """Every mode must refuse to report 'clean' when git cannot answer.

    Pointing GIT_DIR at a path that does not exist is the reliable way to
    force this: git exits 128 regardless of where the process runs.
    (GIT_CEILING_DIRECTORIES is not usable here — pytest's tmp_path often
    sits inside a real repository, and the ceiling is ignored on Windows.)
    """
    env = {**os.environ, 'GIT_DIR': str(tmp_path / '.does-not-exist')}
    result = subprocess.run([sys.executable, str(SCAN), mode],
                            cwd=tmp_path, capture_output=True, text=True, env=env)
    assert result.returncode == 2, (
        f'{mode} must exit 2 (environment error), never 0 — '
        f'got {result.returncode}: {result.stdout!r}'
    )
    assert 'clean' not in result.stdout.lower()


def test_missing_git_binary_raises_rather_than_returning_empty(scan, monkeypatch):
    """git absent from PATH is an environment error, not a clean repo."""
    def no_git(*_a, **_kw):
        raise FileNotFoundError('git')
    monkeypatch.setattr(scan.subprocess, 'run', no_git)

    with pytest.raises(scan.GitError, match='not installed'):
        scan.git('ls-files')


def test_git_failure_raises_rather_than_returning_empty(scan, tmp_path):
    """Unit-level counterpart: git() must not swallow a non-zero exit."""
    import pytest as _pytest
    os.environ['GIT_DIR'] = str(tmp_path / '.does-not-exist')
    try:
        with _pytest.raises(scan.GitError):
            scan.git('ls-files')
    finally:
        os.environ.pop('GIT_DIR', None)


def test_unknown_mode_is_a_usage_error(tmp_path):
    result = subprocess.run([sys.executable, str(SCAN), '--nonsense'],
                            cwd=tmp_path, capture_output=True, text=True)
    assert result.returncode == 2
