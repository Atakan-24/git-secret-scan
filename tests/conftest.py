"""Shared fixtures.

Every secret in this test suite is synthetic and structurally valid but
deliberately not a real credential — the patterns care about shape, so a
fabricated value exercises them exactly as a live one would.
"""

import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


# The synthetic values live in tests/fixtures/ so the scanner does not
# report findings against its own source. See that module for why.
from fixtures.synthetic_secrets import SYNTHETIC  # noqa: E402

__all__ = ["SYNTHETIC"]


@pytest.fixture
def scan():
    import scan as module
    return module


@pytest.fixture
def repo(tmp_path):
    """A real git repository — the CLI paths shell out to git for real."""
    def run(*args, **kw):
        return subprocess.run(['git', *args], cwd=tmp_path,
                              capture_output=True, check=True, **kw)

    run('init', '-q', '-b', 'main')
    run('config', 'user.email', 'test@example.invalid')
    run('config', 'user.name', 'test')
    run('config', 'commit.gpgsign', 'false')
    (tmp_path / 'README.md').write_text('placeholder\n')
    run('add', 'README.md')
    run('commit', '-q', '-m', 'init')
    return tmp_path
