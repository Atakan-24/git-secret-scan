"""The installer is part of the security boundary.

If install.py silently writes a hook that never runs, the repository is
unprotected while looking protected — the same failure shape as bug 3.
These tests check that the file lands, is executable, points at a real
interpreter, and does not destroy a hook that was already there.
"""

import os
import subprocess
import sys
from pathlib import Path

import pytest

INSTALL = Path(__file__).resolve().parent.parent / 'install.py'


@pytest.fixture
def installer():
    import install
    return install


def run_install(cwd):
    return subprocess.run([sys.executable, str(INSTALL)],
                          cwd=cwd, capture_output=True, text=True)


def test_hook_is_written_and_marked(repo, installer):
    result = run_install(repo)
    assert result.returncode == 0

    hook = repo / '.git' / 'hooks' / 'pre-commit'
    assert hook.exists()
    body = hook.read_text()
    assert installer.HOOK_MARKER in body
    assert '--staged' in body


def test_hook_references_a_real_interpreter(repo):
    """`python` is often absent or Python 2 in a hook's environment."""
    run_install(repo)
    body = (repo / '.git' / 'hooks' / 'pre-commit').read_text()
    interpreter = body.split('"')[1]
    assert Path(interpreter).exists(), f'hook points at a missing interpreter: {interpreter}'


def test_hook_uses_lf_endings(repo):
    """CRLF in a shell script makes /bin/sh fail with a confusing error."""
    run_install(repo)
    raw = (repo / '.git' / 'hooks' / 'pre-commit').read_bytes()
    assert b'\r\n' not in raw


def test_existing_foreign_hook_is_backed_up_not_destroyed(repo):
    hooks = repo / '.git' / 'hooks'
    hooks.mkdir(parents=True, exist_ok=True)
    existing = hooks / 'pre-commit'
    existing.write_text('#!/bin/sh\necho someone elses hook\n')

    run_install(repo)

    backup = hooks / 'pre-commit.pre-secret-scan'
    assert backup.exists(), 'a foreign hook must never be silently overwritten'
    assert 'someone elses hook' in backup.read_text()


def test_reinstall_is_idempotent(repo, installer):
    run_install(repo)
    first = (repo / '.git' / 'hooks' / 'pre-commit').read_text()
    run_install(repo)
    hooks = repo / '.git' / 'hooks'
    assert (hooks / 'pre-commit').read_text() == first
    assert not (hooks / 'pre-commit.pre-secret-scan').exists(), (
        'our own hook must not be treated as foreign and backed up each run'
    )


def test_main_in_process_writes_the_hook(repo, installer, monkeypatch, capsys):
    """Same paths as the subprocess tests, but measurable by coverage."""
    monkeypatch.chdir(repo)
    assert installer.main() == 0
    assert 'hook installed' in capsys.readouterr().out
    assert (repo / '.git' / 'hooks' / 'pre-commit').exists()


def test_main_in_process_backs_up_foreign_hook(repo, installer, monkeypatch, capsys):
    hooks = repo / '.git' / 'hooks'
    hooks.mkdir(parents=True, exist_ok=True)
    (hooks / 'pre-commit').write_text('#!/bin/sh\necho foreign\n')
    monkeypatch.chdir(repo)

    installer.main()

    assert 'backed up' in capsys.readouterr().out
    assert 'foreign' in (hooks / 'pre-commit.pre-secret-scan').read_text()


def test_main_in_process_refuses_outside_a_repository(installer, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv('GIT_DIR', str(tmp_path / '.does-not-exist'))
    with pytest.raises(SystemExit):
        installer.main()


def test_install_outside_a_repository_refuses(tmp_path):
    env = {**os.environ, 'GIT_DIR': str(tmp_path / '.does-not-exist')}
    result = subprocess.run([sys.executable, str(INSTALL)],
                            cwd=tmp_path, capture_output=True, text=True, env=env)
    assert result.returncode != 0
    assert 'Not a git repository' in (result.stderr + result.stdout)
