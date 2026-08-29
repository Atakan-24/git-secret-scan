"""End-to-end tests against real git repositories.

The unit tests exercise scan_blob directly. These drive the actual
command-line entry point against a real `git init`, because the three
modes differ only in how they talk to git — which is exactly where the
silent-pass bug lived.
"""

import subprocess
import sys
from pathlib import Path

from conftest import SYNTHETIC

SCAN = Path(__file__).resolve().parent.parent / 'scan.py'


def run_scan(cwd, *args):
    return subprocess.run([sys.executable, str(SCAN), *args],
                          cwd=cwd, capture_output=True, text=True)


def git(cwd, *args):
    return subprocess.run(['git', *args], cwd=cwd, capture_output=True, check=True)


def test_clean_repo_exits_zero(repo):
    result = run_scan(repo, '--tracked')
    assert result.returncode == 0
    assert 'clean' in result.stdout


def test_staged_secret_is_caught(repo):
    (repo / 'settings.py').write_bytes(b'KEY = "' + SYNTHETIC['AWS access key id'] + b'"\n')
    git(repo, 'add', 'settings.py')

    result = run_scan(repo, '--staged')
    assert result.returncode == 1
    assert 'settings.py:1' in result.stdout
    assert 'AWS access key id' in result.stdout
    assert SYNTHETIC['AWS access key id'].decode() not in result.stdout, 'leaked the secret'


def test_unstaged_secret_is_not_reported_by_staged_mode(repo):
    """--staged must describe the commit, not the working tree."""
    (repo / 'scratch.py').write_bytes(b'KEY = "' + SYNTHETIC['Slack token'] + b'"\n')
    assert run_scan(repo, '--staged').returncode == 0


def test_history_mode_finds_a_deleted_secret(repo):
    """The whole point of --history: deleting the file does not undo the leak."""
    (repo / 'oops.py').write_bytes(b'KEY = "' + SYNTHETIC['Google API key'] + b'"\n')
    git(repo, 'add', 'oops.py')
    git(repo, 'commit', '-q', '-m', 'leak')
    git(repo, 'rm', '-q', 'oops.py')
    git(repo, 'commit', '-q', '-m', 'remove it')

    assert run_scan(repo, '--tracked').returncode == 0, 'gone from the working tree'
    result = run_scan(repo, '--history')
    assert result.returncode == 1, 'but still recoverable from history'
    assert 'Google API key' in result.stdout


def test_binary_file_does_not_crash_or_match(repo):
    (repo / 'blob.bin').write_bytes(b'\x00\x01\x02' + SYNTHETIC['OpenAI key'])
    git(repo, 'add', 'blob.bin')
    assert run_scan(repo, '--staged').returncode == 0


def test_help_exits_zero(repo):
    result = run_scan(repo, '--help')
    assert result.returncode == 0
    assert '--staged' in result.stdout


def test_installed_hook_blocks_a_real_commit(repo):
    """The end-to-end promise: `git commit` actually fails."""
    install = Path(__file__).resolve().parent.parent / 'install.py'
    subprocess.run([sys.executable, str(install)], cwd=repo,
                   capture_output=True, check=True)

    (repo / 'leak.py').write_bytes(b'KEY = "' + SYNTHETIC['Telegram bot token'] + b'"\n')
    git(repo, 'add', 'leak.py')
    result = subprocess.run(['git', 'commit', '-m', 'should be blocked'],
                            cwd=repo, capture_output=True, text=True)
    assert result.returncode != 0, 'the hook did not stop the commit'
