"""--range: scan only what a pull request introduces.

The distinction this mode exists for: an existing repository usually has
credentials somewhere in its past. Reporting all of them on the first CI
run produces a wall of findings that nobody can act on, and a check that
always fails is a check that gets removed. --range fails only on what the
current change added.
"""

import os
import subprocess
import sys
from pathlib import Path

from fixtures.synthetic_secrets import SYNTHETIC

SCAN = Path(__file__).resolve().parent.parent / 'scan.py'


def git(cwd, *args):
    return subprocess.run(['git', *args], cwd=cwd, capture_output=True, check=True)


def run_scan(cwd, *args):
    return subprocess.run([sys.executable, str(SCAN), *args],
                          cwd=cwd, capture_output=True, text=True)


def commit_file(repo, name, content: bytes, message):
    (repo / name).write_bytes(content)
    git(repo, 'add', name)
    git(repo, 'commit', '-q', '-m', message)


def test_range_ignores_a_secret_that_predates_the_branch(repo):
    """The key scenario: legacy leak in main, clean feature branch."""
    commit_file(repo, 'legacy.py',
                b'OLD = "' + SYNTHETIC['AWS access key id'] + b'"\n', 'legacy leak')
    base = subprocess.run(['git', 'rev-parse', 'HEAD'], cwd=repo,
                          capture_output=True, text=True, check=True).stdout.strip()

    commit_file(repo, 'feature.py', b'def add(a, b):\n    return a + b\n', 'clean work')

    # The repository is dirty in absolute terms...
    assert run_scan(repo, '--tracked').returncode == 1
    # ...but this change introduced nothing, so the PR check must pass.
    result = run_scan(repo, '--range', f'{base}..HEAD')
    assert result.returncode == 0, result.stdout
    assert 'clean' in result.stdout


def test_range_catches_a_secret_the_branch_adds(repo):
    base = subprocess.run(['git', 'rev-parse', 'HEAD'], cwd=repo,
                          capture_output=True, text=True, check=True).stdout.strip()
    commit_file(repo, 'new.py',
                b'KEY = "' + SYNTHETIC['Slack token'] + b'"\n', 'oops')

    result = run_scan(repo, '--range', f'{base}..HEAD')
    assert result.returncode == 1
    assert 'new.py:1' in result.stdout
    assert 'Slack token' in result.stdout
    assert SYNTHETIC['Slack token'].decode() not in result.stdout


def test_range_reports_the_range_it_used(repo):
    base = subprocess.run(['git', 'rev-parse', 'HEAD'], cwd=repo,
                          capture_output=True, text=True, check=True).stdout.strip()
    out = run_scan(repo, '--range', f'{base}..HEAD').stdout
    assert f'{base}..HEAD' in out, 'the scanned range must be visible in CI logs'


def test_range_without_an_argument_is_a_usage_error(repo):
    assert run_scan(repo, '--range').returncode == 2
    assert run_scan(repo, '--range', 'not-a-range').returncode == 2


def test_range_in_process(scan, repo, monkeypatch, capsys):
    """Same paths in-process, so coverage measures them. See test_main.py."""
    monkeypatch.chdir(repo)
    base = subprocess.run(['git', 'rev-parse', 'HEAD'], cwd=repo,
                          capture_output=True, text=True, check=True).stdout.strip()
    commit_file(repo, 'bad.py', b'K = "' + SYNTHETIC['Google API key'] + b'"\n', 'add')

    assert scan.main(['--range', f'{base}..HEAD']) == 1
    out = capsys.readouterr().out
    assert 'bad.py:1' in out
    assert 'Google API key' in out


def test_range_iterator_yields_only_changed_files(scan, repo, monkeypatch):
    monkeypatch.chdir(repo)
    base = subprocess.run(['git', 'rev-parse', 'HEAD'], cwd=repo,
                          capture_output=True, text=True, check=True).stdout.strip()
    commit_file(repo, 'only_this.py', b'x = 1\n', 'add one file')

    names = [name for name, _ in scan.files_in_range(f'{base}..HEAD')]
    assert names == ['only_this.py'], 'README.md predates the range and must not appear'


def test_range_missing_argument_in_process(scan, repo, monkeypatch, capsys):
    monkeypatch.chdir(repo)
    assert scan.main(['--range']) == 2
    assert 'commit range' in capsys.readouterr().err


def test_range_with_a_broken_git_environment_fails_loudly(repo, tmp_path):
    env = {**os.environ, 'GIT_DIR': str(tmp_path / '.does-not-exist')}
    result = subprocess.run([sys.executable, str(SCAN), '--range', 'a..b'],
                            cwd=repo, capture_output=True, text=True, env=env)
    assert result.returncode == 2
    assert 'clean' not in result.stdout.lower()
