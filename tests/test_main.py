"""In-process tests for the entry point and the git iterators.

test_cli.py drives the same code through a subprocess, which is the
honest end-to-end check but is invisible to coverage and costs a Python
start-up per case. These call main() and the generators directly in the
test process: same code paths, measured coverage, and fast enough to run
on every keystroke.

Both suites are kept. Dropping the subprocess one would stop testing that
the script is actually executable; dropping this one would leave the
argument handling and reporting unmeasured.
"""

import os

import pytest
from conftest import SYNTHETIC


@pytest.fixture
def in_repo(repo, monkeypatch):
    monkeypatch.chdir(repo)
    return repo


def test_main_clean_repo(scan, in_repo, capsys):
    assert scan.main(['--tracked']) == 0
    assert 'clean' in capsys.readouterr().out


def test_main_defaults_to_staged(scan, in_repo, capsys):
    assert scan.main([]) == 0
    assert '--staged' in capsys.readouterr().out


def test_main_reports_and_masks_a_finding(scan, in_repo, capsys, repo):
    secret = SYNTHETIC['Anthropic key']
    (repo / 'conf.py').write_bytes(b'K = "' + secret + b'"\n')
    os.system('git add conf.py')      # noqa: S605 - fixture repo, fixed argument

    assert scan.main(['--staged']) == 1
    out = capsys.readouterr().out
    assert 'Anthropic key' in out
    assert 'conf.py:1' in out
    assert secret.decode() not in out, 'the report must never contain the secret'
    assert 'commit stopped' in out


def test_main_help_returns_zero(scan, capsys):
    assert scan.main(['--help']) == 0
    assert '--history' in capsys.readouterr().out


def test_main_unknown_mode_returns_two(scan, capsys):
    assert scan.main(['--wat']) == 2


def test_main_reports_git_failure_as_two(scan, in_repo, monkeypatch, capsys):
    def boom(*_a, **_kw):
        raise scan.GitError('simulated failure')
    monkeypatch.setattr(scan, 'git', boom)

    assert scan.main(['--tracked']) == 2
    assert 'cannot run' in capsys.readouterr().err


def test_iterators_yield_names_and_contents(scan, in_repo):
    assert [name for name, _ in scan.files_tracked()] == ['README.md']
    assert list(scan.files_staged()) == []
    assert any(name.startswith('blob ') for name, _ in scan.blobs_history())


def test_oversized_blob_is_skipped(scan, in_repo, repo, monkeypatch):
    """A multi-megabyte blob is data; scanning it only costs time."""
    monkeypatch.setattr(scan, 'MAX_BLOB_BYTES', 100)
    (repo / 'big.py').write_bytes(b'x' * 200 + b'\nK = "' + SYNTHETIC['OpenAI key'] + b'"\n')
    os.system('git add big.py')       # noqa: S605 - fixture repo, fixed argument
    assert scan.collect('--staged') == []
