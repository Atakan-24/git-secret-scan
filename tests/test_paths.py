"""Exercise Git's filename protocol and the documented working-tree mode."""

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
from conftest import SYNTHETIC
from test_cli import git, run_scan
from test_install import INSTALL, run_install


@pytest.mark.parametrize('name', ['schlüssel.py', 'with\ttab.py', 'two\nlines.py'])
def test_unusual_paths_are_scanned_in_index_and_range(repo, name):
    if os.name == 'nt' and ('\t' in name or '\n' in name):
        pytest.skip('Windows filenames cannot contain control characters')
    (repo / name).write_bytes(SYNTHETIC['AWS access key id'])
    git(repo, 'add', '--', name)
    assert run_scan(repo, '--staged').returncode == 1
    git(repo, 'commit', '-q', '-m', 'synthetic fixture')
    assert run_scan(repo, '--range', 'HEAD~1..HEAD').returncode == 1


def test_tracked_reads_uncommitted_working_tree_content(repo):
    (repo / 'README.md').write_bytes(SYNTHETIC['AWS access key id'])
    assert run_scan(repo, '--tracked').returncode == 1


def test_tracked_from_subdirectory_reads_the_whole_repository(repo):
    (repo / 'sub').mkdir()
    (repo / 'README.md').write_bytes(SYNTHETIC['AWS access key id'])
    assert run_scan(repo / 'sub', '--tracked').returncode == 1


def test_renamed_file_with_added_secret_is_scanned(repo):
    (repo / 'old.py').write_bytes(b'# existing harmless content\n' * 40)
    git(repo, 'add', 'old.py')
    git(repo, 'commit', '-q', '-m', 'base')
    git(repo, 'mv', 'old.py', 'new.py')
    with (repo / 'new.py').open('ab') as stream:
        stream.write(SYNTHETIC['AWS access key id'])
    git(repo, 'add', 'new.py')
    assert run_scan(repo, '--staged').returncode == 1
    git(repo, 'commit', '-q', '-m', 'synthetic secret')
    assert run_scan(repo, '--range', 'HEAD~1..HEAD').returncode == 1


def test_hook_installs_in_linked_worktree(repo, tmp_path):
    linked = tmp_path / 'linked'
    git(repo, 'worktree', 'add', '-q', '-b', 'linked', str(linked))
    assert run_install(linked).returncode == 0
    (linked / 'leak.py').write_bytes(SYNTHETIC['AWS access key id'])
    git(linked, 'add', 'leak.py')
    result = subprocess.run(['git', 'commit', '-m', 'blocked'], cwd=linked,
                            capture_output=True)
    assert result.returncode != 0


def test_hook_respects_custom_hooks_path(repo):
    git(repo, 'config', 'core.hooksPath', '.custom-hooks')
    assert run_install(repo).returncode == 0
    assert (repo / '.custom-hooks' / 'pre-commit').exists()


def test_relative_hooks_path_from_subdirectory(repo):
    git(repo, 'config', 'core.hooksPath', '.custom-hooks')
    (repo / 'sub').mkdir()
    assert run_install(repo / 'sub').returncode == 0
    assert (repo / '.custom-hooks' / 'pre-commit').exists()
    assert not (repo / 'sub' / '.custom-hooks').exists()


def test_foreign_hook_backup_is_never_overwritten(repo):
    hooks = repo / '.git' / 'hooks'
    hook = hooks / 'pre-commit'
    hook.write_text('#!/bin/sh\necho original\n')
    backup = hooks / 'pre-commit.pre-secret-scan'
    backup.write_text('older original')
    assert run_install(repo).returncode != 0
    assert backup.read_text() == 'older original'
    assert hook.read_text() == '#!/bin/sh\necho original\n'


def test_installed_hook_handles_shell_metacharacters_in_scanner_path(repo):
    folder = repo / "tools ' $(printf BAD) `printf BAD`"
    folder.mkdir()
    shutil.copy2(INSTALL, folder / 'install.py')
    shutil.copy2(Path(INSTALL).with_name('scan.py'), folder / 'scan.py')
    subprocess.run([sys.executable, str(folder / 'install.py')], cwd=repo,
                   capture_output=True, check=True)
    (repo / 'README.md').write_text('clean change\n')
    git(repo, 'add', 'README.md')
    result = subprocess.run(['git', 'commit', '-q', '-m', 'clean'], cwd=repo,
                            capture_output=True)
    assert result.returncode == 0, result.stderr.decode(errors='replace')


def test_git_blob_read_errors_fail_closed(scan, repo, monkeypatch):
    monkeypatch.chdir(repo)
    original = scan.git

    def broken(*args, **kwargs):
        if args[0] == 'show':
            raise scan.GitError('unreadable object')
        return original(*args, **kwargs)

    (repo / 'new.py').write_bytes(b'clean')
    git(repo, 'add', 'new.py')
    monkeypatch.setattr(scan, 'git', broken)
    assert scan.main(['--staged']) == 2
