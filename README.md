# git-secret-scan

[![CI](https://github.com/Atakan-24/git-secret-scan/actions/workflows/ci.yml/badge.svg)](https://github.com/Atakan-24/git-secret-scan/actions/workflows/ci.yml)

A dependency-free Python pre-commit hook and GitHub Action that detect ten credential patterns in Git content. Findings contain file/line locations and masked values. Status: maintained command-line tool; detection is heuristic.

## Problem and implementation

Credentials can reach Git history before anyone notices. `scan.py` collects bytes from the index, working tree, a commit range or Git objects, then applies one pattern table. `install.py` writes the hook using Git's actual hooks path, including linked worktrees and `core.hooksPath`.

- Python 3.9+; Git required; no runtime Python dependencies.
- Exit `0`: no findings in scanned content; `1`: findings; `2`: usage or environment failure.
- Git object read failures fail the check. NUL-separated filenames preserve Unicode and control characters. Renamed files are included.

## Usage

```sh
git clone https://github.com/Atakan-24/git-secret-scan
python git-secret-scan/install.py  # run inside the repository to protect
python git-secret-scan/scan.py --staged
python git-secret-scan/scan.py --tracked   # current working-tree bytes
python git-secret-scan/scan.py --range main..HEAD
python git-secret-scan/scan.py --history
```

A foreign hook is replaced after a backup is written; combine it manually if both checks are needed. The generated hook uses the interpreter and scanner paths from installation, so reinstall after moving either. Hooks can be bypassed; use CI as a separate check.

```yaml
- uses: actions/checkout@v4
  with: { fetch-depth: 0 }
- uses: Atakan-24/git-secret-scan@main
  with:
    mode: changes
```

Use a reviewed commit SHA instead of `main` when pinning dependencies. The action scans changed files at the range endpoint, not only added lines or every intermediate commit.

## Tests and benchmark

```sh
python -m pip install -e '.[dev]'
python -m pytest
python -m coverage run -m pytest
python -m coverage report
python benchmark/measure.py
ruff check .
```

Tests use synthetic credentials and temporary Git repositories. They cover detection, opt-outs, masked output, Git errors, Unicode/renamed paths, working-tree changes and hook installation. CI covers Linux, macOS and Windows; see the workflow for its Python matrix.

The labelled benchmark contains 61 synthetic cases: 40 positive and 21 negative. The current detector finds all positives and rejects all negatives in that corpus. This result does not establish real-world precision or recall. The benchmark and earlier detector are versioned so the comparison is reproducible.

## Limits

Regex detection cannot establish whether a token is live. Explicit ignores, fixture/template exemptions, binary detection and the 5 MB size limit skip content. Unsupported credential formats, secrets outside Git and some encoded secrets are not covered. Rotate exposed credentials; removing a file does not remove earlier Git objects.

[Earlier detection bugs and development notes](docs/DEVELOPMENT.md)
