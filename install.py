"""Installs scan.py as this repository's pre-commit hook.

Hooks live in .git/hooks/ and are not versioned, so this has to run once
after every clone — otherwise nothing is checking.

    python install.py

Works regardless of where this folder sits inside the repository (root, or
e.g. tools/git-secret-scan/): the generated hook resolves scan.py relative
to *itself*, not to the repository root.
"""

import subprocess
import sys
from pathlib import Path

SCAN_PY = (Path(__file__).parent / 'scan.py').resolve()

HOOK_MARKER = '# git-secret-scan pre-commit hook'

# The interpreter is baked in at install time rather than relying on
# `python` being on PATH inside the hook's environment. Git runs hooks
# with a minimal environment, and on many systems `python` is either
# absent or still points at Python 2 — a hook that fails to start is a
# hook that silently stops protecting the repository.
HOOK_TEMPLATE = f"""#!/bin/sh
{HOOK_MARKER}
# Blocks commits containing credentials. Bypass: git commit --no-verify
"{{python}}" "{{scan_py}}" --staged || exit 1
"""


def main():
    root = subprocess.run(['git', 'rev-parse', '--show-toplevel'],
                          capture_output=True, text=True)
    if root.returncode != 0:
        raise SystemExit('Not a git repository.')

    hooks = Path(root.stdout.strip()) / '.git' / 'hooks'
    hooks.mkdir(parents=True, exist_ok=True)
    target = hooks / 'pre-commit'

    if target.exists():
        existing = target.read_text(encoding='utf-8', errors='replace')
        if HOOK_MARKER not in existing:
            backup = target.with_suffix('.pre-secret-scan')
            backup.write_text(existing, encoding='utf-8')
            print(f'Existing hook backed up to {backup.name} — merge it by hand.')

    hook = HOOK_TEMPLATE.format(python=Path(sys.executable).as_posix(),
                                scan_py=SCAN_PY.as_posix())
    # write_bytes, not write_text: the hook is a shell script and must keep
    # LF endings on every platform — CRLF makes /bin/sh fail with a
    # famously unhelpful error. write_text(newline=…) would express that
    # directly but only exists on Python 3.10+, and this supports 3.9.
    # (Found by the CI matrix, not locally: the dev machine runs 3.12.)
    target.write_bytes(hook.encode('utf-8'))
    target.chmod(0o755)
    print(f'pre-commit hook installed: {target}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
