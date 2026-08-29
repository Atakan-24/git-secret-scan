"""Hängt scan.py als pre-commit-Hook in dieses Repo ein.

Hooks liegen in .git/hooks/ und werden nicht mitversioniert — nach einem Klon
muss das hier einmal laufen, sonst prüft niemand mehr.

    python install.py

Funktioniert unabhängig davon, wo dieser Ordner im Repo liegt (Wurzel oder
z.B. tools/git-secret-scan/) — der Hook merkt sich den Pfad zu scan.py
relativ zu SICH SELBST, nicht relativ zur Repo-Wurzel.
"""

import subprocess
import sys
from pathlib import Path

SCAN_PY = (Path(__file__).parent / 'scan.py').resolve()

HOOK_MARKER = '# git-secret-scan pre-commit hook'
HOOK_TEMPLATE = """#!/bin/sh
""" + HOOK_MARKER + """
# Blockiert Commits, in denen Zugangsdaten stecken. Umgehen: git commit --no-verify
python "{scan_py}" --staged || exit 1
"""


def main():
    root = subprocess.run(['git', 'rev-parse', '--show-toplevel'],
                          capture_output=True, text=True)
    if root.returncode != 0:
        raise SystemExit('Kein Git-Repo hier.')
    hooks = Path(root.stdout.strip()) / '.git' / 'hooks'
    hooks.mkdir(parents=True, exist_ok=True)
    target = hooks / 'pre-commit'

    if target.exists() and HOOK_MARKER not in target.read_text(encoding='utf-8', errors='replace'):
        backup = target.with_suffix('.vor-secret-scan')
        backup.write_text(target.read_text(encoding='utf-8', errors='replace'), encoding='utf-8')
        print(f'Vorhandener Hook gesichert nach {backup.name} — bitte von Hand zusammenführen.')

    target.write_text(HOOK_TEMPLATE.format(scan_py=SCAN_PY.as_posix()), encoding='utf-8', newline='\n')
    target.chmod(0o755)
    print(f'pre-commit-Hook eingerichtet: {target}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
