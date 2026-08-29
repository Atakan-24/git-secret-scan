"""Prüft, ob Zugangsdaten in einen Commit rutschen.

Hintergrund: in einem realen Projekt lagen mehrere API-Schlüssel und
Bot-Tokens monatelang im Klartext in getrackten Dateien, unbemerkt bis zur
Vorbereitung eines Backups. Dieses Skript soll genau das beim nächsten
Commit abfangen, nicht erst beim nächsten Aufräumen.

Aufrufe:
    python scan.py --staged     nur was gerade zum Commit vorgemerkt ist
    python scan.py --tracked    alle getrackten Dateien im Arbeitsstand
    python scan.py --history    die komplette Git-Historie (langsam)

Rückgabe 0 = sauber, 1 = Fund. Als pre-commit-Hook installiert über install.py.
"""

import re
import subprocess
import sys

# Muster mit ihrem Klartextnamen. Bewusst eng gefasst: ein Muster, das bei
# jedem zweiten Wort anschlägt, wird abgeschaltet und schützt dann gar nichts.
PATTERNS = [
    ('OpenAI-Key',           re.compile(rb'\bsk-(proj-)?[A-Za-z0-9_-]{20,}')),
    ('Anthropic-Key',        re.compile(rb'\bsk-ant-[A-Za-z0-9_-]{20,}')),
    ('GitHub-Token',         re.compile(rb'gh[pousr]_[A-Za-z0-9]{30,}')),
    ('Slack-Token',          re.compile(rb'xox[baprs]-[A-Za-z0-9-]{10,}')),
    ('AWS-Access-Key',       re.compile(rb'AKIA[0-9A-Z]{16}')),
    ('Google-/AQ-API-Key',   re.compile(rb'AQ\.[A-Za-z0-9_-]{30,}')),
    ('Google-API-Key',       re.compile(rb'AIza[A-Za-z0-9_-]{30,}')),
    ('Telegram-Bot-Token',   re.compile(rb'\b[0-9]{8,12}:AA[A-Za-z0-9_-]{30,}')),
    ('JWT (u.a. Supabase, n8n)', re.compile(rb'eyJhbGciOi[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}')),
    ('privater Schlüssel',   re.compile(rb'-----BEGIN [A-Z ]*PRIVATE KEY-----')),
]

# Platzhalter, die absichtlich so aussehen. Wer hier etwas einträgt, muss
# sicher sein, dass es kein echter Wert ist.
ALLOW = [
    re.compile(rb'REPLACE_'),
    re.compile(rb'<[a-z_]+>'),
    re.compile(rb'(YOUR|DEIN|EXAMPLE|BEISPIEL|DUMMY|xxx|XXX)'),
    re.compile(rb'\.example$'),
]


def git(*args):
    out = subprocess.run(['git', *args], capture_output=True)
    return out.stdout


def allowed(line: bytes) -> bool:
    return any(p.search(line) for p in ALLOW)


def looks_like_prose(value: bytes) -> bool:
    """Echte Schlüssel mischen Groß-, Kleinbuchstaben und Ziffern.

    Ohne diese Prüfung schlug 'ask-before-high-impact-changes' als OpenAI-Key
    an — reiner Fließtext, der zufällig auf 'sk-' endete.
    """
    body = value.split(b'-----')[0]
    return not (re.search(rb'[A-Z]', body) and re.search(rb'[0-9]', body))


def scan_blob(name: str, data: bytes):
    hits = []
    for label, pattern in PATTERNS:
        for match in pattern.finditer(data):
            start = data.rfind(b'\n', 0, match.start()) + 1
            end = data.find(b'\n', match.end())
            line = data[start:end if end != -1 else len(data)]
            if allowed(line):
                continue
            if label != 'privater Schlüssel' and looks_like_prose(match.group(0)):
                continue
            value = match.group(0).decode('utf-8', 'replace')
            masked = value[:10] + '…' + value[-4:] if len(value) > 18 else value
            lineno = data.count(b'\n', 0, match.start()) + 1
            hits.append((name, lineno, label, masked))
    return hits


def files_staged():
    names = git('diff', '--cached', '--name-only', '--diff-filter=ACM')
    for raw in names.split(b'\n'):
        if not raw.strip():
            continue
        name = raw.decode('utf-8', 'replace')
        yield name, git('show', f':{name}')


def files_tracked():
    for raw in git('ls-files', '-z').split(b'\x00'):
        if not raw.strip():
            continue
        name = raw.decode('utf-8', 'replace')
        yield name, git('show', f'HEAD:{name}')


def blobs_history():
    listing = git('cat-file', '--batch-all-objects', '--batch-check=%(objectname) %(objecttype)')
    for row in listing.split(b'\n'):
        parts = row.split()
        if len(parts) == 2 and parts[1] == b'blob':
            sha = parts[0].decode()
            yield f'blob {sha[:10]}', git('cat-file', 'blob', sha)


def main(argv):
    mode = argv[0] if argv else '--staged'
    source = {'--staged': files_staged,
              '--tracked': files_tracked,
              '--history': blobs_history}.get(mode)
    if source is None:
        print(__doc__)
        return 2

    hits = []
    for name, data in source():
        if b'\x00' in data[:8000]:      # Binärdateien überspringen
            continue
        hits.extend(scan_blob(name, data))

    if not hits:
        print(f'secret-scan {mode}: sauber')
        return 0

    print(f'secret-scan {mode}: {len(hits)} Fund(e) — Commit gestoppt\n')
    for name, lineno, label, masked in hits:
        print(f'  {name}:{lineno}\n    {label}: {masked}')
    print('\nZugangsdaten gehören in eine .env, nicht in eine versionierte Datei.')
    print('Ist es ein Fehlalarm: Platzhalter kenntlich machen oder ALLOW in')
    print('scan.py (ALLOW-Liste) erweitern. Notfalls: git commit --no-verify')
    return 1


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
