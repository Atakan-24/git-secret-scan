"""Stops credentials from reaching a git commit.

Background: in a real project several API keys and bot tokens sat in
plaintext in tracked files for months, unnoticed until a backup was being
prepared. This catches that at commit time instead of at cleanup time.

    python scan.py --staged     what is staged for commit (hook default)
    python scan.py --tracked    every tracked file in the working tree
    python scan.py --history    every blob in git history (slow)

Exit code 0 = clean, 1 = findings, 2 = usage/environment error.
Install as a pre-commit hook with install.py.
"""

import re
import subprocess
import sys

# Each pattern carries a `prose_prone` flag.
#
# Why per-pattern and not global: the prose guard below is a *precision*
# tool for prefixes that can also occur in ordinary text. Applying it to
# every pattern silently discarded real Slack and GitHub tokens, because
# those are frequently all-lowercase-plus-digits and the old guard
# demanded both an uppercase letter and a digit. A structurally rigid
# prefix like `AKIA`, `ghp_` or `eyJhbGciOi` does not appear in prose, so
# it needs no guard at all — and giving it one only costs recall.
PATTERNS = [
    # (label, regex, prose_prone)
    ('OpenAI key',            re.compile(rb'\bsk-(proj-)?[A-Za-z0-9_-]{20,}'), True),
    ('Anthropic key',         re.compile(rb'\bsk-ant-[A-Za-z0-9_-]{20,}'), True),
    ('GitHub token',          re.compile(rb'\bgh[pousr]_[A-Za-z0-9]{30,}'), False),
    ('Slack token',           re.compile(rb'\bxox[baprs]-[A-Za-z0-9-]{10,}'), False),
    ('AWS access key id',     re.compile(rb'\b(?:AKIA|ASIA)[0-9A-Z]{16}\b'), False),
    ('Google OAuth token',    re.compile(rb'\bAQ\.[A-Za-z0-9_-]{30,}'), False),
    ('Google API key',        re.compile(rb'\bAIza[A-Za-z0-9_-]{35}\b'), False),
    ('Telegram bot token',    re.compile(rb'\b[0-9]{8,12}:AA[A-Za-z0-9_-]{30,}'), False),
    ('JWT (Supabase, n8n, …)', re.compile(
        rb'\beyJhbGciOi[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}'), False),
    ('private key block',     re.compile(rb'-----BEGIN [A-Z ]*PRIVATE KEY-----'), False),
]

# Placeholders that are meant to look like secrets.
#
# These are matched against the *matched value*, not the whole line. The
# old behaviour checked the entire line, which meant a real key was
# silently ignored whenever the word EXAMPLE appeared anywhere on the same
# line — including in a trailing comment.
ALLOW_VALUE = [
    re.compile(rb'REPLACE[_-]?ME', re.I),
    re.compile(rb'<[a-z_]+>', re.I),
    re.compile(rb'(YOUR|DEIN|EXAMPLE|BEISPIEL|DUMMY|SAMPLE|PLACEHOLDER|CHANGEME)', re.I),
    re.compile(rb'^x+$', re.I),
    re.compile(rb'(0{8,}|1{8,}|a{8,})', re.I),
]

# Explicit, auditable per-line opt-out. Deliberately verbose so it cannot
# be typed by accident and is greppable in review.
INLINE_IGNORE = re.compile(rb'secret-scan:\s*ignore')

# Files whose entire purpose is to carry fake values.
ALLOW_FILENAME = re.compile(
    r'(^|/)(\.env\.example|\.env\.sample|\.env\.template)$'
    r'|\.(example|sample|template|dist)$'
    r'|(^|/)(fixtures?|testdata|__fixtures__)/',
    re.I,
)

MAX_BLOB_BYTES = 5_000_000       # a blob larger than this is data, not source
BINARY_SNIFF_BYTES = 8000


class GitError(RuntimeError):
    """git could not be used — never silently treat this as 'clean'."""


def git(*args, check=True):
    """Run git and return stdout.

    `check` matters: the original version ignored git's exit code, so
    running outside a repository produced empty output, zero findings and
    a confident 'clean'. A scanner that passes when it cannot see anything
    is worse than no scanner.
    """
    try:
        out = subprocess.run(['git', *args], capture_output=True)
    except FileNotFoundError as exc:
        raise GitError('git is not installed or not on PATH') from exc
    if check and out.returncode != 0:
        detail = out.stderr.decode('utf-8', 'replace').strip().splitlines()
        raise GitError(f"git {' '.join(args)} failed: {detail[0] if detail else out.returncode}")
    return out.stdout


def allowed_value(value: bytes) -> bool:
    return any(p.search(value) for p in ALLOW_VALUE)


def allowed_filename(name: str) -> bool:
    return bool(ALLOW_FILENAME.search(name.replace('\\', '/')))


def looks_like_prose(value: bytes) -> bool:
    """True when the match is kebab-case words rather than a random key.

    The original guard asked whether the value contained both an uppercase
    letter and a digit. That was aimed at one real false positive —
    `ask-before-high-impact-changes` matching the OpenAI pattern — but it
    is the wrong question, for two reasons.

    First, the regexes now anchor on a word boundary, so that exact string
    no longer matches at all: the guard no longer protects against the
    case it was written for. Second, and much worse, it demanded
    properties that real tokens do not have. Slack and GitHub tokens are
    routinely all-lowercase-plus-digits, so the guard discarded them —
    turning a precision aid into a silent recall hole.

    This asks the question that actually separates the two: prose is
    lowercase words joined by hyphens; a key is a dense random run.
    """
    return bool(re.fullmatch(rb'[a-z]+(?:-[a-z]+){2,}', value))


def mask(value: str) -> str:
    """Show enough to locate the secret, never enough to use it."""
    return value[:10] + '…' + value[-4:] if len(value) > 18 else value


def scan_blob(name: str, data: bytes):
    """Return [(name, lineno, label, masked)] for one file's contents."""
    if allowed_filename(name):
        return []
    hits = []
    for label, pattern, prose_prone in PATTERNS:
        for match in pattern.finditer(data):
            value = match.group(0)
            start = data.rfind(b'\n', 0, match.start()) + 1
            end = data.find(b'\n', match.end())
            line = data[start:end if end != -1 else len(data)]
            if INLINE_IGNORE.search(line):
                continue
            if allowed_value(value):
                continue
            if prose_prone and looks_like_prose(value):
                continue
            lineno = data.count(b'\n', 0, match.start()) + 1
            hits.append((name, lineno, label, mask(value.decode('utf-8', 'replace'))))
    return hits


def is_binary(data: bytes) -> bool:
    return b'\x00' in data[:BINARY_SNIFF_BYTES]


def files_staged():
    names = git('diff', '--cached', '--name-only', '--diff-filter=ACM')
    for raw in names.split(b'\n'):
        if not raw.strip():
            continue
        name = raw.decode('utf-8', 'replace')
        yield name, git('show', f':{name}', check=False)


def files_tracked():
    for raw in git('ls-files', '-z').split(b'\x00'):
        if not raw.strip():
            continue
        name = raw.decode('utf-8', 'replace')
        yield name, git('show', f'HEAD:{name}', check=False)


def blobs_history():
    listing = git('cat-file', '--batch-all-objects',
                  '--batch-check=%(objectname) %(objecttype)')
    for row in listing.split(b'\n'):
        parts = row.split()
        if len(parts) == 2 and parts[1] == b'blob':
            sha = parts[0].decode()
            yield f'blob {sha[:10]}', git('cat-file', 'blob', sha, check=False)


SOURCES = {'--staged': files_staged, '--tracked': files_tracked, '--history': blobs_history}


def collect(mode: str):
    source = SOURCES[mode]
    hits = []
    for name, data in source():
        if len(data) > MAX_BLOB_BYTES or is_binary(data):
            continue
        hits.extend(scan_blob(name, data))
    return hits


def main(argv):
    mode = argv[0] if argv else '--staged'
    if mode in ('-h', '--help'):
        print(__doc__)
        return 0
    if mode not in SOURCES:
        print(__doc__, file=sys.stderr)
        return 2

    try:
        hits = collect(mode)
    except GitError as exc:
        # Loud on purpose: an unusable scanner must not look like a clean one.
        print(f'secret-scan {mode}: cannot run — {exc}', file=sys.stderr)
        return 2

    if not hits:
        print(f'secret-scan {mode}: clean')
        return 0

    print(f'secret-scan {mode}: {len(hits)} finding(s) — commit stopped\n')
    for name, lineno, label, masked in hits:
        print(f'  {name}:{lineno}\n    {label}: {masked}')
    print('\nCredentials belong in an untracked .env, not in a versioned file.')
    print('False alarm? Mark the placeholder, add "secret-scan: ignore" to the')
    print('line, or extend ALLOW_VALUE in scan.py. Last resort: git commit --no-verify')
    return 1


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
