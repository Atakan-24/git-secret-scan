"""A labelled corpus: every case carries the answer it should produce.

Two rules govern what may go in here.

1. Every "should be found" sample is synthetic and comes from
   tests/fixtures/synthetic_secrets.py — the one place in this repository
   allowed to hold credential-shaped strings. Nothing here is a real
   credential, and nothing here is defined twice.
2. Every "should be ignored" sample is a shape that genuinely occurs in
   real repositories. Inventing implausible negatives would inflate
   precision and make the measurement worthless.

The corpus is deliberately small and hand-labelled. A large auto-generated
one would look more impressive and mean less: nobody could check it.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'tests'))

from fixtures.synthetic_secrets import BY_KIND, PLACEHOLDERS  # noqa: E402

# (filename, content, should_be_detected)

# How a secret actually appears in a file. The same credential in four
# shapes, because a scanner that only handles `KEY = "..."` is a demo.
CONTEXTS = [
    ('py',   b'API_KEY = "%s"\n'),
    ('env',  b'SERVICE_TOKEN=%s\n'),
    ('json', b'{\n  "token": "%s"\n}\n'),
    ('yaml', b'credentials:\n  token: %s\n'),
]


def positives():
    return [
        (f'src/{kind}.{ext}', template % secret, True)
        for kind, secret in BY_KIND.items()
        for ext, template in CONTEXTS
    ]


# Shapes that look secret-adjacent and must never be reported. Each one is
# something that has caused a false positive in some scanner somewhere.
BENIGN_LITERAL = [
    ('src/ids.py',       b'user_id = "550e8400-e29b-41d4-a716-446655440000"\n'),
    ('src/hash.py',      b'sha = "e3b0c44298fc1c149afbf4c8996fb924'
                         b'27ae41e4649b934ca495991b7852b855"\n'),
    ('src/commit.py',    b'rev = "dae166f8c2b1490aa7f3e5d1c9b8a4e6f2d0c3b7"\n'),
    ('package.json',     b'{ "version": "1.24.0-beta.3" }\n'),
    ('src/data.py',      b'payload = "SGVsbG8gd29ybGQsIHRoaXMgaXMganVzdCB0ZXh0Lg=="\n'),
    ('ui/App.tsx',       b'const cls = "flex-row items-center justify-between gap-4";\n'),
    ('config.yaml',      b'mode: ask-before-high-impact-changes\n'),
    ('src/mod.py',       b'from my_package.sub_module import something_useful\n'),
    ('src/api.py',       b'BASE = "https://api.example.com/v2/resource/12345"\n'),
    ('README.md',        b'Pass your API key to the constructor.\n'),
    ('src/lorem.py',     b'text = "consectetur adipiscing elit sed do eiusmod tempor"\n'),
    ('src/colors.py',    b'ACCENT = "#b8860b"\nBG = "#0a0a0a"\n'),
    ('docs/curl.md',     b'curl -H "Authorization: Bearer $TOKEN" https://api.host/v1\n'),
    ('src/regex.py',     b'PATTERN = r"[A-Za-z0-9_-]{20,}"\n'),
]


def negatives():
    cases = [(name, blob, False) for name, blob in BENIGN_LITERAL]

    # Placeholders — the whole point of the allow-list.
    cases += [
        ('src/conf.py',  b'API_KEY = "' + PLACEHOLDERS['replace_me'] + b'"\n', False),
        ('src/conf2.py', b'API_KEY = "' + PLACEHOLDERS['x_padding'] + b'"\n', False),
        ('src/conf3.py', b'AWS = "' + PLACEHOLDERS['your_key'] + b'"\n', False),
    ]

    # Files whose job is to hold fake values — skipped by filename.
    cases += [
        ('.env.example',        b'OPENAI_API_KEY=' + BY_KIND['openai'] + b'\n', False),
        ('config.template',     b'token: ' + BY_KIND['github'] + b'\n', False),
        ('tests/fixtures/k.py', b'KEY = "' + BY_KIND['aws'] + b'"\n', False),
    ]

    # Explicit, auditable opt-out.
    cases += [
        ('src/legacy.py',
         b'OLD = "' + BY_KIND['aws'] + b'"  # secret-scan: ignore\n', False),
    ]
    return cases


def all_cases():
    return positives() + negatives()
