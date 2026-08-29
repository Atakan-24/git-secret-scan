"""Property-based tests.

Example tests prove a case; property tests prove a rule. Hypothesis
generates the inputs, including the ugly ones nobody thinks to write
down — nested quotes, lone surrogates, megabyte lines, empty files.

Each property below states something that must hold for *every* input,
and several of them are security properties rather than correctness ones.
"""

from conftest import SYNTHETIC
from hypothesis import given, settings
from hypothesis import strategies as st

import scan

# Imported at module level rather than taken as a fixture: Hypothesis
# rejects function-scoped fixtures, because the fixture would be torn down
# and rebuilt for every generated example. scan is a stateless module, so
# there is nothing to isolate anyway.

# Bounded so the suite stays fast in CI on a small runner.
FAST = settings(max_examples=150, deadline=None)

any_bytes = st.binary(max_size=2000)
secret_values = st.sampled_from(sorted(SYNTHETIC.values()))
filenames = st.sampled_from(['a.py', 'src/b.ts', 'deep/nested/c.go', '.env', 'Makefile'])


@FAST
@given(data=any_bytes, name=filenames)
def test_never_raises_on_arbitrary_input(data, name):
    """A pre-commit hook that crashes blocks every commit in the repo."""
    scan.scan_blob(name, data)


@FAST
@given(data=any_bytes, name=filenames)
def test_line_numbers_are_always_in_range(data, name):
    total_lines = data.count(b'\n') + 1
    for _, lineno, _, _ in scan.scan_blob(name, data):
        assert 1 <= lineno <= total_lines


@FAST
@given(secret=secret_values)
def test_masking_never_reveals_the_middle(secret):
    """Security property: the report must not be usable as the credential."""
    hits = scan.scan_blob('c.py', b'k = "' + secret + b'"\n')
    if not hits:
        return
    masked = hits[0][3]
    text = secret.decode('utf-8', 'replace')
    if len(text) > 18:
        middle = text[10:-4]
        assert middle not in masked, 'masked output leaked the secret body'
        assert masked.startswith(text[:10]) and masked.endswith(text[-4:])


@FAST
@given(secret=secret_values, before=st.integers(0, 40), after=st.integers(0, 40))
def test_detection_is_independent_of_position(secret, before, after):
    """A secret on line 500 is exactly as dangerous as one on line 1."""
    blob = (b'# filler\n' * before) + b'k = "' + secret + b'"\n' + (b'x = 1\n' * after)
    hits = scan.scan_blob('c.py', blob)
    assert hits, 'position must not affect detection'
    assert hits[0][1] == before + 1


@FAST
@given(secret=secret_values, noise=st.text(alphabet='abc def_-=.,;:()[]{}', max_size=60))
def test_surrounding_noise_never_removes_a_finding(secret, noise):
    """Monotonicity: adding benign text must not silence a real finding.

    Its absence is what made bug 2 possible — an unrelated word in a
    trailing comment used to suppress the whole line.
    """
    plain = scan.scan_blob('c.py', b'k = "' + secret + b'"\n')
    if not plain:
        return
    noisy = scan.scan_blob('c.py', b'k = "' + secret + b'"  # ' + noise.encode() + b'\n')
    if any(p.search(noise.encode()) for p in scan.ALLOW_VALUE):
        return          # the noise is itself a placeholder marker — fair suppression
    if scan.INLINE_IGNORE.search(noise.encode()):
        return          # explicit opt-out — also fair
    assert noisy, f'benign trailing text silenced a finding: {noise!r}'


@FAST
@given(data=any_bytes)
def test_scanning_is_deterministic(data):
    """Same input, same verdict — a flaky security gate gets bypassed."""
    assert scan.scan_blob('c.py', data) == scan.scan_blob('c.py', data)


@FAST
@given(secret=secret_values)
def test_inline_ignore_always_suppresses(secret):
    blob = b'k = "' + secret + b'"  # secret-scan: ignore\n'
    assert scan.scan_blob('c.py', blob) == []


@FAST
@given(data=any_bytes)
def test_binary_content_is_skipped(data):
    """A NUL byte means compiled output or an image, not source."""
    assert scan.is_binary(b'\x00' + data)
