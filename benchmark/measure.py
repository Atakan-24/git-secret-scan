"""Measures precision and recall — current version against the previous one.

    python benchmark/measure.py

Why this exists: "it works" is not a claim anyone can check. The README
quotes numbers, and these are the numbers. Running this reproduces them.

The previous algorithm is reimplemented below rather than pulled from git
history, so the comparison stays runnable from a fresh clone and cannot
drift silently when the file is reorganised. It is a faithful copy of the
logic as it stood before the fixes — the two guards it applied are exactly
the ones that were changed.
"""

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from corpus import all_cases  # noqa: E402

import scan  # noqa: E402

# --- the previous implementation, for comparison only ----------------------

OLD_PATTERNS = [(label, rx) for label, rx, _ in scan.PATTERNS]

OLD_ALLOW = [
    re.compile(rb'REPLACE_'),
    re.compile(rb'<[a-z_]+>'),
    re.compile(rb'(YOUR|DEIN|EXAMPLE|BEISPIEL|DUMMY|xxx|XXX)'),
    re.compile(rb'\.example$'),
]


def old_looks_like_prose(value: bytes) -> bool:
    """Required an uppercase letter AND a digit anywhere in the match."""
    body = value.split(b'-----')[0]
    return not (re.search(rb'[A-Z]', body) and re.search(rb'[0-9]', body))


def old_scan_blob(name: str, data: bytes):
    """No filename allow-list; allow-list applied to the whole line."""
    hits = []
    for label, pattern in OLD_PATTERNS:
        for match in pattern.finditer(data):
            start = data.rfind(b'\n', 0, match.start()) + 1
            end = data.find(b'\n', match.end())
            line = data[start:end if end != -1 else len(data)]
            if any(p.search(line) for p in OLD_ALLOW):
                continue
            if label != 'private key block' and old_looks_like_prose(match.group(0)):
                continue
            hits.append((name, 0, label, ''))
    return hits


# --- scoring ---------------------------------------------------------------

def evaluate(scanner):
    tp = fp = fn = tn = 0
    misses, false_alarms = [], []
    for name, blob, should_detect in all_cases():
        found = bool(scanner(name, blob))
        if should_detect and found:
            tp += 1
        elif should_detect and not found:
            fn += 1
            misses.append(name)
        elif not should_detect and found:
            fp += 1
            false_alarms.append(name)
        else:
            tn += 1
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {
        'tp': tp, 'fp': fp, 'fn': fn, 'tn': tn,
        'precision': precision, 'recall': recall, 'f1': f1,
        'misses': misses, 'false_alarms': false_alarms,
    }


def line(name, r):
    return (f'{name:<12} precision {r["precision"]:6.1%}   '
            f'recall {r["recall"]:6.1%}   F1 {r["f1"]:6.1%}   '
            f'(TP {r["tp"]}  FP {r["fp"]}  FN {r["fn"]}  TN {r["tn"]})')


def main():
    cases = all_cases()
    n_pos = sum(1 for *_, should in cases if should)
    print(f'corpus: {len(cases)} cases — {n_pos} should be detected, '
          f'{len(cases) - n_pos} should be ignored\n')

    old = evaluate(old_scan_blob)
    new = evaluate(scan.scan_blob)
    print(line('previous', old))
    print(line('current', new))

    if old['misses']:
        print(f'\nmissed by the previous version ({len(old["misses"])}):')
        for name in old['misses']:
            print(f'  {name}')
    if new['misses']:
        print(f'\nstill missed ({len(new["misses"])}):')
        for name in new['misses']:
            print(f'  {name}')
    if new['false_alarms']:
        print(f'\nfalse alarms ({len(new["false_alarms"])}):')
        for name in new['false_alarms']:
            print(f'  {name}')

    # CI gate. Recall is the one that matters for a security tool: a false
    # alarm costs a developer a minute, a miss costs a credential.
    ok = new['recall'] >= 0.95 and new['precision'] >= 0.95
    print('\n' + ('PASS' if ok else 'FAIL')
          + ' — gate: precision >= 95%, recall >= 95%')
    return 0 if ok else 1


if __name__ == '__main__':
    sys.exit(main())
