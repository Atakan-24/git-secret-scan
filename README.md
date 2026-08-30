# git-secret-scan

[![CI](https://github.com/Atakan-24/git-secret-scan/actions/workflows/ci.yml/badge.svg)](https://github.com/Atakan-24/git-secret-scan/actions/workflows/ci.yml)
![coverage 98%](https://img.shields.io/badge/coverage-98%25-brightgreen)
![precision 100%](https://img.shields.io/badge/precision-100%25-brightgreen)
![recall 100%](https://img.shields.io/badge/recall-100%25-brightgreen)
![dependencies none](https://img.shields.io/badge/dependencies-none-blue)
![python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue)

A pre-commit hook that stops API keys and tokens from reaching a git
commit. Ten credential types, no dependencies, one file.

```
$ git commit -m "add config"
secret-scan --staged: 1 finding(s) — commit stopped

  src/config.py:14
    AWS access key id: AKIA2X4YQZ…3RTB

Credentials belong in an untracked .env, not in a versioned file.
```

---

## Why this exists

In a project I run, five live credentials — an OpenAI key, an n8n API key,
another API key and two Telegram bot tokens — sat in plaintext in tracked
files for **months**. Nobody noticed until I was preparing a backup and
happened to read the files I was about to copy.

Nothing failed. No alert fired. That is the whole problem: a leaked
credential in a repository is invisible until it is exploited, and by then
the fix is rotation plus an audit of everything the key could reach.

The tool that catches it has to run at the only moment the developer is
guaranteed to be present — the commit.

## What it does

```bash
python scan.py --staged      # what is staged for commit (the hook default)
python scan.py --tracked     # every tracked file in the working tree
python scan.py --history     # every blob in git history — deleting the file
                             # does not undo the leak
```

Exit code `0` clean, `1` findings, `2` usage or environment error.

Findings are always masked (`AKIA2X4YQZ…3RTB`). A security tool that
prints the full credential into a terminal, a CI log and a scrollback
buffer has just made the problem worse.

## Install

```bash
git clone https://github.com/Atakan-24/git-secret-scan
python git-secret-scan/install.py     # run inside the repo you want protected
```

Works from anywhere in the repository — the generated hook resolves
`scan.py` relative to itself, and bakes in the absolute path of the
interpreter that installed it, because `python` is frequently absent from
the minimal environment git gives a hook.

An existing foreign `pre-commit` hook is backed up, never overwritten.

## Use it in CI

The hook protects the developer who installed it. The GitHub Action
protects the repository from everyone else — including the developer who
used `--no-verify`.

```yaml
- uses: actions/checkout@v4
  with: { fetch-depth: 0 }
- uses: Atakan-24/git-secret-scan@main
  with:
    mode: changes          # default: only what this PR introduces
```

`mode: changes` is the one that matters. Pointing a scanner at an existing
repository reports every credential ever committed — on day one that is a
wall of findings nobody can action, and a check that always fails is a
check that gets deleted. Scanning only what the pull request *adds* passes
on merge day and fails on what the author actually wrote.

The same logic is available locally:

```bash
python scan.py --range main..HEAD
```

The action fails the job on a finding, writes a masked summary to the run
page, and exposes a `findings` output. A scanner that cannot run exits `2`
and **always** fails, regardless of `fail-on-finding` — an unusable check
must never be mistaken for a passing one.

## Architecture

One file, three layers.

**Pattern table.** `PATTERNS` in `scan.py` holds ten credential types, each
a regex plus a `prose_prone` flag. The flag is per-pattern, not global,
because a false-positive guard that is right for one prefix is wrong for
another — see the first bug below.

**Sources → one scanner.** Four generators — `files_staged`,
`files_tracked`, `blobs_history`, `files_in_range` — each yield
`(name, bytes)` pairs from a different git command (`diff --cached`,
`ls-files`, `cat-file --batch-all-objects`, `diff <range>`). `collect()`
feeds every pair through the same `scan_blob()` regardless of source, so
`--staged`, `--tracked`, `--history` and `--range` are one detector with
four inputs — a fix to detection fixes all four at once, not one at a time.

**Two installation points, one scanner underneath.** `install.py` writes
a `.git/hooks/pre-commit` script that shells out to `scan.py --staged`
(hooks are not versioned, so this runs once per clone, with the
interpreter path baked in rather than trusting `python` on `PATH`).
`action.yml` wraps the same `scan.py` in a composite GitHub Action that
resolves `--range <base>..<head>` from whatever triggered it — a pull
request's base/head SHAs, or `before`/`GITHUB_SHA` for a push. Hook and
Action call the identical detector; only the source of "what to scan" and
the audience (the developer vs. every reviewer) differ.

---

## Measured, not claimed

`benchmark/measure.py` runs a hand-labelled corpus of 61 cases — 40 that
must be detected across four file formats, 21 benign shapes that must not
be — and scores the current implementation against the previous one.

| | precision | recall | F1 |
|---|---|---|---|
| previous version | 91.4 % | **80.0 %** | 85.3 % |
| current | **100 %** | **100 %** | **100 %** |

Reproduce it in one command:

```bash
python benchmark/measure.py
```

CI fails the build if either number drops below 95 %. A regression in a
security tool is a silent one, so it needs a gate rather than a number
someone remembers to check.

**Read that 100 % correctly.** The corpus is one I wrote, so the honest
claim is "no known failure mode remains", not "nothing gets past it". The
number that actually matters is the one in the row above: recall was 80 %
and I did not know until I measured it.

---

## Three bugs I found in my own tool

Each was a **false negative** — the failure mode that matters here,
because it looks exactly like success. There is a regression test for each
in `tests/test_regressions.py`.

### 1. The false-positive guard was eating real tokens

The original had a guard asking *"does this match contain both an
uppercase letter and a digit?"* It existed for one real false positive:
the config string `ask-before-high-impact-changes`, which matched the
OpenAI `sk-` pattern.

Two things were wrong with it.

It no longer did its job — the patterns had since gained a `\b` word
boundary, so `ask-before-…` stopped matching anyway. And it was applied to
**every** pattern, while Slack and GitHub tokens are routinely
all-lowercase-plus-digits. So the guard silently discarded them:

```
xoxb-12345…   (Slack bot token)    → dropped
ghp_ab3xy9…   (GitHub token)       → dropped
```

(Shortened here on purpose: written out in full, this tool flags its own
README — which it did, on the commit that added this section.)

**2 of 10 supported credential types were undetectable.** That is the
entire 80 % recall figure above.

The fix is not a better regex, it is a better question. Prose is lowercase
words joined by hyphens; a key is a dense random run. The guard now asks
that, and only for the two patterns where `sk-` can collide with ordinary
text — patterns with a rigid prefix like `AKIA` or `eyJhbGciOi` never
needed it, and guarding them only cost recall.

### 2. A placeholder anywhere on the line disabled the line

The allow-list matched against the **whole line**, so this got through:

```python
API_KEY = "sk-proj-Ab3xY9zQ…"   # see EXAMPLE in the docs
```

A real key, silently ignored, because of a word in a trailing comment.
The allow-list now matches against the **matched value**, which is where
a placeholder actually lives. Explicit per-line suppression still exists,
but it has to be written on purpose: `# secret-scan: ignore`.

### 3. A broken git environment reported "clean"

`git`'s exit code was ignored. Run outside a repository, or with `git`
missing from `PATH`, and every mode produced no output, no findings, and
exit `0`:

```
secret-scan --tracked: clean
```

A hook that passes when it cannot see anything is worse than no hook,
because it is trusted. Git failures now raise and exit `2`.

---

## Trade-offs

**Regexes, not entropy.** A Shannon-entropy check catches key formats
nobody has enumerated yet, and it also flags every minified bundle, base64
blob and UUID in the repository. High false-positive tools get disabled,
and a disabled scanner protects nothing. Ten known prefixes at high
precision beats a general detector at 70 %.

**The allow-list matches values, not lines.** More precise, and it means a
placeholder must actually *be* the value. The cost: a genuinely odd
placeholder that looks nothing like one needs the explicit
`# secret-scan: ignore` marker.

**`--history` is slow and that is correct.** It walks every blob in the
object store. It is not in the hook — it is the command you run once,
after inheriting a repository whose past you do not know.

**Fails closed.** Any uncertainty about the environment exits `2` rather
than reporting clean. A scanner is trusted; it must never be quietly
wrong.

**Scoped narrowly on purpose.** Ten credential types, one integration
point. Not an all-purpose SAST tool.

## What it deliberately does not do

- **Rewrite history.** It reports what is in the past; it does not touch
  it. `filter-repo` and BFG exist, they are destructive, and that decision
  belongs to a human who understands what a force-push does to their team.
- **Verify keys against live APIs.** Confirming a key is valid means
  transmitting it to a third party. A scanner must not make the exposure
  worse in order to grade it.
- **Detect passwords or generic high-entropy strings.** See the entropy
  trade-off above.
- **Auto-fix.** Moving a value to `.env` requires knowing how the
  application loads config. Guessing produces a broken app and a developer
  who uninstalls the hook.
- **Phone home.** No network calls anywhere, by design and verifiable in
  one file.

## Testing

```bash
pip install pytest hypothesis coverage ruff
python -m coverage run -m pytest && python -m coverage report
```

**98 tests, 98 % coverage**, across five suites:

| suite | what it protects |
|---|---|
| `test_detection.py` | every pattern fires, in four realistic file formats. Parametrised over the pattern table, so adding a pattern without a sample fails the build |
| `test_false_positives.py` | UUIDs, hashes, base64, semver, prose, placeholders and fixture files stay silent |
| `test_regressions.py` | one test per bug above — they cannot come back |
| `test_properties.py` | property-based (Hypothesis): never crashes on arbitrary bytes, line numbers always in range, **masking never leaks the secret body**, detection independent of position, benign text never silences a finding, deterministic |
|  `test_cli.py` / `test_main.py` / `test_range.py` | real `git init` repositories, real commits, an installed hook actually blocking one |

CI runs on **Linux, macOS and Windows × Python 3.9 and 3.13** — the tool
installs on whatever machine a developer has, so that claim gets tested
rather than assumed. A `dogfood` job runs the scanner against this
repository's own tracked files and full history on every push.

> The synthetic credentials used in tests live in `tests/fixtures/`, which
> `scan.py` skips by convention. The alternative — teaching the tool to
> ignore `tests/` — would have meant missing the real key someone
> eventually pastes into a test file.

## License

All rights reserved. This code is published to be read as a work sample —
it is **not** licensed for reuse, redistribution or modification. If you
would like to use it, get in touch first.
