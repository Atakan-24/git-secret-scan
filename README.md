# git-secret-scan

A tiny, dependency-free pre-commit hook that stops API keys and tokens from
ever reaching a commit — for OpenAI, Anthropic, GitHub, Slack, AWS, Google,
Telegram bot tokens, JWTs (Supabase/n8n and friends), and PEM private keys.

## Why this exists

On a real project, five separate credentials — an OpenAI key, an n8n API
key, another API key, and two Telegram bot tokens — sat in plain text in
tracked files for months. Nobody noticed until a GitHub backup was being
prepared. A pre-commit scan would have caught every one of them on day one.
That's what this is.

## Design choices that matter more than the regex list

- **No dependencies.** Pure `subprocess` + `re`, stdlib only — works in any
  Python 3 environment, nothing to `pip install` before it can protect you.
- **Patterns are deliberately narrow.** A pattern that fires on every other
  word gets disabled by whoever hits it twice, and then it protects
  nothing. Each pattern targets a real, structurally distinctive token
  format (e.g. `sk-ant-` + 20 base62 chars), not a loose heuristic.
- **A prose false-positive filter.** An earlier, naive version flagged the
  literal string `ask-before-high-impact-changes` as a leaked OpenAI key,
  because it happened to contain `sk-`. Real keys mix upper/lowercase
  letters and digits; English prose usually doesn't. `looks_like_prose()`
  uses that difference to throw the false positive out without weakening
  the pattern itself.
- **An explicit allowlist for intentional placeholders** — `REPLACE_`,
  `<placeholder>`, `YOUR_...`, `.example` files — so documentation showing
  *the shape* of a key doesn't get blocked.
- **Three scan depths, one scanner.** `--staged` for the pre-commit hook
  itself, `--tracked` for a full working-tree audit, `--history` to check
  whether a secret ever made it into a *previous* commit (slow — walks
  every blob in the repo, which is the only way to know for sure).

## Use

```bash
python install.py          # installs the hook into .git/hooks/pre-commit
git commit ...              # the hook runs automatically, blocks on a hit
python scan.py --tracked    # audit everything already committed
python scan.py --history    # audit the entire git history (slow)
```

A hit looks like this and exits non-zero:

```
secret-scan --staged: 1 Fund(e) — Commit gestoppt

  config.py:14
    OpenAI-Key: sk-proj-abc…wxyz

Zugangsdaten gehören in eine .env, nicht in eine versionierte Datei.
```

(Output is in German — this was extracted from a German-language project.
The logic reads fine either way; feel free to send a PR translating the
strings if that's useful to you.)

False positive, or an intentional placeholder? Mark it with one of the
allowlist patterns in `scan.py`, or extend `ALLOW`. Genuinely need to bypass
once: `git commit --no-verify`.

## License

All rights reserved. This code is shared here to read as a work sample —
it is **not** licensed for reuse, redistribution, or modification. If
you'd like to use it in your own project, reach out first.
