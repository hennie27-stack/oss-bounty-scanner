# oss-bounty-scanner

Find open, **funded** open-source bounties — and skip the farms, the claimed ones, the
hardware-gated ones and the jokes.

Bounty money lives on GitHub issues. Algora, Opire and IssueHunt all park their rewards on a
GitHub issue, so one reader covers every platform: the public GitHub Search API. This tool reads
it, extracts the dollar amount, measures the competition, then filters out the reasons a ticket
is *not* worth your day.

## Why a filter is the whole product

The first version of this ranked `$5,000` tickets at the top. They were garbage. Every one of
these was found by opening a ticket that looked great:

| trap | real example |
|---|---|
| bot farm, by name | `*/BountyScout`, `SecureBananaLabs/bug-bounty`, `*/bounty-plaza` |
| bot farm, by volume | a repo posting 43 fake `$500+` bounties, 13 stars, 120 forks, its own bot "claiming" them |
| already claimed | tickets where the reporter filed their own fix PR **20 seconds** after opening the issue |
| hardware-gated | a real, funded `$3,000` bounty needing a Blackhole **p150** accelerator card |
| maintainer refuses outsiders | a `$1,110` bounty whose pinned comment says *"we are not accepting any PRs from the community"* |
| blocked by its own label | `$300` + `good first issue` + **`PAUSED - NOT accepting new contributors`** |
| joke / anti-bounty | `$500 Reverse bounty ... pay me $500 ... *the bounty is negative*` |
| already finished | `$100` on a bounty whose own comments say *"30 submissions received"* |

The verdict sections are printed separately, so you can see *why* something was rejected instead
of wondering whether the filter ate a real one.

## Install & run

Python 3.10+, one dependency:

```bash
pip install requests
```

```bash
python bounty_scan.py                              # console + bounty_scan.txt
python bounty_scan.py --min 100 --pages 2          # only >= $100, two pages per query
python bounty_scan.py --claims 30 --opire          # read ticket pages + Opire's funded board
python bounty_scan.py --detail <issue-url>         # full ticket + recent comments
python bounty_scan.py --whoami                     # check an optional GitHub token
```

| flag | what it does | cost |
|---|---|---|
| `--opire` | reads Opire's own funded board and locates each issue on GitHub | ~6 searches |
| `--claims N` | reads the top N ticket **pages** and flags an existing fix PR, hardware needs, and a maintainer refusal | 0 API budget (HTML) |
| `--trust N` | checks the top N repos for stars/forks/last push and demotes farms | 1 search each |
| `--core N` | resolves the real repo language for the shortlist | 1 core call each |
| `--pages N` | pages of 100 results per query | N searches per query |
| `--min N` | ignore bounties under N dollars | free |

## Authentication is optional but transforms it

Unauthenticated GitHub gives **10 searches/minute and 60 core calls/hour** — measured, and 60 is
nothing. A fine-grained read-only token raises that to **30/minute and 5,000/hour**. Put the
token in `github_token.txt` (one line, `github_pat_...`) or set `GITHUB_TOKEN`. The file is
gitignored; the token is only ever printed masked, like `github_pat_1...abcd`.

## Scoring

```
score = dollars / (1 + comments)
      x 1.6 good-fit language      x 0.5 C/C++/Rust/Go
      x 2.0 small scope (docs/typo/tests/rename)
      x 1.5 repo has 100+ stars    x 0.3 repo has none
      x 0.10 bait farm             x 0.05 already claimed
      x 0.02 maintainer refuses PRs
```

## Tests

```bash
python -m unittest discover -s tests -v
```

The unit tests are offline: regexes, scoring, the money parser, the masker and the farm
heuristics. No network, no token.

## Scope and honesty

This finds work; it does not claim rewards for you, and it cannot know a maintainer's private
intentions. Read the ticket before you spend a day on it — that is exactly what this tool makes
cheap.

MIT licensed.
