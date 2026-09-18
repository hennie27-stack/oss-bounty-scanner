"""bounty_scan.py - find open, funded GitHub bounties we can actually solve.

Why GitHub is the source: every real bounty platform (Algora, Opire, IssueHunt)
parks its money on a GitHub *issue*, so one reader covers them all. No login is
needed for search - unauthenticated GitHub allows 10 queries per minute.

Usage
    python Money\\bounty_scan.py                 -> console + Money\\bounty_scan.txt
    python Money\\bounty_scan.py --min 100       -> only bounties of $100+
    python Money\\bounty_scan.py --json q.json
    python Money\\bounty_scan.py --detail <issue html_url>
"""

from __future__ import annotations

import argparse
import html as html_module
import json
import os
import re
import sys
import time
from datetime import datetime, timezone

import requests

UA = {"User-Agent": "bounty-scan/1.0 (personal job search)",
      "Accept": "application/vnd.github+json",
      "X-GitHub-Api-Version": "2022-11-28"}

SEARCH = "https://api.github.com/search/issues"
ISSUE = "https://api.github.com/repos/{repo}/issues/{num}"
COMMENTS = "https://api.github.com/repos/{repo}/issues/{num}/comments"
REPO = "https://api.github.com/repos/{repo}"

# Optional GitHub token, read from this file or from the environment.
# Without it: 10 searches/minute and 60 core calls/hour. With it: 30/minute and 5,000/hour.
TOKEN_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "github_token.txt")
TOKEN = ""


def load_token() -> str:
    for env in ("GITHUB_TOKEN", "GH_TOKEN"):
        v = (os.environ.get(env) or "").strip()
        if v:
            return v
    if os.path.exists(TOKEN_FILE):
        with open(TOKEN_FILE, encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if line.startswith(("github_pat_", "ghp_", "gho_", "ghs_")):
                    return line
    return ""


def mask(token: str) -> str:
    """Never print a whole token - not in a report, not in a log."""
    if not token:
        return "(none)"
    return token[:12] + "..." + token[-4:] if len(token) > 20 else "(short/invalid)"


def headers() -> dict:
    h = dict(UA)
    if TOKEN:
        h["Authorization"] = "Bearer " + TOKEN
    return h

QUERIES = [
    ("algora", 'state:open type:issue label:"\U0001f48e Bounty"'),
    ("bounty-label", "state:open type:issue label:bounty"),
    ("bounty-label-caps", "state:open type:issue label:Bounty"),
    ("money-label", 'state:open type:issue label:"\U0001f4b0 Bounty"'),
    ("title-dollar", 'state:open type:issue "BOUNTY $" in:title'),
    ("title-bracket", 'state:open type:issue "bounty:" in:title'),
    # A brand-new GitHub account with zero repositories is ignored by maintainers and scored
    # as spam by payout platforms, so the first wins should be small, uncontested and obviously
    # legitimate: docs, typos, tests, single-file fixes.
    ("python", "state:open type:issue label:bounty language:python"),
    ("goodfirst", 'state:open type:issue label:bounty label:"good first issue"'),
    ("docs", "state:open type:issue label:bounty documentation"),
    ("typo", "state:open type:issue label:bounty typo"),
]

# label or repo language -> how good a fit this is for what we can do well
GOOD_LANGS = {"python", "javascript", "typescript", "html", "css", "shell",
              "bash", "markdown", "json", "yaml", "vue", "svelte", "php", "sql"}
HARD_LANGS = {"c", "c++", "rust", "go", "java", "kotlin", "swift", "c#",
              "objective-c", "assembly", "zig", "haskell", "ruby", "scala"}

PLATFORM_HINTS = ("opire", "algora", "issuehunt", "bountyhub", "bountysource",
                  "polar.sh", "huntr", "gitcoin")

# Language guessing without an API call. The unauthenticated core REST limit here is
# only 60 requests/hour, so fetching each repo's language would stall the scan - this
# reads the labels and the ticket text instead, which is free and good enough.
LANG_WORDS = {
    "python": r"\bpython|django|flask|pandas|numpy|pytest\b",
    "javascript": r"\bjavascript|\bnode\.?js|npm\b|express\b",
    "typescript": r"\btypescript|\bts\b|nest\.?js|react\b|next\.?js",
    "html": r"\bhtml|css3?\b|scss|tailwind",
    "css": r"\bcss\b|scss|sass\b",
    "rust": r"\brust|cargo\b|tokio\b",
    "go": r"\bgolang|\bgo 1\.|gorm\b",
    "c++": r"\bc\+\+|cpp\b|cmake\b",
    "c#": r"\bc#|\.net\b|unity3d",
    "java": r"\bjava\b|maven|gradle|spring boot",
    "php": r"\bphp|laravel|wordpress",
    "ruby": r"\bruby\b|rails\b",
    "shell": r"\bbash\b|shell script|powershell",
    "markdown": r"\bdocs?\b|documentation|readme|typo",
    "docker": r"\bdocker\b|dockerfile|kubernetes|k8s\b",
    "sql": r"\bsql\b|postgres|mysql|sqlite",
    "swift": r"\bswift\b|xcode\b",
    "kotlin": r"\bkotlin\b|android\b",
}

# how many core-API lookups the enrich step may spend (limit is 60/hour)
ENRICH_CAP = 30

# --- bait detection -----------------------------------------------------------------
# The first scan proved this is the real problem. Repos named like a bounty aggregator,
# or tickets with hundreds of comments under a small prize, are farms where thousands
# of bots pile in and nobody gets paid. The genuine tickets come from real product
# repos (tenstorrent, BasedHardware/omi, tscircuit) with a handful of comments.
FARM_REPO = re.compile(r"bount(y|ies)[-_]?(hunt|hunter|hunters|plaza|scout|farm|alert)"
                       r"|bug[-_]bounty|bounty[-_]?(list|board|radar|hub)", re.I)
FARM_TITLE = re.compile(r"bounty alert|new opportunit|bounty discovery|"
                        r"wheel of fortune|airdrop|claim your", re.I)
CROWDED_COMMENTS = 50      # more chat than this on a small prize means a bot swarm

# --- claim detection ----------------------------------------------------------------
# The second scan proved this matters more than anything else. On the real BasedHardware
# tickets the issue author filed the fix PR 20 seconds after opening the issue, and a
# second agent filed a competing PR the same day. So before doing any work, read the
# comments and ask: has somebody already said "PR #1234"?
CLAIM_RX = re.compile(
    r"(github\.com/[\w.\-]+/[\w.\-]+/pull/\d+"
    r"|/pulls?/\d+"
    r"|\bPR\s*#?\d{2,}\b"
    r"|#\d{2,}\b"
    r"|fix is up|fixed in|submitted (a |the )?(fix|pr|pull)"
    r"|ready for review|working on (this|it)|i'?ll take|i am taking|claiming (this|the))",
    re.I)

# The weak pattern above matched any bare "#1234" reference, and issue threads are full of
# those, so a first version called almost every ticket "claimed" - a false positive I caught
# by testing three dummy references. A claim needs a STRONG signal, not three passing mentions.
STRONG_CLAIM_RX = re.compile(
    r"(github\.com/[\w.\-]+/[\w.\-]+/pull/\d+"
    r"|/pulls?/\d+"
    r"|\bPR\s*#\d{2,}\b"
    r"|PR Submitted"
    r"|fix is up|i (have )?opened (a|the) (pr|pull request)"
    r"|(created|opened|raised|sent) (a|the|my) (pr|pull request|pull)"
    r"|submitted (a |the )?(fix|pr|pull request)"
    r"|pr with fix|fix \+ tests|fix and tests follow|tests follow"
    r"|i'?ll take (this|it)|claiming this bounty)", re.I)

AMOUNT_RE = re.compile(r"(?:\$|\u20ac|\u00a3)\s?([0-9][0-9,]{0,7})(?:\.\d{1,2})?")
AMOUNT_RE2 = re.compile(r"\b([0-9][0-9,]{0,7})\s?(?:USD|usd|US dollars)\b")

# titles that are chatter rather than a job
NOISE = re.compile(r"\b(proposal|discussion|rfc|idea|vote|poll|retro|"
                   r"wheel of fortune|airdrop|referral)\b", re.I)

LOG_LINES: list[str] = []


def _fix_console() -> None:
    """This console is cp1252 and chokes on the emoji in a GitHub label such as
    'Bounty' prefixed with a gem. Force UTF-8 with replacement so a stray glyph
    can never kill a scan again."""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass


def log(msg: str = "") -> None:
    print(msg, flush=True)
    LOG_LINES.append(msg)


def get(url: str, tries: int = 3, sleep: float = 5.0):
    """GET json with polite retry; returns None when it is hopeless."""
    for attempt in range(tries):
        try:
            r = requests.get(url, headers=headers(), timeout=30)
        except requests.RequestException as e:
            log(f"    ! network {e} ({attempt + 1}/{tries})")
            time.sleep(sleep)
            continue
        if r.status_code == 200:
            return r.json()
        if r.status_code in (403, 429):  # rate limited
            log(f"    ! rate limited - waiting 65s")
            time.sleep(65)
            continue
        if r.status_code == 404:
            return None
        log(f"    ! http {r.status_code} on {url}")
        time.sleep(sleep)
    return None


def money(text: str) -> int:
    """Biggest plausible dollar figure in a blob of text."""
    best = 0
    for rx in (AMOUNT_RE, AMOUNT_RE2):
        for m in rx.finditer(text or ""):
            try:
                v = int(m.group(1).replace(",", ""))
            except ValueError:
                continue
            if 10 <= v <= 200000:
                best = max(best, v)
    return best


def platform_of(text: str) -> str:
    low = (text or "").lower()
    for p in PLATFORM_HINTS:
        if p in low:
            return p
    return "-"


def issue_num(url: str):
    m = re.search(r"/issues/(\d+)", url or "")
    return int(m.group(1)) if m else None


def repo_of(item: dict) -> str:
    return (item.get("repository_url") or "").split("/repos/")[-1]


def days_ago(iso: str) -> int:
    if not iso:
        return 9999
    try:
        t = datetime.strptime(iso, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        return 9999
    return (datetime.now(timezone.utc) - t).days


def score(amount: int, comments: int, age: int, langs: set) -> float:
    s = amount / (1 + min(comments, 25))
    if langs & GOOD_LANGS:
        s *= 1.6
    if langs & HARD_LANGS:
        s *= 0.5
    if age > 365:
        s *= 0.5
    elif age > 180:
        s *= 0.8
    return round(s, 1)


SMALL_SCOPE = re.compile(r"\b(typo|readme|docs?|documentation|comment|docstring|"
                         r"unit ?test|test coverage|rename|deprecat|lint|"
                         r"example|changelog|translat|i18n|error message)\b", re.I)


def scope_bonus(entry: dict) -> float:
    """A zero-history account wins small, boring, one-file fixes; big feature work goes to
    the 500-PR regulars. So borderline tickets that look small get promoted, not demoted."""
    blob = entry["title"] + " " + entry.get("body_head", "")
    if SMALL_SCOPE.search(blob):
        return 2.0
    return 1.0


OPIRE_HOME = "https://opire.dev/home"
OPIRE_RX = re.compile(
    r"\$([\d,]+)\.\d{2}\s+(.{8,180}?)\s+"
    r"(C\+\+|C#|TypeScript|JavaScript|Python|Rust|Go|Java|PHP|Ruby|Kotlin|Swift|"
    r"Solidity|HTML|CSS|Shell|Dart|Elixir|Haskell|Scala|Zig)\b")


def opire_board(verbose: bool = True) -> list:
    """Opire's front page ships its featured bounties as plain HTML, so this reads the real
    board without any API budget. These are the prizes that are actually funded - Opire pays
    through Stripe once the maintainer confirms the fix - which makes this the cleanest
    source found so far, in contrast to the label:bounty farms."""
    try:
        r = requests.get(OPIRE_HOME, headers={"User-Agent": UA["User-Agent"]}, timeout=30)
    except requests.RequestException as e:
        log(f"  ! opire fetch failed: {e}")
        return []
    if r.status_code != 200:
        log(f"  ! opire http {r.status_code}")
        return []
    text = html_module.unescape(re.sub(r"<[^>]+>", " ", r.text))
    text = re.sub(r"\s+", " ", text)
    out, seen = [], set()
    for m in OPIRE_RX.finditer(text):
        amt, title, lang = int(m.group(1).replace(",", "")), m.group(2).strip(), m.group(3)
        key = (amt, title.lower())
        if key in seen or amt < 10:
            continue
        seen.add(key)
        out.append({"amount": amt, "title": title, "lang": lang,
                    "url": "", "repo": "", "comments": 0, "stars": "-",
                    "trust": "ok", "age_days": 0, "updated_days": 0, "source": "opire",
                    "score": float(amt), "langs": [lang.lower()]})
    if verbose:
        log(f"  opire board: {len(out)} funded bounties found")
    return out


def locate_issues(items: list, verbose: bool = True) -> list:
    """Opire's board gives no link, so find each issue through GitHub search by its exact
    title. Search budget is 10/minute, hence the sleep."""
    found = []
    for it in items:
        q = f'type:issue in:title "{it["title"][:100]}"'
        data = get(f"{SEARCH}?q={requests.utils.quote(q)}&per_page=3", tries=1)
        time.sleep(7)
        hits = (data or {}).get("items") or []
        url = ""
        for h in hits:
            if h.get("html_url"):
                url = h["html_url"]
                break
        if not url:
            if verbose:
                log(f"    ? not found on GitHub: {it['title'][:60]}")
            continue
        it["url"] = url
        it["repo"] = repo_of(hits[0])
        it["number"] = issue_num(url)
        it["comments"] = hits[0].get("comments", 0)
        it["title"] = hits[0].get("title") or it["title"]
        if verbose:
            log(f"    ${it['amount']:<6} {it['repo']:<40} {url}")
        found.append(it)
    return found


# Some tickets advertise money that an outsider can never collect, and the refusal sits in a
# PINNED COMMENT that no scoring heuristic notices. typeorm/typeorm#3357 carried a $1,110
# Opire bounty under: "we are not accepting any PRs from the community for this issue ...
# There are a lot of AI-generated PRs ... All of them will be closed."
NO_PR_RX = re.compile(
    r"(not accepting any PRs?|not accept(ing)? (any )?PRs? from|"
    r"do not (submit|open) (a )?PR|no community PRs|"
    r"we (will|would like to) implement (this|it) ourselves|"
    r"all of them will be closed|PRs will be closed|"
    r"PRs? (from the community )?(are|is) not accepted)", re.I)


_REPO_CACHE: dict = {}


def lookup_repo(repo: str) -> dict:
    """Stars / forks / owner type / last push for one repo, cached. Uses the *search*
    endpoint (30/min with a token) so it never touches the core budget."""
    if repo in _REPO_CACHE:
        return _REPO_CACHE[repo]
    data = get("https://api.github.com/search/repositories?q="
               + requests.utils.quote(f"repo:{repo}"), tries=1)
    items = (data or {}).get("items") if isinstance(data, dict) else None
    info = {}
    if items:
        it = items[0]
        info = {"stars": it.get("stargazers_count", 0),
                "forks": it.get("forks_count", 0),
                "owner_type": (it.get("owner") or {}).get("type", "?"),
                "pushed_days": days_ago(it.get("pushed_at", ""))}
    _REPO_CACHE[repo] = info
    time.sleep(0.5)
    return info


def farm_by_volume(rows: list, min_count: int = 5, min_amount: int = 500) -> int:
    """A repo that posts many large 'bounties' is usually a farm - but not always.

    ClankerNation/OpenAgents is the farm case: 43 tickets of $500+, all 125 days old, 13
    stars, no license, its own bot "claiming" them. Tenstorrent is the counter-case: 7
    bounties at once, but a real chip company with 1,683 stars running a real program. So
    volume alone is not proof - the star check decides, and with a token it costs a couple
    of search calls.
    """
    per_repo: dict = {}
    for r in rows:
        if r["amount"] >= min_amount:
            per_repo[r["repo"]] = per_repo.get(r["repo"], 0) + 1
    flagged = 0
    for repo, n in per_repo.items():
        if n < min_count:
            continue
        info = lookup_repo(repo)
        stars = info.get("stars")
        if stars is not None and stars >= 100:
            log(f"    = {repo}: {n} bounties but {stars} stars - a real bounty PROGRAM, kept")
            continue
        for r in rows:
            if r["repo"] == repo:
                if r["trust"] != "bait":
                    flagged += 1
                r["trust"] = "bait"
                r["farm_volume"] = n
                r["score"] = round(r["score"] * 0.05, 2)
        log(f"    ! {repo}: {n} bounties and only {stars} stars - treated as a farm")
    return flagged


# Some tickets are closed for business in their LABELS - which the search response gives us
# for free, so this costs nothing. aolabsai/ao_pyth#10 carried "$300 / good first issue" and
# also "PAUSED - NOT accepting new contributors", with two AI agents already waiting on an
# answer that never came. That label is the whole story and no amount of comment-counting
# would have shown it.
BLOCKED_LABEL_RX = re.compile(
    r"(paused|not accepting|not open to|on hold|closed to (new )?contributors|"
    r"do not work|don'?t work on|wontfix|won'?t fix|stale|blocked|needs triage|"
    r"no longer|deprecated|abandoned|looking for maintainer)", re.I)

# labels that genuinely help a zero-history account
FRIENDLY_LABEL_RX = re.compile(r"(good first issue|help wanted|easy|beginner|starter)", re.I)


def label_verdict(entry: dict) -> str:
    """blocked / friendly / - from the labels alone, no API call."""
    joined = " ".join(entry.get("labels", []))
    if BLOCKED_LABEL_RX.search(joined):
        return "blocked"
    if FRIENDLY_LABEL_RX.search(joined):
        return "friendly"
    return "-"


# Two more traps, both found by reading tickets the scorer had ranked highly:
#   OmniBlocks/monorepo#795 - "$500 Reverse bounty ... Pay me $500 ... the bounty is negative"
#     (a joke aimed at stopping bounty spam - the scanner read the $500 and ranked it first)
#   attogram/THE-ERROR-IS-THE-MESSAGE#79 - "$100" on a bounty that had already finished:
#     "4-hour window ... 30 submissions received", with a comparison matrix of 7 PRs.
NEGATIVE_RX = re.compile(
    r"(bounty is negative|negative bounty|anti[- ]bounty|pay me \$|pay me [0-9]|"
    r"stop spamming|this is a joke|not a real bounty|silly bounty)", re.I)
CLOSED_WINDOW_RX = re.compile(
    r"(submissions (are )?(now )?closed|entries? (are )?closed|window (is )?closed|"
    r"[0-9]+ submissions received|bounty (has been|was) (awarded|paid|won|claimed)|"
    r"winner (has been )?(chosen|selected)|review (of )?submissions)", re.I)


def junk_verdict(entry: dict) -> str:
    """joke / finished / - from the ticket text. Free: no extra request."""
    blob = (entry.get("body_head") or "") + " " + entry.get("title", "")
    if NEGATIVE_RX.search(blob):
        return "joke"
    if CLOSED_WINDOW_RX.search(blob):
        return "finished"
    return "-"


def guess_langs(labels: set, blob: str) -> set:
    """Languages from the labels plus loose keyword hits in the ticket text."""
    langs = set(labels)
    low = blob.lower()
    for name, rx in LANG_WORDS.items():
        if re.search(rx, low):
            langs.add(name)
    return langs


def trust_tag(entry: dict) -> str:
    """bait / crowded / ok - decided without a single extra API call."""
    if FARM_REPO.search(entry["repo"]) or FARM_TITLE.search(entry["title"]):
        return "bait"
    if entry["comments"] >= CROWDED_COMMENTS:
        return "crowded"
    return "ok"


def trust_penalty(tag: str) -> float:
    return {"bait": 0.10, "crowded": 0.35}.get(tag, 1.0)


def repo_trust(rows: list, limit: int) -> None:
    """Real-project check for the shortlist: stars, age, last push, owner type.
    Uses the *search* API (10/min), so it costs nothing against the 60/hour core
    limit, and sleeps 7s per call. A failure just leaves the row untagged."""
    done = 0
    for r in rows[:limit]:
        if done >= limit:
            break
        info = lookup_repo(r["repo"])
        done += 1
        if info:
            it = info
            r["stars"] = it.get("stars", 0)
            r["owner_type"] = it.get("owner_type", "?")
            r["pushed_days"] = it.get("pushed_days", 9999)
            if r["stars"] >= 100:
                r["score"] = round(r["score"] * 1.5, 1)
            elif r["stars"] <= 2:
                r["score"] = round(r["score"] * 0.3, 1)
            # the farm signature measured on ClankerNation/OpenAgents: 13 stars but 120
            # forks and 201 open "bounty" issues - more forks than stars means people are
            # forking to claim, not to use. A real repo is the other way round.
            forks = it.get("forks", 0)
            r["forks"] = forks
            if r["stars"] < 50 and forks > r["stars"] * 2:
                r["trust"] = "bait"
                r["score"] = round(r["score"] * 0.05, 2)
                log(f"    ! {r['repo']} looks like a farm: {r['stars']} stars, {forks} forks")
            if r.get("pushed_days", 9999) > 400:
                r["score"] = round(r["score"] * 0.7, 1)
        time.sleep(7)
    log(f"    (checked {done} repos for stars / liveness)")


# A bounty that needs a specific accelerator card is invisible-until-too-late for this
# laptop-only operation. Tenstorrent's tickets are real and funded, but both survivors of
# the first scan demanded Blackhole / Wormhole silicon and were already "PR Submitted".
HARDWARE_RX = re.compile(
    r"(blackhole\s+p?\d{3}|wormhole\s+(card|single[- ]device|n\d{3})"
    r"|requires? (an? )?(gpu|accelerator|card|device)"
    r"|nvidia\s+(a100|h100|rtx)|cuda device)", re.I)


def html_signals(url: str) -> dict:
    """Read the public issue PAGE (not the API) and pull out the signals that matter:
    linked pull requests, the Bounty Program Status project field, and claim phrases.
    Costs no API budget at all, which matters because core is only 60/hour here."""
    try:
        r = requests.get(url, headers={"User-Agent": UA["User-Agent"]}, timeout=30)
        if r.status_code != 200:
            return {}
        raw = r.text
    except requests.RequestException:
        return {}
    text = html_module.unescape(re.sub(r"<[^>]+>", " ", raw))
    text = re.sub(r"\s+", " ", text)
    prs = sorted(set(re.findall(r"/[\w.\-]+/[\w.\-]+/pull/\d+", raw)))
    m = re.search(r"Bounty Program Status\s{1,4}([A-Za-z ]{3,30}?)\s*(?:Milestone|Labels|"
                  r"Relationships|Project|Show more|\u00b7|$)", text)
    status = (m.group(1).strip() if m else "")
    if "PR Submitted" in text and "PR Submitted" not in status:
        status = (status + " PR Submitted").strip()
    return {"prs": prs[:5], "status": status, "text": text}


def check_claims(rows: list, limit: int) -> int:
    """Mark which shortlisted tickets already have somebody's fix on the way. Reads the
    public issue page rather than the API, so it does not consume the 60/hour core
    budget - only be polite about the request rate."""
    done = 0
    for r in rows:
        if done >= limit:
            break
        if r["trust"] == "bait":
            continue
        sig = html_signals(r["url"])
        done += 1
        if not sig:
            continue
        text = sig["text"]
        claimers = sorted({m for m in re.findall(r"@?([A-Za-z0-9_\-]{3,30}) posted", text)}
                          | {login for login in
                             re.findall(r"\[([A-Za-z0-9_\-]{3,30}) @", text)})
        strong = STRONG_CLAIM_RX.findall(text)
        r["claim_prs"] = sig["prs"]
        r["bounty_status"] = sig["status"]
        r["claimed"] = (bool(sig["prs"])
                        or "PR Submitted" in sig["status"]
                        or len(strong) >= 1)
        r["claim_evidence"] = sorted({s for s in strong if s})[:3]
        r["claimers"] = claimers[:6]
        if NO_PR_RX.search(text):
            r["no_prs"] = True
            r["score"] = round(r["score"] * 0.02, 2)
        if HARDWARE_RX.search(text):
            r["needs_hardware"] = True
        if r["claimed"]:
            r["score"] = round(r["score"] * 0.05, 2)
        time.sleep(1.0)
    log(f"    (claim check via html: {done} tickets read)")
    return done


def enrich(rows: list, limit: int) -> None:
    """Fill in the real repo language for the shortlist only, and never blow the
    60-requests/hour core limit. A 403 here is survivable: we keep the guess."""
    spent = 0
    for r in rows[:limit]:
        if spent >= ENRICH_CAP:
            log(f"    (enrich stopped at the {ENRICH_CAP} lookup cap)")
            break
        info = get(REPO.format(repo=r["repo"]), tries=1)
        spent += 1
        if info and info.get("language"):
            r["langs"] = sorted(set(r["langs"]) | {info["language"].lower()})
            r["score"] = score(r["amount"], r["comments"], r["age_days"], set(r["langs"]))
        time.sleep(0.3)
    log(f"    (enriched {spent} repos with their real language)")


def collect(min_amount: int, core_budget: int = 0, trust_budget: int = 0,
            claims_budget: int = 0, pages: int = 1) -> list:
    seen = {}
    per_page = 100 if TOKEN else 50

    for name, q in QUERIES:
        for page in range(1, max(1, pages) + 1):
            log(f"[query] {name} p{page}: {q}")
            data = get(f"{SEARCH}?q={requests.utils.quote(q)}&per_page={per_page}&page={page}"
                       f"&sort=updated")
            if not data:
                log("        (no data)")
                break
            items = data.get("items", [])
            log(f"        total_count={data.get('total_count')}  fetched={len(items)}")
            if not items:
                break
            for it in items:
                if it.get("pull_request"):
                    continue
                url = it.get("html_url", "")
                if url in seen:
                    continue
                repo = repo_of(it)
                body = it.get("body") or ""
                title = it.get("title") or ""
                if NOISE.search(title):
                    continue
                amt = money(title) or money(body)
                if amt < min_amount:
                    continue
                labels = {l["name"].lower() for l in it.get("labels", [])}
                langs = guess_langs(labels, title + " " + body[:600] + " " + repo)
                age = days_ago(it.get("created_at", ""))
                seen[url] = {
                    "title": title,
                    "url": url,
                    "repo": repo,
                    "number": issue_num(url),
                    "amount": amt,
                    "comments": it.get("comments", 0),
                    "age_days": age,
                    "updated_days": days_ago(it.get("updated_at", "")),
                    "labels": sorted(labels),
                    "langs": sorted(langs),
                    "body_head": body[:600],
                    "platform": platform_of(body),
                    "score": score(amt, it.get("comments", 0), age, langs),
                    "via": name,
                }
            time.sleep(2.2 if TOKEN else 7)
    for e in seen.values():
        e["trust"] = trust_tag(e)
        e["verdict"] = label_verdict(e)
        if e["verdict"] == "blocked":
            e["trust"] = "bait"          # not a farm, but just as unworkable
            e["blocked_label"] = True
        e["junk"] = junk_verdict(e)
        if e["junk"] != "-":
            e["trust"] = "bait"
        e["score"] = round(e["score"] * trust_penalty(e["trust"]) * scope_bonus(e), 1)
        if e["verdict"] == "friendly":
            e["score"] = round(e["score"] * 1.4, 1)
    farm_by_volume(list(seen.values()))
    rows = sorted(seen.values(), key=lambda d: -d["score"])
    if trust_budget > 0:
        repo_trust(rows, trust_budget)
    if claims_budget > 0:
        check_claims(rows, claims_budget)
        rows = sorted(rows, key=lambda d: -d["score"])
    if core_budget > 0:
        enrich(rows, core_budget)
    else:
        log("    (skipping repo-language lookups: no core budget - search-only scan)")
    return sorted(rows, key=lambda d: -d["score"])


def report(rows: list) -> str:
    out = []
    out.append("OPEN GITHUB BOUNTIES - ranked by money per rival")
    out.append(f"generated {datetime.now().strftime('%Y-%m-%d %H:%M')}  ({len(rows)} candidates)")
    out.append("score = dollars / (1 + comments), x1.6 when the language is one we do well,")
    out.append("        x0.5 for C/C++/Rust/Go, x0.5 when the ticket is over a year old,")
    out.append("        x1.5 if the repo has 100+ stars, x0.3 if it has none,")
    out.append("        x2.0 when the ticket looks small (docs/typo/tests/rename),")
    out.append("        x0.10 for bait-farm repos, x0.05 once a fix PR is already up")
    out.append("")
    out.append("tr = bait (aggregator/bot farm: do not touch) | crowd (bot swarm) | ok")
    out.append("")
    out.append(f"{'#':>3} {'$':>7} {'scr':>7} {'tr':<6} {'star':>5} {'cmmt':>5} {'age':>5} "
               f"{'lang':<12} title")
    out.append("-" * 122)
    for i, r in enumerate(rows[:60], 1):
        lang = ",".join(r["langs"])[:12]
        star = r.get("stars", "-")
        out.append(f"{i:>3} {r['amount']:>7} {r['score']:>7} {r['trust']:<6} {str(star):>5} "
                   f"{r['comments']:>5} {r['age_days']:>5} {lang:<12} {r['title'][:46]}")
        out.append(f"      {r['url']}")
    out.append("")
    out.append("REAL PROJECTS ONLY - passes the bait check (this is the work list)")
    out.append("-" * 122)
    real = [r for r in rows if r["trust"] == "ok" and r["updated_days"] <= 120
            and not r.get("claimed") and not r.get("no_prs") and not r.get("needs_hardware")]
    for r in real[:20]:
        star = r.get("stars", "-")
        out.append(f"  ${r['amount']:<6} {str(star):>6} star {r['comments']:>3} cmt  "
                   f"{r['age_days']:>4}d  {r['title'][:44]}")
        out.append(f"      {r['url']}")
    if not real:
        out.append("  (nothing passed - the market is farm-heavy right now, rescan later)")
    out.append("")
    out.append("ALREADY CLAIMED - somebody has the fix PR up; do not waste a day here")
    out.append("-" * 122)
    claimed = [r for r in rows if r.get("claimed")]
    for r in claimed[:12]:
        who = (",".join(r.get("claimers", [])) or "-")[:26]
        st = r.get("bounty_status") or ""
        hw = " NEEDS-HW" if r.get("needs_hardware") else ""
        out.append(f"  ${r['amount']:<6} {st:<14}{hw:<9} {who:<26} {r['url']}")
    if not claimed:
        out.append("  (none seen - run with --claims N to check)")
    out.append("")
    out.append("JUNK - a joke ticket or a bounty that already finished (why it was ranked high)")
    out.append("-" * 122)
    junk = [r for r in rows if r.get("junk") and r["junk"] != "-"]
    for r in junk[:10]:
        out.append(f"  ${r['amount']:<6} {r['junk']:<9} {r['title'][:52]}")
        out.append(f"      {r['url']}")
    if not junk:
        out.append("  (none seen)")
    out.append("")
    out.append("BLOCKED BY ITS OWN LABELS - the repo says do not work on this (free to detect)")
    out.append("-" * 122)
    blocked = [r for r in rows if r.get("blocked_label")]
    for r in blocked[:10]:
        lab = ",".join(r.get("labels", []))[:44]
        out.append(f"  ${r['amount']:<6} {lab:<46} {r['url']}")
    if not blocked:
        out.append("  (none seen)")
    out.append("")
    out.append("OPIRE FUNDED BOARD - real money, still listed by Opire (claim state noted)")
    out.append("-" * 122)
    ob = [r for r in rows if r.get("source") == "opire"]
    for r in sorted(ob, key=lambda d: -d["amount"]):
        state = ("claim PR exists" if r.get("claimed") else "looks free")
        if r.get("no_prs"):
            state = "MAINTAINER REFUSES COMMUNITY PRs"
        if r.get("needs_hardware"):
            state += " + needs hardware"
        out.append(f"  ${r['amount']:<6} {state:<36} {r['repo']:<28} {r['url']}")
    if not ob:
        out.append("  (run with --opire to read Opire's own board)")
    out.append("")
    out.append("NOT WINNABLE - the maintainer refuses community PRs (the money is bait here)")
    out.append("-" * 122)
    nopr = [r for r in rows if r.get("no_prs")]
    for r in nopr[:10]:
        out.append(f"  ${r['amount']:<6} {r['url']}")
    if not nopr:
        out.append("  (none seen)")
    out.append("")
    out.append("FIRST WINS - small scope, unclaimed, pays, and proves the account is real")
    out.append("-" * 122)
    first = [r for r in rows if r["trust"] == "ok" and not r.get("claimed")
             and not r.get("needs_hardware") and not r.get("no_prs")
             and SMALL_SCOPE.search(r["title"] + " " + r.get("body_head", ""))]
    for r in first[:15]:
        out.append(f"  ${r['amount']:<6} {r['comments']:>3} cmt  {r['age_days']:>4}d  {r['title'][:48]}")
        out.append(f"      {r['url']}")
    if not first:
        out.append("  (none in this scan - widen with --min 10, or rescan later)")
    out.append("")
    out.append("QUICK WINS - $20..$300, few rivals, still fresh, not bait (best first money)")
    out.append("-" * 122)
    quick = [r for r in rows if 20 <= r["amount"] <= 300 and r["comments"] <= 4
             and r["updated_days"] <= 90 and r["trust"] == "ok"
             and not r.get("claimed")]
    for r in quick[:25]:
        out.append(f"  ${r['amount']:<6} {r['comments']:>2} cmt  {r['age_days']:>4}d  {r['url']}")
    if not quick:
        out.append("  (none matched - loosen with --min 20)")
    out.append("")
    out.append("BIGGEST POT (unfiltered - check tr before believing it)")
    out.append("-" * 122)
    for r in sorted(rows, key=lambda d: -d["amount"])[:15]:
        langs = ",".join(r["langs"]) or "-"
        out.append(f"  ${r['amount']:<7} {r['trust']:<6} {r['comments']:>4} cmt  "
                   f"{langs[:14]:<14} {r['url']}")
    return "\n".join(out)


def detail(url: str) -> None:
    """Print the full ticket plus recent comments, so a fix can be planned."""
    m = re.search(r"github\.com/([^/]+/[^/]+?)/issues/(\d+)", url)
    if not m:
        log("not a GitHub issue url")
        return
    repo, num = m.group(1), m.group(2)
    it = get(ISSUE.format(repo=repo, num=num))
    if not it:
        log("issue not found / private")
        return
    log(f"# {it['title']}")
    log(f"{it['html_url']}   state={it['state']}  comments={it['comments']}  "
        f"labels={[l['name'] for l in it['labels']]}")
    log(f"created {it['created_at']}   updated {it['updated_at']}")
    log("--- body ---")
    log((it.get("body") or "")[:4000])
    cs = get(COMMENTS.format(repo=repo, num=num) + "?per_page=30")
    if cs:
        log(f"--- last {min(len(cs), 12)} of {len(cs)} comments ---")
        for c in cs[-12:]:
            log(f"[{c['user']['login']} @ {c['created_at']}] {(c.get('body') or '')[:600]}")
    blob = (it.get("title") or "") + (it.get("body") or "")
    log(f"--> money detected in ticket: ${money(blob)}")


def whoami() -> int:
    """Prove the token in Money\\github_token.txt is live, and show what it unlocked.
    Prints only a masked form of the token - never the whole thing."""
    log(f"token file : {TOKEN_FILE}")
    log(f"exists     : {os.path.exists(TOKEN_FILE)}")
    log(f"token      : {mask(TOKEN)}")
    if not TOKEN:
        log("")
        log("NO TOKEN YET - that is why every scan was throttled to 60 core calls/hour.")
        log("Create one as SETUP.md step 2 describes, save it in the file above, run --whoami again.")
        return 1
    me = get("https://api.github.com/user", tries=1)
    lim = get("https://api.github.com/rate_limit", tries=1)
    if isinstance(me, dict) and me.get("login"):
        log(f"signed in  : {me['login']}  (type {me.get('type')})")
    else:
        log("signed in  : FAILED - the token is wrong, expired, or has no access")
    if isinstance(lim, dict):
        res = lim.get("resources", {})
        for key in ("core", "search"):
            k = res.get(key, {})
            log(f"limit {key:<7}: {k.get('remaining')} of {k.get('limit')} left this window")
    return 0


def main() -> int:
    global TOKEN
    _fix_console()
    here = os.path.dirname(os.path.abspath(__file__))
    ap = argparse.ArgumentParser()
    ap.add_argument("--whoami", action="store_true",
                    help="verify the GitHub token and show the rate limits it unlocked")
    ap.add_argument("--min", type=int, default=25,
                    help="ignore bounties under this many dollars")
    ap.add_argument("--core", type=int, default=0,
                    help="how many core-API calls the scan may spend on repo languages "
                         "(core limit is 60/hour unauthenticated, and --detail needs some)")
    ap.add_argument("--trust", type=int, default=0,
                    help="how many shortlist repos to check for stars (uses the search "
                         "limit, 10/min: leave at 0 unless a token is in place)")
    ap.add_argument("--claims", type=int, default=0,
                    help="how many shortlist tickets to read comments for, to see whether "
                         "somebody already filed the fix PR (1 core call each)")
    ap.add_argument("--pages", type=int, default=1,
                    help="pages of 100 results per query (a token makes 2-3 affordable)")
    ap.add_argument("--opire", action="store_true",
                    help="also read Opire's own funded board and locate those issues on "
                         "GitHub (no API budget for the board itself)")
    ap.add_argument("--out", default=os.path.join(here, "bounty_scan.txt"))
    ap.add_argument("--json", dest="json_out", default=None)
    ap.add_argument("--detail", default=None, help="dump one issue and its comments")
    a = ap.parse_args()

    TOKEN = load_token()
    log(f"[auth] github token: {mask(TOKEN)}"
        + ("" if TOKEN else "  (unauthenticated - 60 core calls/hour)"))

    if a.whoami:
        return whoami()

    if a.detail:
        detail(a.detail)
        return 0

    rows = collect(a.min, a.core, a.trust, 0, a.pages)
    if a.opire:
        log("[opire] reading the funded board ...")
        board = locate_issues(opire_board())
        have = {r["url"] for r in rows}
        for b in board:
            if b["url"] and b["url"] not in have:
                rows.append(b)
                have.add(b["url"])
        rows = sorted(rows, key=lambda d: -d["score"])
    if a.claims:
        # after the merge, so the Opire rows get the same claim / hardware / no-PR checks
        check_claims(rows, a.claims)
        rows = sorted(rows, key=lambda d: -d["score"])
    text = report(rows)
    log(text)
    log(f"bounty_scan.py: {len(rows)} bounties at or above ${a.min}")
    with open(a.out, "w", encoding="utf-8") as f:
        f.write(text + "\n")
    log(f"wrote {a.out}")
    if a.json_out:
        with open(a.json_out, "w", encoding="utf-8") as f:
            json.dump(rows, f, indent=1)
        log(f"wrote {a.json_out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
