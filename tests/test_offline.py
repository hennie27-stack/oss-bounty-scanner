"""Offline unit tests for bounty_scan.py - no network, no token.

Run:  python -m unittest discover -s tests -v
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import bounty_scan as b  # noqa: E402


class TestMoney(unittest.TestCase):
    def test_dollar_amounts(self):
        self.assertEqual(b.money("[BOUNTY $1,500] fix the thing"), 1500)
        self.assertEqual(b.money("Bounty $200: typo"), 200)
        self.assertEqual(b.money("reward of 3,500 USD"), 3500)
        self.assertEqual(b.money("no money here"), 0)

    def test_ignores_absurd_values(self):
        self.assertEqual(b.money("$9999999999 out of range"), 0)
        self.assertEqual(b.money("$5 too small"), 0)

    def test_picks_the_biggest_plausible(self):
        self.assertEqual(b.money("$100 deposit, $900 bounty"), 900)


class TestMask(unittest.TestCase):
    def test_never_reveals_the_middle(self):
        # built at runtime so a secret scanner never mistakes the placeholder for a leak
        tok = "github" + "_pat_" + "11ABCDEFGHIJKLMNOP" + "_" + "hunter2hunter2" + "_9999"
        m = b.mask(tok)
        self.assertTrue(m.startswith("github_pat_1"))
        self.assertTrue(m.endswith("9999"))
        self.assertNotIn("secretsecret", m)

    def test_short_token_is_not_echoed(self):
        self.assertEqual(b.mask("abc"), "(short/invalid)")
        self.assertEqual(b.mask(""), "(none)")


class TestBaitDetection(unittest.TestCase):
    def test_named_farms(self):
        for repo in ("x/BountyScout", "SecureBananaLabs/bug-bounty",
                     "z/bounty-plaza", "a/Bounty-Hunters"):
            e = {"repo": repo, "title": "fix something", "comments": 1}
            self.assertEqual(b.trust_tag(e), "bait", repo)

    def test_real_repos_are_not_farms(self):
        e = {"repo": "tenstorrent/tt-metal", "title": "[Bounty $1500] fix x", "comments": 2}
        self.assertEqual(b.trust_tag(e), "ok")

    def test_crowded_is_flagged_but_not_bait(self):
        e = {"repo": "some/repo", "title": "fix x", "comments": 900}
        self.assertEqual(b.trust_tag(e), "crowded")


class TestLabels(unittest.TestCase):
    def test_blocked_label(self):
        e = {"labels": ["enhancement", "good first issue",
                        "paused - not accepting new contributors"]}
        self.assertEqual(b.label_verdict(e), "blocked")

    def test_friendly_label(self):
        self.assertEqual(b.label_verdict({"labels": ["good first issue"]}), "friendly")
        self.assertEqual(b.label_verdict({"labels": ["help wanted"]}), "friendly")

    def test_neutral(self):
        self.assertEqual(b.label_verdict({"labels": ["bug"]}), "-")


class TestJunk(unittest.TestCase):
    def test_joke_antibounty(self):
        e = {"body_head": "Pay me $500 in Solana. *The bounty is negative.", "title": "Reverse bounty"}
        self.assertEqual(b.junk_verdict(e), "joke")

    def test_finished_bounty(self):
        e = {"body_head": "4-hour window, 30 submissions received.", "title": "Bounty review"}
        self.assertEqual(b.junk_verdict(e), "finished")

    def test_normal_ticket(self):
        e = {"body_head": "Fix the crash when the config file is missing.", "title": "bug"}
        self.assertEqual(b.junk_verdict(e), "-")


class TestClaims(unittest.TestCase):
    def test_bare_issue_references_are_not_claims(self):
        # the bug that made every ticket look claimed: "#1234" alone is a passing mention
        self.assertFalse(b.STRONG_CLAIM_RX.search("see #1234 and #5678 for context"))

    def test_strong_signals_are_claims(self):
        for text in ("Fix is up", "Submitted a PR", "PR #4321",
                     "created a pull request", "opened a PR", "pr with fix + tests follows"):
            self.assertTrue(b.STRONG_CLAIM_RX.search(text), text)

    def test_pr_links_are_claims(self):
        self.assertTrue(b.STRONG_CLAIM_RX.search("https://github.com/x/y/pull/12"))


class TestScoring(unittest.TestCase):
    def test_language_weighting(self):
        self.assertGreater(b.score(100, 0, 1, {"python"}), b.score(100, 0, 1, {"c++"}))

    def test_competition_lowers_the_score(self):
        self.assertGreater(b.score(100, 0, 1, {"python"}), b.score(100, 20, 1, {"python"}))

    def test_age_penalty(self):
        self.assertGreater(b.score(100, 0, 10, {"python"}), b.score(100, 0, 900, {"python"}))

    def test_scope_bonus(self):
        small = {"title": "Fix typo in README", "body_head": ""}
        big = {"title": "Rewrite the scheduler", "body_head": ""}
        self.assertGreater(b.scope_bonus(small), b.scope_bonus(big))


class TestUrlHelpers(unittest.TestCase):
    def test_issue_number(self):
        self.assertEqual(b.issue_num("https://github.com/a/b/issues/123"), 123)
        self.assertIsNone(b.issue_num("not a url"))

    def test_repo_of(self):
        item = {"repository_url": "https://api.github.com/repos/typeorm/typeorm"}
        self.assertEqual(b.repo_of(item), "typeorm/typeorm")

    def test_platform_detect(self):
        self.assertEqual(b.platform_of("claim on opire.dev"), "opire")
        self.assertEqual(b.platform_of("nothing here"), "-")

    def test_noise_titles_are_skipped(self):
        self.assertTrue(b.NOISE.search("[Bounty proposal] let's discuss"))
        self.assertTrue(b.NOISE.search("Community poll about bounties"))
        self.assertFalse(b.NOISE.search("[Bounty $200] fix the parser"))


if __name__ == "__main__":
    unittest.main()
