import io
import contextlib
from contextlib import closing
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest
from unittest.mock import AsyncMock, Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from trustline.approvals import ReviewedPages
from trustline.inspection import ApprovedSites, Inspector
from trustline.proxy import InspectionProxy
from trustline.reviews import ReviewManager
from test_proxy import make_flow


class PersistentApprovalTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "approved.sqlite3"
        self.sites = ApprovedSites(self.path)
        self.clock = Mock(return_value=1000.0)
        self.store = ReviewedPages(self.path, clock=self.clock)
        self.reviewer = Mock(review=AsyncMock(return_value={"verdict": "allow", "reason": "Observed page", "evidence": []}))
        self.manager = ReviewManager(self.reviewer, approvals=self.store)
        self.addCleanup(self.manager.close)

    async def scan(self, url="https://ordinary.example/article"):
        row = self.manager.start(url)
        if row.task:
            await row.task
        return row

    async def test_success_persists_and_restarted_proxy_skips_both_models(self):
        url = "https://ordinary.example/article"
        row = await self.scan(url)
        self.assertEqual(row.status, "allow")
        restarted = ReviewManager(approvals=ReviewedPages(self.path, clock=self.clock))
        self.addCleanup(restarted.close)
        jev = Mock()
        addon = InspectionProxy(Inspector(self.sites, jev), restarted)
        self.addCleanup(addon.done)
        item = make_flow(url)
        await addon.requestheaders(item)
        self.assertIsNone(item.response)
        jev.assess.assert_not_called()
        self.assertTrue(restarted.allowed(url, "main_frame", "HEAD"))
        self.assertTrue(restarted.allowed("https://ordinary.example/app.js", "script", "GET"))
        for target, kind, method in [
            ("https://ordinary.example/other-page", "main_frame", "GET"),
            ("http://ordinary.example/article", "main_frame", "GET"),
            ("https://sub.ordinary.example/article", "main_frame", "GET"),
            (url, "sub_frame", "GET"), (url, "main_frame", "POST"),
        ]:
            self.assertFalse(restarted.allowed(target, kind, method))
        self.assertEqual(self.sites.domains(), ["linkedin.com", "youtube.com"])

    async def test_expired_approval_requires_new_scan_even_with_old_job_in_memory(self):
        url = "https://ordinary.example/article"
        first = await self.scan(url)
        self.clock.return_value += 86401
        self.assertFalse(self.manager.allowed(url, "main_frame", "GET"))
        self.assertFalse(self.manager.allowed("https://ordinary.example/app.js", "script", "GET"))
        second = await self.scan(url)
        self.assertNotEqual(first.token, second.token)
        self.assertEqual(self.reviewer.review.await_count, 2)
        self.assertTrue(self.store.contains(url))

    async def test_only_successful_full_url_reviews_are_saved(self):
        for result in [{"verdict": "block"}, {"verdict": "inconclusive"}, RuntimeError("provider failed"),
                       {"verdict": "allow", "reason": 42}]:
            self.reviewer.review = AsyncMock(side_effect=result) if isinstance(result, Exception) else AsyncMock(return_value=result)
            manager = ReviewManager(self.reviewer, approvals=self.store)
            with contextlib.redirect_stdout(io.StringIO()):
                row = manager.start("https://ordinary.example/" + str(id(result)))
                await row.task
            self.assertFalse(self.store.contains(row.url))
            manager.close()
        self.reviewer.review = AsyncMock(return_value={"verdict": "allow"})
        url = "https://ordinary.example/article?token=private"
        row = await self.scan(url)
        self.assertEqual(row.status, "inconclusive")
        self.assertFalse(self.store.contains(url))
        with self.assertRaises(ValueError):
            await self.scan("https://user:password@ordinary.example/article")
        with self.assertRaises(ValueError):
            await self.scan("https://ordinary.example/article#unreviewed-route")
        self.assertEqual(self.row_count(), 0)

    def row_count(self):
        with closing(sqlite3.connect(self.path)) as db:
            return db.execute("SELECT count(*) FROM scanned_pages").fetchone()[0]

    async def test_forced_rescan_removes_previous_approval_before_checking(self):
        url = "https://ordinary.example/article"
        await self.scan(url)
        rescan = ReviewManager(Mock(review=AsyncMock(return_value={"verdict": "block"})), approvals=self.store)
        self.addCleanup(rescan.close)
        row = rescan.start(url)
        self.assertFalse(self.store.contains(url))
        with contextlib.redirect_stdout(io.StringIO()):
            await row.task
        self.assertEqual(row.status, "block")
        self.assertFalse(self.store.contains(url))

    async def test_database_failures_do_not_approve_page(self):
        with patch.object(self.store, "approve", side_effect=sqlite3.OperationalError("disk full")):
            row = await self.scan()
        self.assertEqual(row.status, "inconclusive")
        self.assertFalse(self.store.contains(row.url))
        with patch.object(self.store, "contains", side_effect=sqlite3.OperationalError("unavailable")):
            self.assertFalse(self.manager.allowed(row.url, "main_frame", "GET"))
        with patch.object(self.store, "remove", side_effect=sqlite3.OperationalError("unavailable")):
            blocked = self.manager.start("https://ordinary.example/different")
        self.assertEqual(blocked.status, "inconclusive")
        self.assertIsNone(blocked.task)

    async def test_database_stores_hash_and_origin_without_page_text_or_full_path(self):
        url = "https://ordinary.example/private-path"
        await self.scan(url)
        with closing(sqlite3.connect(self.path)) as db:
            db.row_factory = sqlite3.Row
            row = dict(db.execute("SELECT * FROM scanned_pages").fetchone())
        self.assertEqual(len(row["url_hash"]), 64)
        self.assertEqual(row["origin"], "https://ordinary.example")
        self.assertNotIn("private-path", str(row))
        self.assertNotIn("Observed page", str(row))
        self.assertEqual(row["expires_at"] - row["approved_at"], 86400)
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)

    async def test_cache_capacity_and_domain_revocation_preserve_trusted_table(self):
        bounded = ReviewedPages(self.path, clock=self.clock, max_entries=2)
        for url in ["https://ordinary.example/old", "https://sub.ordinary.example/new", "https://other.example/"]:
            self.clock.return_value += 1
            bounded.approve(url)
        self.assertEqual(self.row_count(), 2)
        self.assertFalse(bounded.contains("https://ordinary.example/old"))
        bounded.clear_domain("ordinary.example")
        self.assertEqual(self.row_count(), 1)
        self.assertTrue(bounded.contains("https://other.example/"))
        self.assertEqual(self.sites.domains(), ["linkedin.com", "youtube.com"])


if __name__ == "__main__":
    unittest.main()
