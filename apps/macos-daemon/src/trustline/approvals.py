"""SQLite cache of successful page reviews, separate from trusted domains."""

from contextlib import closing
import hashlib
import math
from pathlib import Path
import sqlite3
import time

from .inspection import normalize_host, normalize_origin
from .reviews import request_key, review_url


REVIEW_POLICY_VERSION = 1


class ReviewedPages:
    def __init__(self, path: Path, *, ttl=86400, clock=None, max_entries=10000):
        if not math.isfinite(ttl) or ttl <= 0 or max_entries < 1:
            raise ValueError("Invalid page approval cache limits")
        self.path, self.ttl = path, ttl
        self.clock, self.max_entries = clock or time.time, max_entries
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        with closing(sqlite3.connect(path)) as db, db:
            db.execute("""CREATE TABLE IF NOT EXISTS scanned_pages (
                url_hash TEXT PRIMARY KEY,
                origin TEXT NOT NULL,
                hostname TEXT NOT NULL,
                approved_at REAL NOT NULL,
                expires_at REAL NOT NULL,
                policy_version INTEGER NOT NULL
            )""")
            db.execute("CREATE INDEX IF NOT EXISTS scanned_pages_origin ON scanned_pages(origin)")
        path.chmod(0o600)

    @staticmethod
    def identity(url):
        target, private_parts = review_url(url)
        if private_parts:
            raise ValueError("Only fully reviewed URLs can be saved")
        origin, host = normalize_origin(target)
        digest = hashlib.sha256(request_key(target).encode("utf-8")).hexdigest()
        return digest, origin, host

    def approve(self, url):
        digest, origin, host = self.identity(url)
        now = self.clock()
        with closing(sqlite3.connect(self.path)) as db, db:
            db.execute("DELETE FROM scanned_pages WHERE expires_at <= ? OR policy_version != ?",
                       (now, REVIEW_POLICY_VERSION))
            db.execute("""INSERT INTO scanned_pages VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(url_hash) DO UPDATE SET origin=excluded.origin,
                hostname=excluded.hostname, approved_at=excluded.approved_at,
                expires_at=excluded.expires_at, policy_version=excluded.policy_version""",
                (digest, origin, host, now, now + self.ttl, REVIEW_POLICY_VERSION))
            db.execute("""DELETE FROM scanned_pages WHERE url_hash IN (
                SELECT url_hash FROM scanned_pages ORDER BY approved_at DESC, url_hash
                LIMIT -1 OFFSET ?
            )""", (self.max_entries,))

    def contains(self, url):
        try:
            digest, _, _ = self.identity(url)
        except ValueError:
            return False
        now = self.clock()
        with closing(sqlite3.connect(self.path)) as db:
            return db.execute("""SELECT 1 FROM scanned_pages WHERE url_hash = ?
                AND approved_at <= ? AND expires_at > ? AND policy_version = ?""",
                (digest, now, now, REVIEW_POLICY_VERSION)).fetchone() is not None

    def allows_assets(self, origin):
        now = self.clock()
        with closing(sqlite3.connect(self.path)) as db:
            return db.execute("""SELECT 1 FROM scanned_pages WHERE origin = ?
                AND approved_at <= ? AND expires_at > ? AND policy_version = ? LIMIT 1""",
                (origin, now, now, REVIEW_POLICY_VERSION)).fetchone() is not None

    def remove(self, url):
        try:
            digest, _, _ = self.identity(url)
        except ValueError:
            return
        with closing(sqlite3.connect(self.path)) as db, db:
            db.execute("DELETE FROM scanned_pages WHERE url_hash = ?", (digest,))

    def clear_domain(self, domain):
        host = normalize_host(domain)
        with closing(sqlite3.connect(self.path)) as db, db:
            db.execute("DELETE FROM scanned_pages WHERE hostname = ? OR hostname LIKE ?",
                       (host, "%." + host))
