"""Bounded remote jobs with optional persistent, expiring page approvals."""

import asyncio
from collections import OrderedDict
from dataclasses import dataclass, field
import secrets
import sqlite3
import time
from urllib.parse import urlsplit

from .inspection import is_local_host, normalize_origin


def review_url(value):
    origin, host = normalize_origin(value)
    parts = urlsplit(value)
    if parts.username is not None or parts.password is not None or is_local_host(host):
        raise ValueError("This destination cannot be reviewed remotely")
    # Queries and fragments can contain account/session tokens. Do not send them.
    return origin + (parts.path or "/"), bool(parts.query or parts.fragment)


def request_key(value):
    origin, _ = normalize_origin(value)
    parts = urlsplit(value)
    if parts.username is not None or parts.password is not None:
        raise ValueError("URLs containing credentials cannot be reviewed")
    if parts.fragment:
        raise ValueError("URL fragments cannot be reviewed by the proxy")
    return origin + (parts.path or "/") + ("?" + parts.query if parts.query else "")


@dataclass
class Review:
    token: str
    url: str
    created: float
    status: str = "pending"
    reason: str = "Checking the website in an isolated cloud browser."
    evidence: list[str] = field(default_factory=list)
    task: asyncio.Task | None = None


class ReviewManager:
    def __init__(self, reviewer=None, *, approvals=None, timeout=90, ttl=120, max_pending=8, max_records=128):
        self.reviewer = reviewer
        self.approvals = approvals
        self.timeout, self.ttl = timeout, ttl
        self.max_pending, self.max_records = max_pending, max_records
        self.records = OrderedDict()
        self.by_url = {}
        self.resource_grants = {}
        self.worker = asyncio.Semaphore(1)

    def prune(self):
        now = time.monotonic()
        for token, row in list(self.records.items()):
            if now - row.created > self.ttl:
                if row.task and not row.task.done():
                    row.task.cancel()
                self.records.pop(token)
                if self.by_url.get(row.url) == token:
                    self.by_url.pop(row.url, None)
        self.resource_grants = {key: expiry for key, expiry in self.resource_grants.items()
                                if expiry > now}

    def allowed(self, url, kind, method):
        self.prune()
        if method not in {"GET", "HEAD"}:
            return False
        if self.approvals is not None:
            try:
                if kind == "main_frame":
                    return self.approvals.contains(url)
                if kind == "sub_frame":
                    return False
                origin, _ = normalize_origin(url)
                return self.approvals.allows_assets(origin)
            except (sqlite3.Error, OSError):
                # A failed cache read cannot grant permission to forward.
                return False
        token = self.by_url.get(request_key(url))
        row = self.records.get(token)
        if kind == "main_frame":
            return bool(row and row.status == "allow")
        # A reviewed page can load its first-party assets, but cannot approve a
        # different page/iframe on the same origin. Third parties remain separate.
        if kind == "sub_frame":
            return False
        origin, _ = normalize_origin(url)
        return origin in self.resource_grants

    def start(self, url, method="GET", *, force=False):
        self.prune()
        key = request_key(url)
        existing = self.records.get(self.by_url.get(key))
        retry_token = None
        if force and existing and existing.status != "pending":
            # Preserve checking-page capabilities when an explicit scan retries a
            # completed job. Reloading that page must still find the new result.
            retry_token = existing.token
            self.records.pop(existing.token)
            self.by_url.pop(key, None)
            existing = None
        if existing and existing.status == "allow" and not self.allowed(url, "main_frame", method):
            self.records.pop(existing.token)
            self.by_url.pop(key, None)
            existing = None
        if existing:
            return existing
        if len(self.records) >= self.max_records:
            return None
        row = Review(retry_token or secrets.token_urlsafe(24), key, time.monotonic())
        self.records[row.token] = row
        self.by_url[key] = row.token
        if self.approvals is not None:
            try:
                # An explicit new scan invalidates an older approval immediately.
                self.approvals.remove(url)
            except (sqlite3.Error, OSError):
                row.status, row.reason = "inconclusive", "The approval database is unavailable. The website remains blocked."
                return row
        if method != "GET":
            row.status, row.reason = "inconclusive", "Only GET page navigations can be reviewed. No form data was sent."
        elif self.reviewer is None:
            row.status, row.reason = "inconclusive", "Connect your ChatGPT plan and Cloudflare Browser Run to inspect this website."
        elif sum(item.status == "pending" for item in self.records.values()) > self.max_pending:
            row.status, row.reason = "inconclusive", "The inspection queue is full. The website remains blocked."
        else:
            row.task = asyncio.create_task(self._run(row))
        return row

    async def _run(self, row):
        try:
            async with asyncio.timeout(self.timeout):
                async with self.worker:
                    target, has_private_parts = review_url(row.url)
                    result = await self.reviewer.review(target)
            status = result.get("verdict")
            if status not in {"allow", "block", "inconclusive"}:
                raise ValueError("Invalid review verdict")
            reason = result.get("reason", "")
            evidence = result.get("evidence", [])
            if not isinstance(reason, str) or not isinstance(evidence, list) or not all(isinstance(v, str) for v in evidence):
                raise ValueError("Invalid review result")
            row.status, row.reason = status, reason[:600]
            row.evidence = [item[:400] for item in evidence[:6]]
            if status == "allow" and has_private_parts:
                row.status = "inconclusive"
                row.reason = "URL parameters were withheld for privacy. A check of the page without them cannot approve this link."
            if row.status == "allow":
                if self.approvals is not None:
                    self.approvals.approve(row.url)
                origin, _ = normalize_origin(row.url)
                self.resource_grants[origin] = row.created + self.ttl
            elif row.status == "block":
                print("suspicious website", flush=True)
        except asyncio.CancelledError:
            raise
        except Exception:
            # Never expose SDK exceptions, which may contain tokens or URLs.
            row.status, row.reason = "inconclusive", "The remote check could not finish. The website remains blocked."

    def get(self, token):
        self.prune()
        return self.records.get(token)

    def snapshot(self, token):
        row = self.get(token)
        if row is None:
            return None
        return {"status": row.status, "reason": row.reason, "evidence": row.evidence,
                "using_chatgpt_plan": self.reviewer is not None}

    def close(self):
        for row in self.records.values():
            if row.task and not row.task.done():
                row.task.cancel()
