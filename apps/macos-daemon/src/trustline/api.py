"""Loopback API for the Chrome extension, sharing the proxy's review queue."""

import asyncio
import json
import re
from urllib.parse import urlsplit

from tornado.httpserver import HTTPServer
from tornado.web import Application, RequestHandler

from .inspection import Observation
from .reviews import request_key

# Top of the extension's Dangerous zone (scores under 40).
BLOCKED_MAX_SCORE = 39


class ExtensionAPI:
    def __init__(self, proxy):
        self.proxy = proxy
        self.pending = 0

    def target(self, url):
        observation = Observation.parse({"url": url})
        if observation.hostname == "blocked.example.com":
            match = re.fullmatch(r"/_trustline/check/([A-Za-z0-9_-]+)", urlsplit(url).path)
            row = self.proxy.reviews.get(match[1]) if match else None
            if row is None:
                raise ValueError("This TrustLine page has no active website review")
            return row.url
        return url

    async def analyze(self, url, mode):
        target = self.target(url)
        # Capture before waiting for Jev: a proxy job can finish during that wait.
        # A click made while it was pending must consume that result, not rescan.
        existing = None
        if mode == "deep":
            try:
                existing = self.proxy.reviews.records.get(self.proxy.reviews.by_url.get(request_key(target)))
            except ValueError:
                # Verified domains bypass review even when a URL has a fragment.
                pass
        join_pending = existing is not None and existing.status == "pending"
        if self.pending >= 8:
            raise ValueError("The URL inspection queue is full. Try again shortly.")
        self.pending += 1
        try:
            # Use the same single worker/cache as the proxy, never concurrent Jev calls.
            result = await asyncio.get_running_loop().run_in_executor(
                self.proxy.executor, self.proxy.inspector.inspect, {"url": target})
        finally:
            self.pending -= 1
        verified = result.get("reason") == "approved_destination"
        probability = result.get("probability")
        score = 100 if verified else (round((1 - probability) * 100) if probability is not None else None)
        verdict = {"suspicious": "dangerous", "uncertain": "suspicious",
                   "not_flagged": "safe"}.get(result["status"], "suspicious")
        reasons = (["Domain is in the verified website database."] if verified else
                   [f"TrustLine estimates a {probability:.1%} chance this web address is fake or misleading.",
                    "This quick check only looked at the web address, not the page itself."] if probability is not None else
                   [result.get("reason", "TrustLine score unavailable")])
        if result.get("money_site") and not verified:
            reasons.append("This looks like a money or shopping site, so TrustLine checks it more strictly.")
        data = {"verdict": "safe" if verified else verdict, "score": score,
                "verified": verified, "score_source": "verified_database" if verified else "jev",
                "jev_probability": probability, "jev_status": result["status"],
                "reasons": reasons, "target_url": target}
        if mode == "deep" and not verified:
            row = self.proxy.reviews.start(target, force=not join_pending)
            if row is None:
                raise ValueError("The cloud inspection queue is full. Try again shortly.")
            data["review"] = {"token": row.token, **self.proxy.reviews.snapshot(row.token)}
            self.apply_review(data)
        elif not verified:
            # Retain cloud evidence after a successful proxy review automatically
            # returns the browser to its original URL. This starts no new job.
            try:
                row = self.proxy.reviews.get(self.proxy.reviews.by_url.get(request_key(target)))
            except ValueError:
                row = None
            if row and row.status != "pending":
                data["review"] = {"token": row.token, **self.proxy.reviews.snapshot(row.token)}
                self.apply_review(data)
        return data

    @staticmethod
    def apply_review(data):
        review = data["review"]
        if review["status"] != "pending":
            data["verdict"] = {"allow": "safe", "block": "dangerous"}.get(review["status"], "suspicious")
            data["reasons"] = [review["reason"], *review["evidence"]][:6]
            data["score"] = reviewed_score(data["score"], review)
        return data


def reviewed_score(score, review):
    """The lower of the URL and page scores; a blocked page never scores above Dangerous."""
    page = review.get("page_probability")
    if page is not None:
        page_score = round((1 - page) * 100)
        score = page_score if score is None else min(score, page_score)
    if review["status"] == "block" and score is not None:
        score = min(score, BLOCKED_MAX_SCORE)
    return score


class APIHandler(RequestHandler):
    def initialize(self, api):
        self.api = api

    def set_default_headers(self):
        self.set_header("Content-Type", "application/json")
        self.set_header("Cache-Control", "no-store")
        self.set_header("X-Content-Type-Options", "nosniff")

    def prepare(self):
        # Reject website origins and DNS rebinding. No website can spend cloud/model
        # quota or read browsing results through this API. Native CLI clients may
        # omit Origin; Chrome extensions use their generated extension origin.
        if self.request.host_name not in {"127.0.0.1", "localhost"}:
            self.set_status(403)
            self.finish({"error": "Loopback host required"})
            return
        origin = self.request.headers.get("Origin")
        if origin is not None and not re.fullmatch(r"chrome-extension://[a-p]{32}", origin):
            self.set_status(403)
            self.finish({"error": "Only Chrome extensions can access this API"})
            return
        if origin:
            self.set_header("Access-Control-Allow-Origin", origin)
            self.set_header("Vary", "Origin")

    def options(self, *args):
        self.set_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.set_header("Access-Control-Allow-Headers", "Content-Type")
        self.set_status(204)
        self.finish()

    def write_error(self, status_code, **kwargs):
        self.finish({"error": "The daemon request could not complete"})


class HealthHandler(APIHandler):
    def get(self):
        self.finish({"status": "ok", "version": "0.2.0",
                     "cloud_review_configured": self.api.proxy.reviews.reviewer is not None})


class AnalyzeHandler(APIHandler):
    async def post(self):
        if self.request.headers.get("Content-Type", "").split(";", 1)[0].strip().lower() != "application/json":
            self.set_status(415)
            self.finish({"error": "Expected application/json"})
            return
        try:
            body = json.loads(self.request.body)
            if not isinstance(body, dict) or body.get("mode", "quick") not in {"quick", "deep"}:
                raise ValueError("Expected a URL and quick or deep mode")
            result = await self.api.analyze(body.get("url"), body.get("mode", "quick"))
        except (ValueError, TypeError):
            self.set_status(400)
            self.finish({"error": "Invalid URL, unsupported mode, or inspection queue unavailable"})
            return
        except Exception:
            self.set_status(503)
            self.finish({"error": "The inspection service is unavailable"})
            return
        self.finish(result)


class ReviewHandler(APIHandler):
    def get(self, token):
        snapshot = self.api.proxy.reviews.snapshot(token)
        if snapshot is None:
            self.set_status(404)
            self.finish({"error": "This cloud review is unavailable or expired"})
        else:
            self.finish(snapshot)


def application(api):
    return Application([
        (r"/health", HealthHandler, {"api": api}),
        (r"/v1/analyze", AnalyzeHandler, {"api": api}),
        (r"/v1/reviews/([A-Za-z0-9_-]+)", ReviewHandler, {"api": api}),
    ], log_function=lambda handler: None)


def start_api(proxy, port):
    server = HTTPServer(application(ExtensionAPI(proxy)), max_body_size=16384,
                        max_header_size=8192, body_timeout=10, idle_connection_timeout=15)
    server.listen(port, address="127.0.0.1")
    return server
