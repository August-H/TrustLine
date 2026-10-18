"""Loopback API for the Chrome extension, sharing the proxy's review queue."""

import asyncio
import json
import re
from urllib.parse import urlsplit, urlunsplit

from tornado.httpserver import HTTPServer
from tornado.web import Application, RequestHandler

from .inspection import Observation
from .reviews import request_key

# Top of the extension's Dangerous zone (scores under 40).
BLOCKED_MAX_SCORE = 39
MODES = {"quick", "deep", "navigate"}
# Jev's URL questions are Noul (yes/no) judgments, which carry no `confidence`
# field. TypeSafe's docs put a Noul on the Choice confidence scale as |2p - 1|:
# 0 when yes and no are equally likely, 1 when Jev is certain either way.
#
# Before a page opens (navigate mode):
# - confidence >= NAVIGATION_CONFIDENCE: no cloud check. A confident pass opens;
#   a confident flag goes to the warning page.
# - less confident, but the trust score passes (>= PASSING_SCORE): opens with no
#   cloud check, marked `unsure` so the extension offers a Deep scan.
# - less confident and failing: the loading screen runs the cloud check.
#
# A money site (crypto, banking, investing, payments, loans or shopping) that Jev
# does not recognize as a well-known organization (recognized probability under
# RECOGNIZED_THRESHOLD) always gets the cloud check first, however good its
# address looks. Only a confident "fake" verdict skips straight to the warning.
NAVIGATION_CONFIDENCE = 0.85
PASSING_SCORE = 70
RECOGNIZED_THRESHOLD = 0.8


def jev_confidence(probability):
    return None if probability is None else round(abs(2 * probability - 1), 4)


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
        unrecognized_money = (not verified and result.get("money_site") is True
                              and (result.get("recognized") or 0) < RECOGNIZED_THRESHOLD)
        if unrecognized_money:
            reasons.append("This looks like a money or shopping site TrustLine doesn't recognize, "
                           "so it checks the page itself before it opens.")
        elif result.get("money_site") and not verified:
            reasons.append("This looks like a money or shopping site, so TrustLine checks it more strictly.")
        data = {"verdict": "safe" if verified else verdict, "score": score,
                "verified": verified, "score_source": "verified_database" if verified else "jev",
                "jev_probability": probability, "jev_status": result["status"],
                "jev_confidence": None if verified else jev_confidence(probability),
                "recognized_probability": None if verified else result.get("recognized"),
                "reasons": reasons, "target_url": target}
        confidence = data["jev_confidence"]
        confident = confidence is not None and confidence >= NAVIGATION_CONFIDENCE
        passing = (score is not None and score >= PASSING_SCORE
                   and result["status"] in {"not_flagged", "uncertain"})
        confident_flag = confident and result["status"] == "suspicious"
        needs_cloud = not verified and ((not passing and not confident)
                                        or (unrecognized_money and not confident_flag))
        if mode == "deep" and not verified:
            row = self.proxy.reviews.start(target, force=not join_pending)
            if row is None:
                raise ValueError("The cloud inspection queue is full. Try again shortly.")
            data["review"] = {"token": row.token, **self.proxy.reviews.snapshot(row.token)}
            self.apply_review(data)
        elif mode == "navigate" and needs_cloud:
            review = self.navigation_review(target)
            if review is not None:
                data["review"] = review
                self.apply_review(data, keep_url_verdict=True)
        elif not verified:
            # Retain cloud evidence after a successful proxy review automatically
            # returns the browser to its original URL. This starts no new job.
            try:
                row = self.proxy.reviews.get(self.proxy.reviews.by_url.get(request_key(target)))
            except ValueError:
                row = None
            if row and row.status != "pending":
                data["review"] = {"token": row.token, **self.proxy.reviews.snapshot(row.token)}
                self.apply_review(data, keep_url_verdict=mode == "navigate")
            elif mode == "navigate":
                # A page approved in the last 24 hours needs no Deep scan offer.
                approved = self.approved_review(target)
                if approved is not None:
                    data["review"] = approved
                    self.apply_review(data, keep_url_verdict=True)
        if (mode == "navigate" and passing and not verified
                and data.get("review", {}).get("status") not in {"allow", "block"}):
            data["verdict"] = "safe"
            # Shown when a cloud check is unavailable or inconclusive, or was skipped.
            if not confident or result["status"] != "not_flagged" or unrecognized_money:
                data["unsure"] = True
            if not confident or result["status"] != "not_flagged":
                data["reasons"] = [*data["reasons"],
                                   f"Jev is only {confidence:.0%} confident about this address. "
                                   "Run a deep scan to check the page itself."]
        return data

    def navigation_review(self, target):
        """Join, reuse or start the cloud review for a page the browser is about to open.

        Unlike an explicit Deep scan this never discards a finished review, and a
        page approved within the last 24 hours is not sent to the cloud again.
        Returns None when no cloud review can run, so the address check stands.
        """
        reviews = self.proxy.reviews
        if reviews.reviewer is None:
            return None
        approved = self.approved_review(target)
        if approved is not None:
            return approved
        try:
            row = reviews.start(self.page_url(target))
        except ValueError:
            # Local addresses and URLs with credentials are never sent to the cloud.
            return None
        if row is None:
            return None
        return {"token": row.token, **reviews.snapshot(row.token)}

    @staticmethod
    def page_url(target):
        # The fragment never reaches the website, so the page is the same without it.
        return urlunsplit(urlsplit(target)._replace(fragment=""))

    def approved_review(self, target):
        """The approval for a page that passed a cloud review in the last 24 hours, or None."""
        reviews = self.proxy.reviews
        page = self.page_url(target)
        try:
            if not reviews.allowed(page, "main_frame", "GET"):
                return None
            row = reviews.get(reviews.by_url.get(request_key(page)))
        except ValueError:
            return None
        if row is not None and row.status == "allow":
            return {"token": row.token, **reviews.snapshot(row.token)}
        return {"status": "allow", "page_probability": None, "evidence": [],
                "reason": "TrustLine checked this page in a cloud browser in the last 24 hours."}

    @staticmethod
    def apply_review(data, keep_url_verdict=False):
        review = data["review"]
        # Before a page opens, a cloud check that could not decide falls back to
        # the address check rather than holding every such page.
        if keep_url_verdict and review["status"] == "inconclusive":
            return data
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
            if not isinstance(body, dict) or body.get("mode", "quick") not in MODES:
                raise ValueError("Expected a URL and quick, deep or navigate mode")
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
