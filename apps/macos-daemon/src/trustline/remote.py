"""Cloudflare-hosted Chromium controlled by a local ChatGPT plan model."""

import asyncio
import base64
import ipaddress
import math
import re
import socket
from urllib.parse import urlsplit
from urllib.error import HTTPError

from . import debug
from .inspection import MONEY_SITE, is_local_host, normalize_origin
from .reviews import review_url
from .transport import request_json


class RemoteError(Exception):
    pass


CHALLENGE_WAIT_SECONDS = 10


def public_url(value):
    target, sensitive_parts = review_url(value)
    parts = urlsplit(target)
    if sensitive_parts or parts.port not in {None, 80, 443}:
        raise RemoteError("Navigation requires an ordinary public URL without private parameters")
    return target


def browser_error_code(error):
    """Chrome's network error code (such as ERR_NAME_NOT_RESOLVED) from a browser error.

    Only the fixed code is kept; the rest of the message can contain URLs.
    """
    match = re.search(r"\b(?:net::)?(ERR_[A-Z0-9_]{3,60})\b", str(error))
    return match[1] if match else None


def browser_failure_message(stage, code):
    """Fixed explanations only, never the browser's URL-bearing exception text."""
    if stage in {"loading the site", "browser action: navigate"}:
        if code == "ERR_CONNECTION_RESET":
            return "The cloud browser's connection to the website was reset."
        if code == "ERR_NAME_NOT_RESOLVED":
            return "The cloud browser could not resolve the website's address."
        if code == "ERR_CONNECTION_REFUSED":
            return "The website refused the cloud browser's connection."
        if code and code.startswith("ERR_CERT_"):
            return "The cloud browser could not verify the website's security certificate."
        return "The cloud browser could not load the website."
    return {
        "connecting to the Cloudflare browser": "TrustLine could not connect to the cloud browser.",
        "configuring the Cloudflare browser": "TrustLine could not prepare the cloud browser for inspection.",
        "reading the page": "The cloud browser could not read the website.",
        "waiting for the website's browser check": "The website's browser check could not finish. Safety is undetermined.",
    }.get(stage, "The cloud browser could not complete the inspection.")


class CloudflareBrowser:
    def __init__(self, account_id, api_token):
        if not re.fullmatch(r"[a-fA-F0-9]{32}", account_id or "") or not api_token:
            raise RemoteError("Configure CLOUDFLARE_ACCOUNT_ID and CLOUDFLARE_API_TOKEN")
        self.base = f"https://api.cloudflare.com/client/v4/accounts/{account_id}/browser-run/devtools/browser"
        self.token = api_token
        self.session_id = None
        self.playwright = self.browser = self.context = self.page = None
        self.initial_origin = None
        self.initial_url = None
        self.http_status = None
        self.mitigation = None
        # Blocks that stopped the inspected page itself from loading. Any of these
        # means the page was not seen as a visitor would see it.
        self.blocked = []
        # Everything else the policy refused: analytics beacons, websockets, media,
        # popups, cross-origin frames. Normal on real sites; reported, not disqualifying.
        self.background_blocks = 0
        self.requests = 0
        self.resolved = {}
        # Which step the browser is on, so a failure can say where it happened.
        self.stage = "not started"

    async def check_public_host(self, host):
        if is_local_host(host):
            return False
        if host not in self.resolved:
            try:
                answers = await asyncio.wait_for(asyncio.get_running_loop().getaddrinfo(
                    host, 443, type=socket.SOCK_STREAM), timeout=5)
                self.resolved[host] = bool(answers) and all(
                    ipaddress.ip_address(answer[4][0]).is_global for answer in answers)
            except OSError:
                self.resolved[host] = False
        return self.resolved[host]

    async def start(self, target):
        from playwright.async_api import async_playwright
        target = public_url(target)
        self.initial_url = target
        self.initial_origin, host = normalize_origin(target)
        self.stage = "checking the address resolves publicly"
        if not await self.check_public_host(host):
            raise RemoteError("The destination does not resolve to public addresses")
        self.stage = "starting a Cloudflare browser session"
        result = await self.acquire_session(host)
        session_id = result.get("sessionId", "")
        if not re.fullmatch(r"[a-fA-F0-9-]{20,64}", session_id):
            raise RemoteError("Cloudflare did not create a browser session")
        self.session_id = session_id
        # Construct the fixed trusted endpoint, never use arbitrary response URLs.
        endpoint = (self.base + "/" + session_id).replace("https://", "wss://", 1)
        self.stage = "connecting to the Cloudflare browser"
        self.playwright = await async_playwright().start()
        self.browser = await self.playwright.chromium.connect_over_cdp(
            endpoint, headers={"Authorization": "Bearer " + self.token}, timeout=15000)
        # No local launch(), user profile, or user cookies. This context is remote.
        self.stage = "configuring the Cloudflare browser"
        self.context = await self.browser.new_context(viewport={"width": 1280, "height": 800},
            accept_downloads=False, service_workers="block", permissions=[])
        self.context.set_default_timeout(6000)
        self.context.set_default_navigation_timeout(15000)
        await self.context.route("**/*", self.route)
        await self.context.route_web_socket("**/*", lambda ws: ws.close())
        self.page = await self.context.new_page()
        self.page.on("dialog", lambda dialog: dialog.dismiss())
        self.page.on("response", self.document_response)
        # Register after creating the inspection tab so it is not a popup.
        self.context.on("page", self.close_popup)
        self.stage = "loading the site"
        await self.navigate(target)
        self.stage = "loaded"
        # A site that upgrades http:// to https:// on the same host is the same site:
        # inspect it from its HTTPS origin from here on.
        final_url = getattr(self.page, "url", None)
        if isinstance(final_url, str) and self.https_upgrade():
            try:
                if normalize_origin(final_url)[0] == self.https_upgrade():
                    self.initial_origin = self.https_upgrade()
            except ValueError:
                pass

    def remember_document_response(self, response):
        self.http_status = response.status
        self.mitigation = response.headers.get("cf-mitigated")
        if self.mitigation == "guardrails" and "Cloudflare blocked a required navigation" not in self.blocked:
            self.blocked.append("Cloudflare blocked a required navigation")
        # Many sites answer on another origin of the same site (siemens.com ->
        # www.siemens.com/en-us/, http -> https). Inspect where the server sent
        # us, but never follow a redirect to a different site.
        landed, _ = normalize_origin(self.page.url)
        if landed != self.initial_origin:
            if not same_site_redirect(self.initial_origin, landed):
                raise RemoteError("The website redirected to a different site")
            self.initial_origin = landed

    def document_response(self, response):
        # Challenge scripts may reload the main document after goto() returns.
        # Subresources and iframe responses must not overwrite its status.
        request = response.request
        if request.is_navigation_request() and request.frame == self.page.main_frame:
            self.remember_document_response(response)

    async def navigate(self, target):
        from playwright.async_api import Error
        # Reuse the guarded context, so a retry needs no new Cloudflare session.
        # DNS, certificate, policy and timeout failures are not retried.
        transient = {"ERR_CONNECTION_RESET", "ERR_CONNECTION_CLOSED",
                     "ERR_NETWORK_CHANGED", "ERR_HTTP2_PROTOCOL_ERROR"}
        for attempt in range(2):
            try:
                self.http_status = self.mitigation = None
                response = await self.page.goto(target, wait_until="domcontentloaded")
                # Response events normally set this first. Retain the latest
                # document if an automatic navigation has already followed it.
                if response and self.http_status is None:
                    self.remember_document_response(response)
                return response
            except Error as error:
                code = browser_error_code(error)
                if attempt or code not in transient or self.blocked:
                    raise
                debug.log("cloud.retry", stage=self.stage, code=code, attempt=2)
                await asyncio.sleep(0.5)

    async def challenge_present(self):
        if self.mitigation == "challenge":
            return True
        # Whole-page interstitial markers, not ordinary embedded Turnstile forms.
        # Return only a boolean; page text and challenge tokens are never logged.
        return await self.page.evaluate("""({status}) => {
            const title = (document.title || '').trim();
            const text = (document.body?.innerText || '').trim().slice(0, 4000);
            const shortPage = text.length < 2000;
            const marker = Boolean(document.querySelector(
                '#challenge-form, #challenge-running, #challenge-stage, #cf-challenge-running'));
            const challengeTitle = /^(just a moment|checking your browser|verify (you are|you're) human|security verification)([.!…\\s]|$)/i.test(title);
            const challengeText = /checking your browser|performing security verification|verifying (you are|you're) human|verify (you are|you're) human/i.test(text);
            return shortPage && (marker || challengeTitle ||
                ([403, 429, 503].includes(status) && challengeText));
        }""", {"status": self.http_status}) is True

    async def wait_for_site(self):
        from playwright.async_api import Error
        waiting = False
        try:
            async with asyncio.timeout(CHALLENGE_WAIT_SECONDS):
                while True:
                    try:
                        challenged = await self.challenge_present()
                    except Error as error:
                        # Automatic challenge reloads can replace the JS context
                        # during this fixed read. Wait for the new document.
                        if not any(message in str(error) for message in (
                                "Execution context was destroyed", "Cannot find context with specified id")):
                            raise
                        challenged = True
                    if not challenged:
                        if waiting:
                            debug.log("cloud.challenge", status="cleared", http_status=self.http_status)
                        return
                    if not waiting:
                        waiting = True
                        self.stage = "waiting for the website's browser check"
                        debug.log("cloud.challenge", status="waiting", http_status=self.http_status,
                                  timeout_seconds=CHALLENGE_WAIT_SECONDS)
                    if self.blocked:
                        raise RemoteError("The website's browser check could not complete under the inspection policy. Safety is undetermined.")
                    await asyncio.sleep(0.5)
        except TimeoutError:
            if not waiting:
                raise RemoteError("The cloud browser could not read the website.") from None
            debug.log("cloud.challenge", status="timeout", http_status=self.http_status)
            raise RemoteError("The website's browser check did not clear within 10 seconds. Safety is undetermined.") from None

    async def acquire_session(self, host):
        # The free plan allows one new instance per 20 seconds. Retry once,
        # without a browser running, within the caller's overall review budget.
        for attempt in range(2):
            try:
                return await asyncio.to_thread(request_json, self.base + "?keep_alive=60000", method="POST",
                    token=self.token, data={"guardrails": {"allowedDomains": allowed_domains(host),
                                                          "allowedDomainSets": ["common-cdns"]}})
            except HTTPError as error:
                status = error.code
                try:
                    delay = float((error.headers or {}).get("Retry-After", "20"))
                except (ValueError, TypeError):
                    delay = 20
                error.close()
                if status != 429 or attempt or not math.isfinite(delay) or delay > 30:
                    raise RemoteError("Cloudflare browser acquisition is unavailable") from None
                await asyncio.sleep(max(20, delay))

    async def close_popup(self, page):
        if page is not self.page:
            self.background_blocks += 1
            await page.close()

    async def route(self, route):
        request = route.request
        self.requests += 1
        try:
            origin, host = normalize_origin(request.url)
            parts = urlsplit(request.url)
            if (request.method not in {"GET", "HEAD"} or self.requests > 150
                    or parts.username is not None or parts.password is not None
                    or parts.port not in {None, 80, 443}
                    or request.resource_type in {"media", "websocket", "eventsource"}
                    or not await self.check_public_host(host)):
                raise RemoteError("Request denied")
            if request.is_navigation_request() and not self.same_site(origin):
                raise RemoteError("Cross-origin navigation denied")
            await route.continue_()
        except Exception:
            if not self.is_main_document(request):
                self.background_blocks += 1
            elif len(self.blocked) < 12:
                self.blocked.append("The page itself was blocked by the inspection policy")
            await route.abort()

    def https_upgrade(self):
        """The https:// origin for an http:// starting origin on a default port, else None."""
        origin = self.initial_origin or ""
        rest = origin[len("http://"):]
        if origin.startswith("http://") and rest and ":" not in rest:
            return "https://" + rest
        return None

    def same_site(self, origin):
        return origin == self.initial_origin or (origin is not None and origin == self.https_upgrade())

    def is_main_document(self, request):
        """The inspected tab's own page load, not its scripts, beacons, frames or popups."""
        try:
            if not request.is_navigation_request():
                return False
            return self.page is None or request.frame == self.page.main_frame
        except Exception:
            return True  # When unsure, count it against approval.

    async def observe(self):
        self.stage = "reading the page"
        if self.page.is_closed():
            raise RemoteError("The inspection page closed")
        await self.wait_for_site()
        self.stage = "reading the page"
        current, _ = normalize_origin(self.page.url)
        if not self.same_site(current):
            raise RemoteError("The browser left the inspected origin")
        screenshot = await self.page.screenshot(type="jpeg", quality=55, full_page=False,
                                               timeout=6000)
        if len(screenshot) > 1_500_000:
            raise RemoteError("Screenshot exceeded the size limit")
        # Fixed extraction code, never model-supplied JavaScript.
        state = await self.page.evaluate("""() => ({
            title: document.title.slice(0,300),
            text: (document.body?.innerText || '').slice(0,14000),
            links: Array.from(document.querySelectorAll('a[href]')).slice(0,40)
                .map(a => ({text:(a.innerText || '').slice(0,100), url:a.href.split(/[?#]/)[0].slice(0,1000),
                            download:a.hasAttribute('download')})),
            forms: Array.from(document.forms).slice(0,10).map(f => ({
                method:f.method, action:f.action.split(/[?#]/)[0].slice(0,1000),
                inputs:Array.from(f.elements).slice(0,20).map(e => ({type:e.type, name:e.name?.slice(0,80),
                                                                     autocomplete:(e.autocomplete || '').slice(0,40)}))
            })),
            // Many sign-in and checkout pages render fields outside a <form>.
            fields: Array.from(document.querySelectorAll('input')).slice(0,60)
                .map(e => ({type:e.type, name:e.name?.slice(0,80), autocomplete:(e.autocomplete || '').slice(0,40)})),
            // Jev reads the page body; the <head> is mostly preload and script tags.
            html: (document.body || document.documentElement).outerHTML.slice(0,2000000)
        })""")
        return {**state, "url": self.page.url.split("?", 1)[0].split("#", 1)[0],
                "initial_origin": self.initial_origin, "initial_url": self.initial_url, "http_status": self.http_status,
                "policy_blocks": self.blocked[:], "background_requests_blocked": self.background_blocks,
                "screenshot": "data:image/jpeg;base64," + base64.b64encode(screenshot).decode()}

    async def act(self, action):
        operation = action.get("action")
        self.stage = f"browser action: {operation}"
        if operation == "scroll":
            delta = action.get("y")
            # A scroll amount is harmless: clamp an oversized one instead of failing the review.
            if type(delta) not in (int, float) or delta != delta:
                delta = 800
            delta = max(-1600, min(1600, round(delta)))
            await self.page.mouse.wheel(0, delta)
            await asyncio.sleep(0.2)
        elif operation == "navigate":
            target = public_url(action.get("url"))
            if not self.same_site(normalize_origin(target)[0]):
                raise RemoteError("Navigation must remain on the inspected origin")
            await self.navigate(target)
        elif operation == "click_link":
            x, y = action.get("x"), action.get("y")
            if type(x) is not int or type(y) is not int or not (0 <= x < 1280 and 0 <= y < 800):
                raise RemoteError("Invalid click coordinates")
            # Resolve the anchor rather than click arbitrary JS/form controls.
            # Navigation still has the same-origin and request-method guards.
            href = await self.page.evaluate("""({x,y}) => {
                const a = document.elementFromPoint(x,y)?.closest('a[href]');
                return a && !a.hasAttribute('download') ? a.href : null;
            }""", {"x": x, "y": y})
            if not href:
                raise RemoteError("Only links may be selected")
            await self.act({"action": "navigate", "url": href})
        else:
            raise RemoteError("Unsupported browser action")

    async def close(self):
        try:
            if self.browser:
                await asyncio.wait_for(self.browser.close(), 5)
        except Exception:
            pass
        try:
            if self.session_id:
                await asyncio.to_thread(request_json, self.base + "/" + self.session_id,
                                        token=self.token, method="DELETE", timeout=5)
        except Exception:
            pass
        finally:
            if self.playwright:
                await self.playwright.stop()


def allowed_domains(host):
    """The host and its subdomains, plus the bare domain for a www. address."""
    domains = [host, "*." + host]
    if host.startswith("www.") and host.count(".") >= 2:
        domains += [host[4:], "*." + host[4:]]
    return domains


def same_site_redirect(initial_origin, landed_origin):
    """Whether a server redirect stays on the reviewed site.

    Allowed: an http -> https upgrade, a move to a subdomain (www., a region),
    and www.example -> example. Never a different site, and never a downgrade.
    """
    before, after = urlsplit(initial_origin), urlsplit(landed_origin)
    if after.scheme != before.scheme and not (before.scheme == "http" and after.scheme == "https"):
        return False
    a, b = before.hostname or "", after.hostname or ""
    return bool(a and b) and (a == b or b.endswith("." + a) or a == "www." + b)


SIGN_IN_FIELD = re.compile(r"passw|passcode|otp|one-time-code", re.I)
PAYMENT_FIELD = re.compile(r"cc-|card|cvc|cvv|iban|routing|account.?num|expir", re.I)
DOWNLOAD_FILE = re.compile(r"\.(exe|dmg|pkg|msi|apk|scr|bat|jar|zip)$", re.I)


def field_kinds(fields):
    hints = [f"{field.get('name') or ''} {field.get('autocomplete') or ''}" for field in fields]
    sign_in = any(field.get("type") == "password" for field in fields) or any(SIGN_IN_FIELD.search(h) for h in hints)
    return sign_in, any(PAYMENT_FIELD.search(h) for h in hints)


def page_features(observations):
    """What the reviewed pages ask of a visitor, from the fixed extraction code.

    Plain facts for the warning page: whether the pages ask for a password or
    card details, send either to a different site, or offer file downloads.
    """
    features = {"sign_in": False, "payment": False, "external_form": False, "downloads": False}
    for observation in observations:
        try:
            page_origin = normalize_origin(observation.get("url", ""))[0]
        except ValueError:
            page_origin = None
        sign_in, payment = field_kinds(observation.get("fields", []))
        features["sign_in"] |= sign_in
        features["payment"] |= payment
        for form in observation.get("forms", []):
            form_sign_in, form_payment = field_kinds(form.get("inputs", []))
            features["sign_in"] |= form_sign_in
            features["payment"] |= form_payment
            if not (form_sign_in or form_payment):
                continue
            try:
                action_origin = normalize_origin(form.get("action") or "")[0]
            except ValueError:
                action_origin = None
            if page_origin and action_origin and action_origin != page_origin:
                features["external_form"] = True
        for link in observation.get("links", []):
            if link.get("download") or DOWNLOAD_FILE.search(link.get("url") or ""):
                features["downloads"] = True
    return features


# Jev's limit is 32k tokens for the page plus one question. HTML is token-dense,
# so cap it well under that, after the visible text (up to 14,000 characters).
HTML_LIMIT = 48_000


def _shorten_script(match):
    body = match[2]
    return match[1] + (body if len(body) <= 2000 else body[:2000] + "…") + match[3]


def compact_html(html):
    """The rendered page's <body> HTML, made small enough for Jev.

    Starts at <body> (anything before it, such as <head>, is dropped). Drops
    comments, CSS, SVG drawings and embedded base64 files, keeps the first
    2,000 characters of each inline script, collapses whitespace, then caps it.
    Hidden elements, form targets, link targets and script sources all remain.
    """
    if not isinstance(html, str):
        return ""
    body = re.search(r"<body\b", html, re.I)
    if body:
        html = html[body.start():]
    html = re.sub(r"<!--.*?-->", "", html, flags=re.S)
    html = re.sub(r"(<style\b[^>]*>).*?(</style>)", r"\1\2", html, flags=re.S | re.I)
    html = re.sub(r"(<svg\b[^>]*>).*?(</svg>)", r"\1\2", html, flags=re.S | re.I)
    html = re.sub(r"data:[\w/+.-]+;base64,[A-Za-z0-9+/=]+", "data:…", html)
    html = re.sub(r"(<script\b[^>]*>)(.*?)(</script>)", _shorten_script, html, flags=re.S | re.I)
    return re.sub(r"\s+", " ", html).strip()[:HTML_LIMIT]


def page_state(observation, *, include_html=True):
    """The landing page as Jev sees it: visible text, forms and compacted HTML.

    No URL path, query or screenshot. The HTML does include link and form targets.
    """
    origin, hostname = normalize_origin(observation["url"])
    forms = []
    for form in observation.get("forms", []):
        try:
            action_origin = normalize_origin(form.get("action"))[0]
        except ValueError:
            action_origin = None
        forms.append({"method": form.get("method"), "action_origin": action_origin,
                      "inputs": form.get("inputs", [])})
    state = {"url_origin": origin, "hostname": hostname, "title": observation.get("title", ""),
             "text": observation.get("text", ""), "forms": forms}
    html = compact_html(observation.get("html")) if include_html else ""
    if html:
        state["html"] = html
    return state


class RemoteReviewer:
    def __init__(self, model, browser_factory, *, max_steps=6, jev=None, threshold=0.8,
                 money_threshold=0.6):
        self.model, self.browser_factory, self.max_steps = model, browser_factory, max_steps
        self.jev, self.threshold, self.money_threshold = jev, threshold, money_threshold

    async def review(self, url):
        browser = self.browser_factory()
        checks, observations = [], []
        try:
            try:
                result = await self.explore(browser, url, checks, observations)
            except Exception as error:
                from playwright.async_api import Error
                stage = getattr(browser, "stage", None)
                code = browser_error_code(error)
                debug.log("cloud.error", stage=stage if isinstance(stage, str) else None,
                          error=type(error).__name__, code=code)
                page = await checks[0] if checks else None
                # A scam Jev found on the page still blocks it if the cloud model fails.
                if self.page_flagged(page):
                    return {**self.page_block(page), "page_features": page_features(observations)}
                if isinstance(error, Error):
                    raise RemoteError(browser_failure_message(stage, code)) from None
                raise
            page = await checks[0] if checks else None
            # Jev finding a scam blocks the page even when the model would allow it.
            if self.page_flagged(page) and result["verdict"] != "block":
                result = self.page_block(page)
            elif page:
                result["page_probability"] = page[0]
            result["page_features"] = page_features(observations)
            return result
        finally:
            for check in checks:
                check.cancel()
            await browser.close()

    async def explore(self, browser, url, checks, observations):
        history = []
        await browser.start(url)
        for step in range(self.max_steps):
            observation = await browser.observe()
            observations.append(observation)
            debug.log("cloud.page", step=step + 1, url=debug.safe_url(observation.get("url", "")),
                      http_status=observation.get("http_status"), text_chars=len(observation.get("text") or ""),
                      html_chars=len(observation.get("html") or ""), blocked=len(observation.get("policy_blocks") or []),
                      background_blocked=observation.get("background_requests_blocked", 0))
            if not checks and self.jev is not None:
                # Jev reads the landing page while the model decides its first action.
                checks.append(asyncio.create_task(self.check_page(observation)))
            action = await asyncio.to_thread(self.model.action, observation, history)
            debug.log("cloud.action", step=step + 1, action=action.get("action"), verdict=action.get("verdict"),
                      y=action.get("y"),
                      url=debug.safe_url(action.get("url")) if action.get("url") else None,
                      reason=str(action.get("reason", ""))[:200])
            if action.get("action") == "finish":
                return self.finish(action, observation)
            history.append({"page_url": observation.get("url"), "title": observation.get("title"),
                            "observed_text": observation.get("text", "")[:4000],
                            "action": action.get("action"), "reason": str(action.get("reason", ""))[:400]})
            await browser.act(action)
        return {"verdict": "inconclusive", "reason": "The browser action limit was reached.", "evidence": []}

    @staticmethod
    def finish(action, observation):
        verdict = action.get("verdict")
        if verdict not in {"allow", "block", "inconclusive"}:
            raise RemoteError("Invalid model verdict")
        # A restricted, incomplete page cannot earn an automatic pass.
        if verdict == "allow" and (observation.get("policy_blocks")
                or observation.get("http_status", 0) not in range(200, 300)
                or not observation.get("text", "").strip()):
            return {"verdict": "inconclusive", "reason": "The page could not be inspected completely.", "evidence": []}
        return {"verdict": verdict, "reason": action.get("reason", ""),
                "evidence": action.get("evidence", [])}

    async def check_page(self, observation):
        """Return Jev's deceptive-page and money-site probabilities, or None if unavailable."""
        page = page_state(observation)
        try:
            result = await asyncio.to_thread(self.jev.assess_page, page)
            debug.log("jev.page", deceptive=result[0], money=result[1], html_chars=len(page.get("html", "")),
                      text_chars=len(page.get("text") or ""))
            return result
        except Exception as error:
            debug.log("jev.page.error", error=type(error).__name__, html_chars=len(page.get("html", "")),
                      retry_without_html="html" in page)
            if "html" not in page:
                # The cloud model's verdict stands alone when the page check is unavailable.
                return None
        try:
            # The HTML may have pushed it past Jev's context limit: the visible page still counts.
            result = await asyncio.to_thread(self.jev.assess_page, page_state(observation, include_html=False))
            debug.log("jev.page", deceptive=result[0], money=result[1], html_chars=0, retried=True)
            return result
        except Exception as error:
            debug.log("jev.page.error", error=type(error).__name__, retried=True)
            return None

    def page_flagged(self, page):
        if page is None:
            return False
        deceptive, money = page
        return deceptive >= (self.money_threshold if money >= MONEY_SITE else self.threshold)

    @staticmethod
    def page_block(page):
        deceptive, money = page
        evidence = [f"TrustLine estimates a {deceptive:.0%} chance this page is phishing or a scam."]
        if money >= MONEY_SITE:
            evidence.append("This looks like a money or shopping site, so TrustLine checks it more strictly.")
        return {"verdict": "block", "reason": "TrustLine found signs of a scam on this page.",
                "evidence": evidence, "page_probability": deceptive}
