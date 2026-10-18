"""Cloudflare-hosted Chromium controlled by a local ChatGPT plan model."""

import asyncio
import base64
import ipaddress
import math
import re
import socket
from urllib.parse import urlsplit
from urllib.error import HTTPError

from .inspection import MONEY_SITE, is_local_host, normalize_origin
from .reviews import review_url
from .transport import request_json


class RemoteError(Exception):
    pass


def public_url(value):
    target, sensitive_parts = review_url(value)
    parts = urlsplit(target)
    if sensitive_parts or parts.port not in {None, 80, 443}:
        raise RemoteError("Navigation requires an ordinary public URL without private parameters")
    return target


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
        self.blocked = []
        self.requests = 0
        self.resolved = {}

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
        if not await self.check_public_host(host):
            raise RemoteError("The destination does not resolve to public addresses")
        result = await self.acquire_session(host)
        session_id = result.get("sessionId", "")
        if not re.fullmatch(r"[a-fA-F0-9-]{20,64}", session_id):
            raise RemoteError("Cloudflare did not create a browser session")
        self.session_id = session_id
        # Construct the fixed trusted endpoint, never use arbitrary response URLs.
        endpoint = (self.base + "/" + session_id).replace("https://", "wss://", 1)
        self.playwright = await async_playwright().start()
        self.browser = await self.playwright.chromium.connect_over_cdp(
            endpoint, headers={"Authorization": "Bearer " + self.token}, timeout=15000)
        # No local launch(), user profile, or user cookies. This context is remote.
        self.context = await self.browser.new_context(viewport={"width": 1280, "height": 800},
            accept_downloads=False, service_workers="block", permissions=[])
        self.context.set_default_timeout(6000)
        self.context.set_default_navigation_timeout(15000)
        await self.context.route("**/*", self.route)
        await self.context.route_web_socket("**/*", lambda ws: ws.close())
        self.page = await self.context.new_page()
        self.page.on("dialog", lambda dialog: dialog.dismiss())
        # Register after creating the inspection tab so it is not a popup.
        self.context.on("page", self.close_popup)
        response = await self.page.goto(target, wait_until="domcontentloaded")
        self.http_status = response.status if response else None
        if response and response.headers.get("cf-mitigated") == "guardrails":
            self.blocked.append("Cloudflare blocked a required navigation")

    async def acquire_session(self, host):
        # The free plan allows one new instance per 20 seconds. Retry once,
        # without a browser running, within the caller's overall review budget.
        for attempt in range(2):
            try:
                return await asyncio.to_thread(request_json, self.base + "?keep_alive=60000", method="POST",
                    token=self.token, data={"guardrails": {"allowedDomains": [host, "*." + host],
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
            self.blocked.append("A popup was blocked")
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
            if request.is_navigation_request() and origin != self.initial_origin:
                raise RemoteError("Cross-origin navigation denied")
            await route.continue_()
        except Exception:
            if len(self.blocked) < 12:
                self.blocked.append("A network request was blocked by the inspection policy")
            await route.abort()

    async def observe(self):
        if self.page.is_closed():
            raise RemoteError("The inspection page closed")
        current, _ = normalize_origin(self.page.url)
        if current != self.initial_origin:
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
                .map(a => ({text:(a.innerText || '').slice(0,100), url:a.href.split(/[?#]/)[0].slice(0,1000)})),
            forms: Array.from(document.forms).slice(0,10).map(f => ({
                method:f.method, action:f.action.split(/[?#]/)[0].slice(0,1000),
                inputs:Array.from(f.elements).slice(0,20).map(e => ({type:e.type, name:e.name?.slice(0,80)}))
            }))
        })""")
        return {**state, "url": self.page.url.split("?", 1)[0].split("#", 1)[0],
                "initial_origin": self.initial_origin, "initial_url": self.initial_url, "http_status": self.http_status,
                "policy_blocks": self.blocked[:],
                "screenshot": "data:image/jpeg;base64," + base64.b64encode(screenshot).decode()}

    async def act(self, action):
        operation = action.get("action")
        if operation == "scroll":
            delta = action.get("y")
            if type(delta) is not int or not -1600 <= delta <= 1600:
                raise RemoteError("Invalid scroll")
            await self.page.mouse.wheel(0, delta)
            await asyncio.sleep(0.2)
        elif operation == "navigate":
            target = public_url(action.get("url"))
            if normalize_origin(target)[0] != self.initial_origin:
                raise RemoteError("Navigation must remain on the inspected origin")
            response = await self.page.goto(target, wait_until="domcontentloaded")
            self.http_status = response.status if response else None
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


def page_state(observation):
    """The landing page as Jev sees it: no path, query, screenshot, or link targets."""
    origin, hostname = normalize_origin(observation["url"])
    forms = []
    for form in observation.get("forms", []):
        try:
            action_origin = normalize_origin(form.get("action"))[0]
        except ValueError:
            action_origin = None
        forms.append({"method": form.get("method"), "action_origin": action_origin,
                      "inputs": form.get("inputs", [])})
    return {"url_origin": origin, "hostname": hostname, "title": observation.get("title", ""),
            "text": observation.get("text", ""), "forms": forms}


class RemoteReviewer:
    def __init__(self, model, browser_factory, *, max_steps=6, jev=None, threshold=0.8,
                 money_threshold=0.6):
        self.model, self.browser_factory, self.max_steps = model, browser_factory, max_steps
        self.jev, self.threshold, self.money_threshold = jev, threshold, money_threshold

    async def review(self, url):
        browser = self.browser_factory()
        checks = []
        try:
            try:
                result = await self.explore(browser, url, checks)
            except Exception:
                page = await checks[0] if checks else None
                # A scam Jev found on the page still blocks it if the cloud model fails.
                if self.page_flagged(page):
                    return self.page_block(page)
                raise
            page = await checks[0] if checks else None
            # Jev finding a scam blocks the page even when the model would allow it.
            if self.page_flagged(page) and result["verdict"] != "block":
                return self.page_block(page)
            if page:
                result["page_probability"] = page[0]
            return result
        finally:
            for check in checks:
                check.cancel()
            await browser.close()

    async def explore(self, browser, url, checks):
        history = []
        await browser.start(url)
        for step in range(self.max_steps):
            observation = await browser.observe()
            if not checks and self.jev is not None:
                # Jev reads the landing page while the model decides its first action.
                checks.append(asyncio.create_task(self.check_page(observation)))
            action = await asyncio.to_thread(self.model.action, observation, history)
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
        try:
            return await asyncio.to_thread(self.jev.assess_page, page_state(observation))
        except Exception:
            # The cloud model's verdict stands alone when the page check is unavailable.
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
