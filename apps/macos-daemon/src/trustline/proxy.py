"""Inspect metadata inside a local HTTP(S) proxy, without a browser extension."""

import asyncio
from concurrent.futures import ThreadPoolExecutor
import fcntl
import json
import logging
import os
from pathlib import Path
import signal
import sys

from mitmproxy import http, options, tls
from mitmproxy.net import tls as net_tls
from mitmproxy.tools.dump import DumpMaster

from .inspection import Inspector, is_local_host, normalize_host
from .pages import redirect, response_page
from .reviews import ReviewManager
from .approvals import ReviewedPages

REDIRECT_URL = "https://blocked.example.com/"
REDIRECT_HOST = "blocked.example.com"


def request_kind(request: http.Request) -> str:
    destination = request.headers.get("sec-fetch-dest", "").lower()
    mode = request.headers.get("sec-fetch-mode", "").lower()
    if destination == "document" and mode == "navigate":
        return "main_frame"
    if destination in {"frame", "iframe"}:
        return "sub_frame"
    # Plain HTTP navigations may omit Fetch Metadata headers. Only use the HTML
    # fallback when no destination is supplied, never for a known subresource.
    if not destination and mode in {"", "navigate"}:
        accepted = {part.split(";", 1)[0].strip().lower()
                    for part in request.headers.get("accept", "").split(",")}
        if accepted & {"text/html", "application/xhtml+xml"}:
            return "main_frame"
    return {
        "style": "stylesheet", "script": "script", "image": "image", "font": "font",
        "audio": "media", "video": "media", "object": "object", "embed": "object",
        "empty": "xmlhttprequest",
    }.get(destination, "other")


class InspectionProxy:
    def __init__(self, inspector: Inspector, reviews=None):
        self.inspector = inspector
        self.reviews = reviews if reviews is not None else ReviewManager(approvals=ReviewedPages(inspector.sites.path))
        self.executor = ThreadPoolExecutor(max_workers=1)
        self.pending = 0

    def passthrough(self, hostname: str) -> bool:
        host = normalize_host(hostname)
        return self.inspector.sites.contains(host) or is_local_host(host)

    def tls_clienthello(self, data: tls.ClientHelloData):
        address = data.context.server.address
        if not address:
            return
        try:
            if normalize_host(address[0]) != REDIRECT_HOST and self.passthrough(address[0]):
                # Leave approved HTTPS bytes encrypted and unmodified end to end.
                data.ignore_connection = True
        except ValueError:
            return

    async def requestheaders(self, flow: http.HTTPFlow):
        request = flow.request
        # Stream bodies through the proxy instead of collecting them for analysis.
        request.stream = True
        try:
            host = normalize_host(request.host)
            if host == REDIRECT_HOST:
                self.control_request(flow)
                return
            if self.passthrough(host):
                return
            kind = request_kind(request)
            if self.reviews.allowed(request.pretty_url, kind, request.method):
                return
            authority = f"[{host}]" if ":" in host else host
            metadata = {
                "url": f"{request.scheme}://{authority}:{request.port}",
                "method": request.method,
                "resource_type": kind,
            }
        except ValueError:
            flow.response = http.Response.make(400, b"Invalid destination\n")
            return
        if self.pending >= 8:
            self.hold(flow, kind)
            return
        self.pending += 1
        try:
            result = await asyncio.get_running_loop().run_in_executor(
                self.executor, self.inspector.inspect, metadata,
            )
        except Exception:
            self.hold(flow, kind)
            return
        finally:
            self.pending -= 1
        if result["status"] == "suspicious":
            headers = {
                "Cache-Control": "no-store",
                "Referrer-Policy": "no-referrer",
                "Content-Type": "text/plain; charset=utf-8",
            }
            if kind == "main_frame":
                flow.response = redirect(REDIRECT_URL)
            else:
                # Redirecting an image or fetch cannot navigate the browser's tab.
                flow.response = http.Response.make(403, b"Suspicious destination blocked\n", headers)
        else:
            # A low origin-metadata score does not approve the page's contents.
            # All non-allowlisted pages need a completed remote check.
            self.hold(flow, kind)

    def hold(self, flow, kind):
        if kind != "main_frame":
            flow.response = http.Response.make(403, b"Destination has not been reviewed\n",
                                               {"Cache-Control": "no-store"})
            return
        try:
            row = self.reviews.start(flow.request.pretty_url, flow.request.method)
        except ValueError:
            row = None
        flow.response = (redirect(REDIRECT_URL + "_trustline/check/" + row.token) if row
                         else response_page("Website remains blocked", "The inspection queue is unavailable.", status=503))

    def control_request(self, flow):
        request = flow.request
        if request.method != "GET":
            flow.response = http.Response.make(405, b"Method not allowed\n")
            return
        path = request.path.split("?", 1)[0]
        prefix = "/_trustline/"
        if path.startswith(prefix):
            parts = path.removeprefix(prefix).split("/")
            if len(parts) == 2:
                action, token = parts
                row = self.reviews.get(token)
                if row and action == "check":
                    flow.response = response_page("Checking this website", row.reason, token=token)
                    return
                if row and action == "reviews":
                    flow.response = http.Response.make(200, json.dumps(self.reviews.snapshot(token)).encode(), {
                        "Content-Type": "application/json", "Cache-Control": "no-store",
                        "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer",
                    })
                    return
                if row and action == "continue" and row.status == "allow" and self.reviews.allowed(row.url, "main_frame", "GET"):
                    flow.response = redirect(row.url)
                    return
            flow.response = response_page("Website remains blocked", "This check is unavailable or expired.", status=404)
            return
        flow.response = response_page("Website blocked", "TrustLine detected a suspicious website. No page content was loaded locally.")

    def responseheaders(self, flow: http.HTTPFlow):
        if flow.response:
            flow.response.stream = True

    def done(self):
        self.reviews.close()
        self.executor.shutdown(wait=False, cancel_futures=True)


async def run_proxy(state_dir: Path, inspector: Inspector, port: int = 8899, extra_addons=(), reviewer=None, api_port=None,
                    debug_state=False):
    os.umask(0o077)
    state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    state_dir.chmod(0o700)
    certificates = state_dir / "certificates"
    certificates.mkdir(exist_ok=True, mode=0o700)
    certificates.chmod(0o700)
    with (state_dir / "daemon.lock").open("a") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise ValueError("TrustLine is already running in this state directory") from None
        # Disable optional TLS secret logging even if inherited from the shell.
        if net_tls.log_master_secret:
            net_tls.log_master_secret.close()
        net_tls.log_master_secret = None
        library_log = logging.getLogger("mitmproxy")
        library_log.addHandler(logging.NullHandler())
        library_log.propagate = False
        opts = options.Options(listen_host="127.0.0.1", listen_port=port, confdir=str(certificates))
        # No flow dumper, interactive UI, flow files, or URL-bearing terminal logs.
        master = DumpMaster(opts, with_termlog=False, with_dumper=False)
        master.options.update(connection_strategy="lazy", upstream_cert=False,
                              ssl_insecure=False, http2=True)
        addon = InspectionProxy(inspector, ReviewManager(reviewer, approvals=ReviewedPages(inspector.sites.path)))
        master.addons.add(addon, *extra_addons)
        api_server = None
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(sig, master.shutdown)
        try:
            if api_port is not None:
                from .api import start_api
                api_server = start_api(addon, api_port, debug_state=debug_state)
                print(f"TrustLine extension API starting on 127.0.0.1:{api_port}", file=sys.stderr, flush=True)
            print(f"TrustLine proxy starting on 127.0.0.1:{port}", file=sys.stderr, flush=True)
            await master.run()
        finally:
            if api_server is not None:
                api_server.stop()
                await api_server.close_all_connections()
            addon.done()
