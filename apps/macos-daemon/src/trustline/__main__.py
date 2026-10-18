import argparse
import asyncio
import getpass
import json
import os
from pathlib import Path
import subprocess
import sys

from dotenv import dotenv_values

from . import debug
from .inspection import ApprovedSites, Inspector, JevClient

ENV_FILE = Path(__file__).resolve().parents[2] / ".env"


def setting(name, default=None):
    value = os.environ.get(name)
    if value:
        return value
    if ENV_FILE.is_file():
        return dotenv_values(ENV_FILE, interpolate=False).get(name) or default
    return default


def api_key() -> str | None:
    if os.environ.get("TYPESAFE_API_KEY"):
        return os.environ["TYPESAFE_API_KEY"]
    # Use the service's directory even when launchd starts us from another cwd.
    # Read only the API key; do not export unrelated .env values or expand secrets.
    if ENV_FILE.is_file():
        value = dotenv_values(ENV_FILE, interpolate=False).get("TYPESAFE_API_KEY")
        if value:
            return value
    if sys.platform == "darwin":
        try:
            result = subprocess.run([
                "/usr/bin/security", "find-generic-password", "-a", getpass.getuser(),
                "-s", "com.trustline.typesafe", "-w",
            ], capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                return result.stdout.strip() or None
        except (OSError, subprocess.TimeoutExpired):
            pass
    return None


def main():
    parser = argparse.ArgumentParser(description="TrustLine local website inspection proxy")
    parser.add_argument("--state-dir", type=Path, default=Path.home() / "Library/Application Support/TrustLine")
    commands = parser.add_subparsers(dest="command", required=True)
    daemon = commands.add_parser("serve", help="Run the background analysis service")
    daemon.add_argument("--model", default="jev-latest")
    daemon.add_argument("--threshold", type=float, default=0.8)
    daemon.add_argument("--money-threshold", type=float, default=0.6,
                        help="Stricter threshold for crypto, finance, and shopping sites")
    daemon.add_argument("--port", type=int, default=8899)
    daemon.add_argument("--api-port", type=int, default=8765, help="Loopback Chrome extension API port")
    daemon.add_argument("--debug", action="store_true",
                        help="Write a debug log and open a Terminal window showing it with live state "
                             "(also TRUSTLINE_DEBUG=1 in .env)")
    for name, text in (("debug", "Open the debug console in a new Terminal window"),
                       ("debug-console", "Show the debug log and live state in this terminal")):
        command = commands.add_parser(name, help=text)
        command.add_argument("--api-port", type=int, default=8765)
    browser = commands.add_parser("launch-chrome", help="Open a Chrome session using the proxy")
    browser.add_argument("--port", type=int, default=8899)
    inspect = commands.add_parser("inspect", help="Assess a URL directly without opening it")
    inspect.add_argument("url")
    review = commands.add_parser("review", help="Run a remote browser review using your connected ChatGPT plan")
    review.add_argument("url")
    commands.add_parser("approved", help="List approved domains")
    login = commands.add_parser("chatgpt-login", help="Continue with ChatGPT to authorize subscription usage")
    login.add_argument("--new-account", action="store_true")
    commands.add_parser("chatgpt-status", help="Show the connected account, never tokens")
    commands.add_parser("chatgpt-accounts", help="List saved ChatGPT account registrations")
    select = commands.add_parser("chatgpt-select", help="Select a saved account registration")
    select.add_argument("account_id")
    commands.add_parser("chatgpt-logout", help="Revoke the selected ChatGPT session")
    commands.add_parser("check-config", help="Check configuration without revealing secrets")
    for name in ("approve", "revoke"):
        command = commands.add_parser(name)
        command.add_argument("domain")
    args = parser.parse_args()
    args.state_dir = args.state_dir.expanduser().resolve()
    os.umask(0o077)
    try:
        if args.command == "debug-console":
            debug.run_console(args.api_port)
            return
        if args.command == "debug":
            args.state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
            if not debug.open_console(args.state_dir, args.api_port):
                raise ValueError("Opening Terminal needs macOS. Run debug-console in a terminal instead.")
            return
        if args.command.startswith("chatgpt-") or args.command == "check-config":
            from .chatgpt import ChatGPTAccount, PlanError
            account = ChatGPTAccount(args.state_dir)
            try:
                if args.command == "chatgpt-login":
                    result = account.login(new_account=args.new_account)
                elif args.command == "chatgpt-logout":
                    result = account.logout()
                elif args.command == "chatgpt-accounts":
                    result = account.profiles()
                elif args.command == "chatgpt-select":
                    account.select(args.account_id)
                    result = account.status()
                else:
                    result = account.status()
                    if args.command == "check-config":
                        result = {"chatgpt": result, "typesafe_configured": bool(api_key()),
                                  "cloudflare_configured": bool(setting("CLOUDFLARE_ACCOUNT_ID") and setting("CLOUDFLARE_API_TOKEN"))}
                print(json.dumps(result, indent=2))
            except PlanError as error:
                raise ValueError(str(error)) from None
            return
        if args.command == "review":
            from .chatgpt import ChatGPTAccount, ChatGPTPlanClient
            from .remote import CloudflareBrowser, RemoteReviewer
            from .reviews import ReviewManager
            from .approvals import ReviewedPages
            account = ChatGPTAccount(args.state_dir)
            account_id, token = setting("CLOUDFLARE_ACCOUNT_ID"), setting("CLOUDFLARE_API_TOKEN")
            if not account.status()["using_chatgpt_plan"] or not account_id or not token:
                raise ValueError("Complete chatgpt-login and configure Cloudflare before running review")
            key = api_key()
            async def run_review():
                manager = ReviewManager(RemoteReviewer(ChatGPTPlanClient(account), lambda: CloudflareBrowser(account_id, token),
                                                       jev=JevClient(key) if key else None),
                                        approvals=ReviewedPages(args.state_dir / "approved.sqlite3"))
                try:
                    row = manager.start(args.url)
                    if row.task:
                        await row.task
                    print(json.dumps(manager.snapshot(row.token), indent=2))
                finally:
                    manager.close()
            asyncio.run(run_review())
            return
        if hasattr(args, "port") and not 1 <= args.port <= 65535:
            raise ValueError("Port must be between 1 and 65535")
        if args.command == "serve" and (not 1 <= args.api_port <= 65535 or args.api_port == args.port):
            raise ValueError("API port must be between 1 and 65535 and different from the proxy port")
        if args.command == "launch-chrome":
            from .browser import launch_chrome
            launch_chrome(args.state_dir, args.port)
            return
        sites = ApprovedSites(args.state_dir / "approved.sqlite3")
        if args.command in {"serve", "inspect"}:
            inspector = Inspector(sites, JevClient(api_key(), model=getattr(args, "model", "jev-latest")),
                                  getattr(args, "threshold", 0.8),
                                  money_threshold=getattr(args, "money_threshold", None))
            if args.command == "serve":
                try:
                    from .proxy import run_proxy
                except ImportError:
                    raise ValueError("Install requirements.txt with this Python interpreter first") from None
                from .chatgpt import ChatGPTAccount, ChatGPTPlanClient
                from .remote import CloudflareBrowser, RemoteReviewer
                account = ChatGPTAccount(args.state_dir)
                account_id, token = setting("CLOUDFLARE_ACCOUNT_ID"), setting("CLOUDFLARE_API_TOKEN")
                reviewer = None
                if account.status()["using_chatgpt_plan"] and account_id and token:
                    reviewer = RemoteReviewer(ChatGPTPlanClient(account), lambda: CloudflareBrowser(account_id, token),
                                              jev=inspector.jev, threshold=inspector.threshold,
                                              money_threshold=inspector.money_threshold)
                debug_mode = args.debug or str(setting("TRUSTLINE_DEBUG", "")).lower() in {"1", "true", "yes", "on"}
                if debug_mode:
                    debug.enable()
                    debug.log("startup", proxy_port=args.port, api_port=args.api_port, jev_model=args.model,
                              threshold=args.threshold, money_threshold=args.money_threshold,
                              typesafe_key=bool(inspector.jev.api_key), cloud_review=reviewer is not None)
                    args.state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
                    debug.open_console(args.state_dir, args.api_port)
                asyncio.run(run_proxy(args.state_dir, inspector, args.port, reviewer=reviewer, api_port=args.api_port,
                                      debug_state=debug_mode))
            else:
                print(json.dumps(inspector.inspect({"url": args.url})))
        elif args.command == "approved":
            print("\n".join(sites.domains()))
        elif args.command == "approve":
            sites.add(args.domain)
        elif args.command == "revoke":
            sites.remove(args.domain)
            from .approvals import ReviewedPages
            ReviewedPages(sites.path).clear_domain(args.domain)
    except (ValueError, OSError) as error:
        # ValueError messages are deliberately fixed strings from our validation code.
        message = str(error) if isinstance(error, ValueError) else "Local service operation failed"
        print(message, file=sys.stderr)
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
