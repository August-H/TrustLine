"""Opt-in debug output: an event log, plus a console that shows it with live state.

Off unless `serve --debug` or TRUSTLINE_DEBUG=1. While off, log() does nothing.
The log never holds API keys, tokens, cookies, page text or HTML (only their
sizes), and URLs lose their credentials, query and fragment.
"""

import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import threading
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit, urlunsplit
from urllib.request import ProxyHandler, build_opener

LOG_PATH = Path.home() / "Library/Logs/TrustLine/debug.log"
DAEMON_DIR = Path(__file__).resolve().parents[2]
MAX_VALUE = 300

_enabled = False
_path = LOG_PATH
_lock = threading.Lock()


def enable(path: Path | None = None):
    global _enabled, _path
    _path = Path(path) if path else LOG_PATH
    _path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with _lock, _path.open("a") as output:
        output.write(f"\n{time.strftime('%Y-%m-%d %H:%M:%S')} debug mode on (pid {os.getpid()})\n")
    _path.chmod(0o600)
    _enabled = True


def disable():
    global _enabled
    _enabled = False


def enabled() -> bool:
    return _enabled


def log_path() -> Path:
    return _path


def safe_url(value) -> str:
    """Scheme, host, port and path only."""
    try:
        parts = urlsplit(str(value))
        host = parts.hostname or ""
        if parts.port:
            host += f":{parts.port}"
        return urlunsplit((parts.scheme, host, parts.path, "", ""))
    except ValueError:
        return "<invalid url>"


def _format(value) -> str:
    if isinstance(value, float):
        text = f"{value:.3f}"
    elif isinstance(value, str):
        text = value if value and not any(c.isspace() for c in value) else json.dumps(value)
    else:
        text = json.dumps(value, default=str, separators=(",", ":"))
    return text if len(text) <= MAX_VALUE else text[:MAX_VALUE] + "…"


def log(event: str, **fields):
    if not _enabled:
        return
    now = time.time()
    stamp = time.strftime("%H:%M:%S", time.localtime(now)) + f".{int(now % 1 * 1000):03d}"
    line = f"{stamp} {event:<16} " + " ".join(f"{key}={_format(value)}" for key, value in fields.items())
    try:
        with _lock, _path.open("a") as output:
            output.write(line.rstrip() + "\n")
    except OSError:
        pass  # Debug output never breaks inspection.


# ------------------------------------------------------------------ console

def console_script(state_dir: Path, api_port: int) -> str:
    python = shlex.quote(sys.executable)
    run = shlex.quote(str(DAEMON_DIR / "run.py"))
    return ("#!/bin/sh\n"
            "# Opened by TrustLine debug mode. Close this window to stop watching.\n"
            f"cd {shlex.quote(str(DAEMON_DIR))}\n"
            f"exec {python} {run} --state-dir {shlex.quote(str(state_dir))} "
            f"debug-console --api-port {int(api_port)}\n")


def open_console(state_dir: Path, api_port: int) -> bool:
    """Open a Terminal window running the debug console. macOS only.

    A .command file opens in Terminal through Launch Services, so this works under
    launchd without asking for permission to control Terminal.
    """
    if sys.platform != "darwin":
        return False
    script = Path(state_dir) / "debug-console.command"
    script.write_text(console_script(state_dir, api_port))
    script.chmod(0o700)
    try:
        subprocess.Popen(["/usr/bin/open", "-a", "Terminal", str(script)],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
    except OSError:
        return False
    return True


def fetch_state(api_port: int):
    """The daemon's debug state, or a string saying why it is unavailable."""
    opener = build_opener(ProxyHandler({}))
    try:
        with opener.open(f"http://127.0.0.1:{int(api_port)}/v1/debug/state", timeout=2) as response:
            return json.loads(response.read(1_000_000))
    except HTTPError as error:
        error.close()
        if error.code == 404:
            return "Debug mode is off. Set TRUSTLINE_DEBUG=1 in .env (or use serve --debug) and restart."
        return f"The daemon answered HTTP {error.code}."
    except (URLError, OSError, ValueError):
        return f"The daemon isn't reachable on 127.0.0.1:{int(api_port)}. Is it running?"


def tail(path: Path, count: int) -> list[str]:
    try:
        with Path(path).open("rb") as source:
            source.seek(0, os.SEEK_END)
            size = source.tell()
            source.seek(max(0, size - 200_000))
            lines = source.read().decode("utf-8", "replace").splitlines()
    except OSError:
        return []
    return lines[-count:] if count > 0 else []


def _section(title, width):
    return f"── {title} " + "─" * max(0, width - len(title) - 4)


def render(state, log_lines: list[str], width: int, height: int) -> str:
    """One screen: live state on top, the newest log lines below."""
    out = [_section("TrustLine debug · " + time.strftime("%H:%M:%S"), width)]
    if isinstance(state, str):
        out.append(state)
    else:
        settings = state.get("settings", {})
        out.append("settings  " + "  ".join(f"{k}={_format(v)}" for k, v in settings.items()))
        jev = state.get("jev", {})
        out.append(f"jev       key={'set' if jev.get('api_key_configured') else 'MISSING'}  "
                   f"cooldown={jev.get('cooldown_seconds', 0):.0f}s  cached={jev.get('cache_entries', 0)}  "
                   f"api_pending={state.get('api', {}).get('pending', 0)}")
        for row in jev.get("recent", []):
            out.append(f"  {row['origin']:<40} {row['status']:<12} p={_format(row['probability'])} "
                       f"conf={_format(row['confidence'])} money={row['money_site']} "
                       f"recognized={_format(row['recognized'])} ttl={row['expires_in']}s")
        reviews = state.get("reviews", {})
        out.append(f"reviews   pending={reviews.get('pending', 0)}  kept={reviews.get('total', 0)}")
        for row in reviews.get("recent", []):
            page = "" if row.get("page_probability") is None else f" page_p={_format(row['page_probability'])}"
            out.append(f"  {row['token']} {row['status']:<12} {row['age_seconds']:>4}s {row['url']}{page}")
            if row.get("reason"):
                out.append(f"      {row['reason']}")
    out.append(_section("log · " + str(state.get("debug_log") if isinstance(state, dict) else log_path()), width))
    room = max(3, height - len(out) - 1)
    out.extend(line[:width] for line in log_lines[-room:])
    return "\n".join(line[:width] for line in out)


def run_console(api_port: int, interval: float = 1.0):
    try:
        while True:
            size = shutil.get_terminal_size((120, 40))
            state = fetch_state(api_port)
            path = Path(state["debug_log"]) if isinstance(state, dict) and state.get("debug_log") else log_path()
            screen = render(state, tail(path, size.lines), size.columns, size.lines)
            sys.stdout.write("\x1b[H\x1b[2J" + screen + "\n")
            sys.stdout.flush()
            time.sleep(interval)
    except KeyboardInterrupt:
        print()
