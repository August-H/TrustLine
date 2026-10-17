#!/usr/bin/env python3
"""Generate a user LaunchAgent for the local inspection proxy."""

import argparse
import os
from pathlib import Path
import plistlib
import shlex
import sys


def install(home: Path, python: Path, runner: Path, port: int = 8899) -> dict[str, Path]:
    if not 1 <= port <= 65535:
        raise ValueError("Port must be between 1 and 65535")
    state = home / "Library/Application Support/TrustLine"
    logs = home / "Library/Logs/TrustLine"
    agents = home / "Library/LaunchAgents"
    for directory in (state, logs, agents):
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    state.chmod(0o700)
    logs.chmod(0o700)
    agent = agents / "com.trustline.daemon.plist"
    # Preserve the venv executable path; resolve() would select its base Python.
    agent.write_bytes(plistlib.dumps({
        "Label": "com.trustline.daemon",
        "ProgramArguments": [str(python), str(runner), "--state-dir", str(state), "serve", "--port", str(port)],
        "RunAtLoad": True,
        "KeepAlive": True,
        "ThrottleInterval": 10,
        "StandardOutPath": str(logs / "daemon.log"),
        "StandardErrorPath": str(logs / "daemon.error.log"),
        "ProcessType": "Background",
        "Umask": 0o077,
    }))
    agent.chmod(0o600)
    return {"state": state, "agent": agent, "logs": logs}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8899)
    parser.add_argument("--home", type=Path, default=Path.home(), help="Override home for staging/tests")
    args = parser.parse_args()
    if sys.platform != "darwin":
        parser.error("The installer supports macOS only")
    os.umask(0o077)
    try:
        paths = install(args.home.expanduser().resolve(), Path(sys.executable).absolute(),
                        Path(__file__).resolve().parents[1] / "run.py", args.port)
    except (OSError, ValueError) as error:
        parser.error(str(error))
    print("Created LaunchAgent. No service, browser, proxy setting, or certificate trust was changed.")
    print("Start with:")
    print(f"launchctl bootstrap gui/{os.getuid()} {shlex.quote(str(paths['agent']))}")
    print(f"Console output: {paths['logs'] / 'daemon.log'}")


if __name__ == "__main__":
    main()
