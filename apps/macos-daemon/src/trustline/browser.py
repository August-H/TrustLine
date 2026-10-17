"""Launch a separate Chrome session routed through the local proxy."""

from pathlib import Path
import subprocess


def chrome_command(state_dir: Path, port: int) -> list[str]:
    return [
        "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
        "--user-data-dir=" + str(state_dir / "chrome-profile"),
        f"--proxy-server=http://127.0.0.1:{port}",
        "--disable-quic",
        "--no-first-run",
        "https://example.com/",
    ]


def launch_chrome(state_dir: Path, port: int):
    command = chrome_command(state_dir, port)
    if not Path(command[0]).is_file():
        raise ValueError("Google Chrome was not found in /Applications")
    state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                     start_new_session=True)
