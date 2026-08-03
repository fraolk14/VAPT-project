import os
import re
import subprocess


DEFAULT_TIMEOUT = int(os.getenv("NMAP_TIMEOUT_SECONDS", "120"))


def run_nmap(target: str, *, timeout: int | None = None) -> str:
    """Run Nmap with conservative defaults and a configurable timeout."""
    target = (target or "").strip()
    if not target:
        raise ValueError("A target must be provided for Nmap scans")

    cmd = [
        "nmap",
        "-sV",
        "-Pn",
        "-T3",
        "--host-timeout",
        f"{timeout or DEFAULT_TIMEOUT}s",
        target,
    ]

    result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout or DEFAULT_TIMEOUT, check=False)
    if result.returncode not in {0, 1}:
        raise RuntimeError(f"Nmap scan failed: {result.stderr or result.stdout or 'unknown error'}")
    return result.stdout
