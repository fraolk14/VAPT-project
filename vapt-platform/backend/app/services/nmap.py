import subprocess


def run_nmap(target: str) -> str:
    """
    Run Nmap scan inside the nmap container and
    return raw stdout output.
    """

    cmd = [
        "docker", "exec", "vapt-nmap",
        "nmap",
        "-sV",          # service/version detection
        "-Pn",          # skip host discovery
        target
    ]

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        check=True
    )

    return result.stdout
