from __future__ import annotations

import os
import smtplib
from email.message import EmailMessage


SMTP_HOST = os.getenv("SMTP_HOST", "mailpit")
SMTP_PORT = int(os.getenv("SMTP_PORT", "1025"))
SMTP_USERNAME = os.getenv("SMTP_USERNAME", "")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "")
SMTP_USE_TLS = os.getenv("SMTP_USE_TLS", "false").lower() == "true"
EMAIL_FROM = os.getenv("EMAIL_FROM", "noreply@vap.local")
PLATFORM_NAME = os.getenv("PLATFORM_NAME", "VAP")


def email_config_status() -> dict[str, str | bool | int]:
    return {
        "host": SMTP_HOST,
        "port": SMTP_PORT,
        "from_address": EMAIL_FROM,
        "tls": SMTP_USE_TLS,
        "configured": bool(SMTP_HOST and EMAIL_FROM),
    }


def send_email(*, to_address: str, subject: str, body: str) -> None:
    if not to_address:
        return
    message = EmailMessage()
    message["From"] = EMAIL_FROM
    message["To"] = to_address
    message["Subject"] = subject
    message.set_content(body)

    with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=20) as server:
        if SMTP_USE_TLS:
            server.starttls()
        if SMTP_USERNAME:
            server.login(SMTP_USERNAME, SMTP_PASSWORD)
        server.send_message(message)


def send_welcome_email(*, email: str, username: str, role: str, temporary_password: str) -> None:
    send_email(
        to_address=email,
        subject=f"{PLATFORM_NAME} account created",
        body=(
            f"Hello {username},\n\n"
            f"Your {PLATFORM_NAME} account has been created.\n"
            f"Role: {role}\n"
            f"Temporary password: {temporary_password}\n\n"
            "Sign in and rotate your password as soon as possible.\n"
        ),
    )


def send_finding_assignment_email(*, email: str, username: str, finding_title: str, severity: str, target: str, details: str) -> None:
    send_email(
        to_address=email,
        subject=f"{PLATFORM_NAME} finding assigned: {finding_title}",
        body=(
            f"Hello {username},\n\n"
            "A finding has been assigned to you.\n\n"
            f"Title: {finding_title}\n"
            f"Severity: {severity}\n"
            f"Target: {target}\n"
            f"Details: {details}\n\n"
            "Please review the platform for remediation and validation actions.\n"
        ),
    )


def send_email_mfa_code(*, email: str, username: str, code: str) -> None:
    send_email(
        to_address=email,
        subject=f"{PLATFORM_NAME} sign-in verification code",
        body=(
            f"Hello {username},\n\n"
            f"Your {PLATFORM_NAME} email verification code is: {code}\n\n"
            "This code expires in 10 minutes.\n"
            "If you did not attempt to sign in, ignore this message.\n"
        ),
    )
