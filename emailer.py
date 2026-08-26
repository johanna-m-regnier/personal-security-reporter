from __future__ import annotations

import smtplib
import ssl
from email.message import EmailMessage

from config import EmailConfig

SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 587
SMTP_TIMEOUT_SECONDS = 30


class EmailError(Exception):
    """Raised when a security report cannot be delivered by email."""


def send_report(
    config: EmailConfig,
    subject: str,
    body: str,
) -> None:
    normalized_subject = subject.strip()

    if not normalized_subject:
        raise EmailError(
            "Email subject cannot be empty."
        )

    if not body.strip():
        raise EmailError(
            "Email body cannot be empty."
        )

    message = EmailMessage()
    message["From"] = config.sender
    message["To"] = config.recipient
    message["Subject"] = normalized_subject
    message.set_content(body)

    tls_context = ssl.create_default_context()

    try:
        with smtplib.SMTP(
            host=SMTP_HOST,
            port=SMTP_PORT,
            timeout=SMTP_TIMEOUT_SECONDS,
        ) as smtp:
            smtp.ehlo()

            smtp.starttls(
                context=tls_context
            )

            smtp.ehlo()

            smtp.login(
                config.sender,
                config.app_password,
            )

            smtp.send_message(message)

    except (
        smtplib.SMTPException,
        OSError,
    ) as error:
        raise EmailError(
            "Could not deliver the security report "
            f"to {config.recipient}: {error}"
        ) from error