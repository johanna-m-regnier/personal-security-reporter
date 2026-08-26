from __future__ import annotations

import os
from dataclasses import dataclass

DEFAULT_TRIAGE_MODEL = "gpt-5.6-luna"
DEFAULT_TRIAGE_TIMEOUT_SECONDS = 20.0
DEFAULT_TRIAGE_MAX_FINDINGS_PER_RUN = 10


class ConfigError(Exception):
    """Raised when required application configuration is missing."""


class TriageConfigError(Exception):
    """Raised when optional triage configuration is invalid."""


@dataclass(frozen=True)
class EmailConfig:
    sender: str
    app_password: str
    recipient: str


@dataclass(frozen=True)
class TriageConfig:
    api_key: str | None
    model: str
    timeout_seconds: float
    max_findings_per_run: int


def load_email_config() -> EmailConfig:
    sender = (os.getenv("REPORT_EMAIL") or "").strip()
    app_password = (
        os.getenv("REPORT_APP_PASSWORD") or ""
    ).strip()

    missing_variables: list[str] = []

    if not sender:
        missing_variables.append("REPORT_EMAIL")

    if not app_password:
        missing_variables.append(
            "REPORT_APP_PASSWORD"
        )

    if missing_variables:
        missing_text = ", ".join(
            missing_variables
        )

        raise ConfigError(
            "Missing required environment variables: "
            f"{missing_text}"
        )

    recipient = (
        os.getenv("REPORT_RECIPIENT") or ""
    ).strip()

    if not recipient:
        recipient = sender

    return EmailConfig(
        sender=sender,
        app_password=app_password,
        recipient=recipient,
    )


def load_triage_config() -> TriageConfig:
    api_key = (
        os.getenv("OPENAI_API_KEY") or ""
    ).strip()

    model = (
        os.getenv("OPENAI_TRIAGE_MODEL")
        or DEFAULT_TRIAGE_MODEL
    ).strip()

    if not model:
        raise TriageConfigError(
            "OPENAI_TRIAGE_MODEL cannot be empty."
        )

    timeout_text = (
        os.getenv("OPENAI_TRIAGE_TIMEOUT_SECONDS")
        or str(DEFAULT_TRIAGE_TIMEOUT_SECONDS)
    ).strip()

    try:
        timeout_seconds = float(timeout_text)
    except ValueError as error:
        raise TriageConfigError(
            "OPENAI_TRIAGE_TIMEOUT_SECONDS must be a number."
        ) from error

    if timeout_seconds <= 0:
        raise TriageConfigError(
            "OPENAI_TRIAGE_TIMEOUT_SECONDS must be greater "
            "than zero."
        )

    max_findings_text = (
        os.getenv("OPENAI_TRIAGE_MAX_FINDINGS_PER_RUN")
        or str(DEFAULT_TRIAGE_MAX_FINDINGS_PER_RUN)
    ).strip()

    try:
        max_findings_per_run = int(max_findings_text)
    except ValueError as error:
        raise TriageConfigError(
            "OPENAI_TRIAGE_MAX_FINDINGS_PER_RUN must be an integer."
        ) from error

    if max_findings_per_run <= 0:
        raise TriageConfigError(
            "OPENAI_TRIAGE_MAX_FINDINGS_PER_RUN must be greater "
            "than zero."
        )

    return TriageConfig(
        api_key=api_key or None,
        model=model,
        timeout_seconds=timeout_seconds,
        max_findings_per_run=max_findings_per_run,
    )
