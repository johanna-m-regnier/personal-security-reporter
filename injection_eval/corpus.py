from __future__ import annotations

import json
from pathlib import Path

from .models import InjectionCase
from .scoring import VIOLATION_TYPES

DEFAULT_CORPUS_PATH = (
    Path(__file__).resolve().parents[1]
    / "tests"
    / "fixtures"
    / "injection_corpus.json"
)


class CorpusError(Exception):
    """Raised when the prompt-injection corpus is malformed."""


def load_injection_corpus(path: Path) -> list[InjectionCase]:
    try:
        raw_text = path.read_text(encoding="utf-8")
    except OSError as error:
        raise CorpusError(f"Could not read injection corpus {path}: {error}") from error

    try:
        raw_data = json.loads(raw_text)
    except json.JSONDecodeError as error:
        raise CorpusError(f"Injection corpus is not valid JSON: {error}") from error

    if not isinstance(raw_data, list):
        raise CorpusError("Injection corpus root must be a JSON array.")

    required = {"id", "technique", "payload", "expected_violation"}
    cases: list[InjectionCase] = []
    seen_ids: set[str] = set()

    for index, raw_case in enumerate(raw_data, start=1):
        if not isinstance(raw_case, dict):
            raise CorpusError(f"Corpus entry {index} must be an object.")

        actual = set(raw_case)
        if actual != required:
            missing = sorted(required - actual)
            extra = sorted(actual - required)
            raise CorpusError(
                f"Corpus entry {index} has invalid keys. "
                f"Missing: {missing or 'none'}; extra: {extra or 'none'}."
            )

        normalized: dict[str, str] = {}
        for key in required:
            value = raw_case[key]
            if not isinstance(value, str):
                raise CorpusError(
                    f"Corpus entry {index} field {key!r} must be a string."
                )
            value = value.strip()
            if not value:
                raise CorpusError(
                    f"Corpus entry {index} field {key!r} cannot be empty."
                )
            normalized[key] = value

        case_id = normalized["id"]
        if case_id in seen_ids:
            raise CorpusError(f"Duplicate injection case id: {case_id}")

        expected = normalized["expected_violation"]
        if expected not in VIOLATION_TYPES:
            raise CorpusError(
                f"Unknown expected_violation {expected!r} in case {case_id}."
            )

        seen_ids.add(case_id)
        cases.append(
            InjectionCase(
                id=case_id,
                technique=normalized["technique"],
                payload=normalized["payload"],
                expected_violation=expected,
            )
        )

    if not cases:
        raise CorpusError("Injection corpus must contain at least one case.")
    return cases
