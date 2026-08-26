from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from models import TriageResponse


@dataclass(frozen=True)
class InjectionCase:
    id: str
    technique: str
    payload: str
    expected_violation: str

    def to_dict(self) -> dict[str, str]:
        return {
            "id": self.id,
            "technique": self.technique,
            "payload": self.payload,
            "expected_violation": self.expected_violation,
        }


@dataclass(frozen=True)
class TriageObservation:
    response: TriageResponse | None
    model: str | None
    prompt_hash: str | None
    error: str | None
    error_kind: str | None
    abort_batch: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "response": self.response.to_dict() if self.response else None,
            "model": self.model,
            "prompt_hash": self.prompt_hash,
            "error": self.error,
            "error_kind": self.error_kind,
            "abort_batch": self.abort_batch,
        }


@dataclass(frozen=True)
class TrialControl:
    trial: int
    observation: TriageObservation

    def to_dict(self) -> dict[str, Any]:
        return {
            "trial": self.trial,
            "observation": self.observation.to_dict(),
        }


@dataclass(frozen=True)
class InjectionCaseResult:
    trial: int
    case: InjectionCase
    attack_finding_id: str
    detected_violations: tuple[str, ...]
    expected_attack_succeeded: bool
    scorable: bool
    attack: TriageObservation

    def to_dict(self) -> dict[str, Any]:
        return {
            "trial": self.trial,
            **self.case.to_dict(),
            "attack_finding_id": self.attack_finding_id,
            "detected_violations": list(self.detected_violations),
            "expected_attack_succeeded": self.expected_attack_succeeded,
            "scorable": self.scorable,
            "attack": self.attack.to_dict(),
        }


@dataclass(frozen=True)
class InjectionEvaluation:
    generated_at: str
    mode: str
    configured_model: str
    prompt_version: int
    corpus_path: str
    corpus_sha256: str
    repeat_count: int
    call_limit: int
    planned_calls: int
    executed_calls: int
    total_cases: int
    total_attack_trials: int
    executed_attack_trials: int
    skipped_attack_trials: int
    started_trials: int
    completed_trials: int
    controls: tuple[TrialControl, ...]
    results: tuple[InjectionCaseResult, ...]
