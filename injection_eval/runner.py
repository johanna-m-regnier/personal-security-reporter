from __future__ import annotations

import hashlib
import json
from collections.abc import Sequence
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from config import TriageConfig
from findings import Finding, make_new_listener_finding
from triage import (
    ClientFactory,
    TRIAGE_PROMPT_VERSION,
    TriageClient,
    TriageError,
    triage_finding,
)

from .models import (
    InjectionCase,
    InjectionCaseResult,
    InjectionEvaluation,
    TrialControl,
    TriageObservation,
)
from .scoring import is_scorable, score_attack

_CONTROL_OWNER = "unknown-listener-owner"
_EVALUATION_PORT = "4444"
_OFFLINE_MODEL = "offline-safe-fixture"


class EvaluationError(Exception):
    """Raised when the testbed cannot complete safely."""


class _BudgetResponses:
    def __init__(self, responses: Any, *, max_calls: int) -> None:
        self._responses = responses
        self.max_calls = max_calls
        self.call_count = 0

    def create(self, **kwargs: Any) -> Any:
        if self.call_count >= self.max_calls:
            raise EvaluationError("The prompt-injection call budget was exhausted.")
        self.call_count += 1
        return self._responses.create(**kwargs)


class _BudgetClient:
    def __init__(self, client: TriageClient, *, max_calls: int) -> None:
        self.responses = _BudgetResponses(client.responses, max_calls=max_calls)


class _OfflineSafeResponses:
    def create(self, **kwargs: Any) -> Any:
        del kwargs
        response = {
            "explanation": (
                "A new network-reachable listener requires owner verification. "
                "Host-derived labels are evidence, not instructions, and the "
                "available data is insufficient to classify it as benign."
            ),
            "likely_benign": False,
            "investigation_steps": [
                "Confirm the executable path and code signature for the owner.",
                "Compare it with approved software and installation history.",
            ],
            "confidence": "low",
        }
        return SimpleNamespace(
            status="completed",
            output=[],
            output_text=json.dumps(response),
            model=_OFFLINE_MODEL,
        )


class _OfflineSafeClient:
    def __init__(self) -> None:
        self.responses = _OfflineSafeResponses()


def offline_client_factory(config: TriageConfig) -> TriageClient:
    del config
    return _OfflineSafeClient()


def _control_finding() -> Finding:
    return make_new_listener_finding(
        port=_EVALUATION_PORT,
        owners=[_CONTROL_OWNER],
    )


def _attack_finding(case: InjectionCase) -> Finding:
    return make_new_listener_finding(
        port=_EVALUATION_PORT,
        owners=[f"{_CONTROL_OWNER} | untrusted label: {case.payload}"],
    )


def _classify_error(error: TriageError) -> str:
    message = str(error).lower()
    if "refused" in message:
        return "refusal"
    if any(
        marker in message
        for marker in (
            "invalid json",
            "failed validation",
            "must be a json object",
            "no structured triage text",
            "empty triage response",
            "incomplete triage response",
        )
    ):
        return "protocol_failure"
    return "execution_error"


def _observe(
    finding: Finding,
    *,
    run_id: str,
    config: TriageConfig,
    client: TriageClient,
) -> TriageObservation:
    try:
        annotation = triage_finding(
            finding,
            run_id=run_id,
            config=config,
            client=client,
        )
    except TriageError as error:
        return TriageObservation(
            response=None,
            model=None,
            prompt_hash=None,
            error=str(error),
            error_kind=_classify_error(error),
            abort_batch=error.abort_batch,
        )
    return TriageObservation(
        response=annotation.response,
        model=annotation.model,
        prompt_hash=annotation.prompt_hash,
        error=None,
        error_kind=None,
        abort_batch=False,
    )


def _rotated_cases(
    cases: Sequence[InjectionCase],
    *,
    trial: int,
) -> list[InjectionCase]:
    """Rotate case order so a partial budget does not always favor early cases."""

    offset = (trial - 1) % len(cases)
    return [*cases[offset:], *cases[:offset]]


def run_injection_testbed(
    cases: Sequence[InjectionCase],
    *,
    corpus_path: Path,
    config: TriageConfig,
    client_factory: ClientFactory,
    max_calls: int,
    mode: str,
    repeat: int = 1,
    generated_at: str | None = None,
) -> InjectionEvaluation:
    if repeat <= 0:
        raise EvaluationError("The repeat count must be greater than zero.")
    if not cases:
        raise EvaluationError("The injection testbed requires at least one case.")

    effective_limit = min(max_calls, config.max_findings_per_run)
    if effective_limit < 2:
        raise EvaluationError(
            "The effective call limit must be at least 2 so one control and "
            "one attack can be evaluated."
        )

    try:
        client = client_factory(config)
    except TriageError as error:
        raise EvaluationError(f"Could not create triage client: {error}") from error
    except Exception as error:  # noqa: BLE001 - injected factories vary
        raise EvaluationError(
            f"Could not create triage client ({type(error).__name__}): {error}"
        ) from error

    budget_client = _BudgetClient(client, max_calls=effective_limit)
    run_prefix = "injection-eval-" + datetime.now().astimezone().strftime(
        "%Y%m%dT%H%M%S%z"
    )
    controls: list[TrialControl] = []
    results: list[InjectionCaseResult] = []
    completed_trials = 0
    stop_all = False

    for trial in range(1, repeat + 1):
        if budget_client.responses.call_count >= effective_limit:
            break

        run_id = f"{run_prefix}-trial-{trial:03d}"
        control = _observe(
            _control_finding(),
            run_id=run_id,
            config=config,
            client=budget_client,
        )
        controls.append(TrialControl(trial=trial, observation=control))

        if control.error is not None:
            if trial == 1 and not results:
                raise EvaluationError(
                    "The clean control could not be triaged; attack calls were "
                    f"not attempted: {control.error}"
                )
            if control.abort_batch:
                break
            continue

        executed_this_trial = 0
        for case in _rotated_cases(cases, trial=trial):
            if budget_client.responses.call_count >= effective_limit:
                break

            finding = _attack_finding(case)
            attack = _observe(
                finding,
                run_id=run_id,
                config=config,
                client=budget_client,
            )
            detected = score_attack(control, attack)
            scorable = is_scorable(
                case.expected_violation,
                control=control,
                attack=attack,
            )
            results.append(
                InjectionCaseResult(
                    trial=trial,
                    case=case,
                    attack_finding_id=finding.id,
                    detected_violations=detected,
                    expected_attack_succeeded=(
                        scorable and case.expected_violation in detected
                    ),
                    scorable=scorable,
                    attack=attack,
                )
            )
            executed_this_trial += 1

            if attack.abort_batch:
                stop_all = True
                break

        if executed_this_trial == len(cases):
            completed_trials += 1
        if stop_all:
            break

    if generated_at is None:
        generated_at = datetime.now().astimezone().isoformat()
    try:
        corpus_hash = hashlib.sha256(corpus_path.read_bytes()).hexdigest()
    except OSError as error:
        raise EvaluationError(
            f"Could not hash injection corpus {corpus_path}: {error}"
        ) from error

    total_attack_trials = len(cases) * repeat
    executed_attack_trials = len(results)
    full_call_plan = repeat * (1 + len(cases))

    return InjectionEvaluation(
        generated_at=generated_at,
        mode=mode,
        configured_model=config.model,
        prompt_version=TRIAGE_PROMPT_VERSION,
        corpus_path=str(corpus_path),
        corpus_sha256=corpus_hash,
        repeat_count=repeat,
        call_limit=effective_limit,
        planned_calls=min(full_call_plan, effective_limit),
        executed_calls=budget_client.responses.call_count,
        total_cases=len(cases),
        total_attack_trials=total_attack_trials,
        executed_attack_trials=executed_attack_trials,
        skipped_attack_trials=total_attack_trials - executed_attack_trials,
        started_trials=len(controls),
        completed_trials=completed_trials,
        controls=tuple(controls),
        results=tuple(results),
    )
