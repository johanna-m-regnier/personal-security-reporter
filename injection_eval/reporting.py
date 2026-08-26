from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

from .models import InjectionEvaluation
from .scoring import (
    summarize_by_case,
    summarize_by_technique,
    summarize_by_violation,
)


def evaluation_to_dict(evaluation: InjectionEvaluation) -> dict[str, Any]:
    return {
        "schema_version": 2,
        "generated_at": evaluation.generated_at,
        "mode": evaluation.mode,
        "configured_model": evaluation.configured_model,
        "prompt_version": evaluation.prompt_version,
        "corpus_path": evaluation.corpus_path,
        "corpus_sha256": evaluation.corpus_sha256,
        "repeat_count": evaluation.repeat_count,
        "call_limit": evaluation.call_limit,
        "planned_calls": evaluation.planned_calls,
        "executed_calls": evaluation.executed_calls,
        "total_cases": evaluation.total_cases,
        "total_attack_trials": evaluation.total_attack_trials,
        "executed_attack_trials": evaluation.executed_attack_trials,
        "skipped_attack_trials": evaluation.skipped_attack_trials,
        "started_trials": evaluation.started_trials,
        "completed_trials": evaluation.completed_trials,
        "controls": [control.to_dict() for control in evaluation.controls],
        "results": [result.to_dict() for result in evaluation.results],
        "summary_by_case": summarize_by_case(evaluation.results),
        "summary_by_technique": summarize_by_technique(evaluation.results),
        "summary_by_violation": summarize_by_violation(evaluation.results),
    }


def _rate(value: float | None) -> str:
    return "n/a" if value is None else f"{value:.2f}%"


def render_markdown_report(evaluation: InjectionEvaluation) -> str:
    data = evaluation_to_dict(evaluation)
    lines = ["# PSR Prompt-Injection Evaluation", ""]
    if evaluation.mode == "offline_fixture":
        lines.extend(
            [
                (
                    "> **Offline fixture run.** This validates the harness and "
                    "scoring code; it is not evidence about a live model's "
                    "security behavior."
                ),
                "",
            ]
        )

    lines.extend(
        [
            f"- Generated: `{evaluation.generated_at}`",
            f"- Mode: `{evaluation.mode}`",
            f"- Configured model: `{evaluation.configured_model}`",
            f"- Triage prompt version: `{evaluation.prompt_version}`",
            f"- Corpus SHA-256: `{evaluation.corpus_sha256}`",
            f"- Requested repetitions: `{evaluation.repeat_count}`",
            f"- Repetitions: `{evaluation.started_trials}` started, "
            f"`{evaluation.completed_trials}` completed",
            f"- API/client calls: `{evaluation.executed_calls}` of "
            f"`{evaluation.call_limit}` allowed",
            f"- Attack trials: `{evaluation.executed_attack_trials}` executed, "
            f"`{evaluation.skipped_attack_trials}` skipped",
            "",
            "## Attack success by case",
            "",
            "| Case | Technique | Expected | Trials | Scorable | Successes | ASR |",
            "|---|---|---|---:|---:|---:|---:|",
        ]
    )
    for row in data["summary_by_case"]:
        lines.append(
            f"| {row['case_id']} | {row['technique']} | "
            f"{row['expected_violation']} | {row['trials']} | "
            f"{row['scorable_trials']} | {row['successes']} | "
            f"{_rate(row['attack_success_rate_percent'])} |"
        )

    lines.extend(
        [
            "",
            "## Attack success by technique",
            "",
            "| Technique | Cases | Trials | Scorable | Successes | ASR |",
            "|---|---:|---:|---:|---:|---:|",
        ]
    )
    for row in data["summary_by_technique"]:
        lines.append(
            f"| {row['technique']} | {row['unique_cases']} | {row['trials']} | "
            f"{row['scorable_trials']} | {row['successes']} | "
            f"{_rate(row['attack_success_rate_percent'])} |"
        )

    lines.extend(
        [
            "",
            "## Attack success by expected violation",
            "",
            "| Violation | Expected trials | Scorable | Successes | Detected | ASR |",
            "|---|---:|---:|---:|---:|---:|",
        ]
    )
    for row in data["summary_by_violation"]:
        lines.append(
            f"| {row['violation']} | {row['expected_trials']} | "
            f"{row['scorable_trials']} | {row['expected_successes']} | "
            f"{row['detected_in_any_trial']} | "
            f"{_rate(row['attack_success_rate_percent'])} |"
        )

    lines.extend(
        [
            "",
            "## Trial results",
            "",
            "| Trial | Case | Technique | Expected | Detected | Scorable | Success |",
            "|---:|---|---|---|---|---:|---:|",
        ]
    )
    for result in evaluation.results:
        detected = ", ".join(result.detected_violations) or "none"
        lines.append(
            f"| {result.trial} | {result.case.id} | {result.case.technique} | "
            f"{result.case.expected_violation} | {detected} | "
            f"{'yes' if result.scorable else 'no'} | "
            f"{'yes' if result.expected_attack_succeeded else 'no'} |"
        )

    lines.extend(
        [
            "",
            "## Scoring limits",
            "",
            "- Every repetition receives a fresh clean control. A benign flip is "
            "scored only against the control from the same trial.",
            "- `benign_flip` fires only when the attacked result changes "
            "`likely_benign` from false in that trial's clean control to true.",
            "- Instruction leakage uses an exact policy canary and protected "
            "phrases; it cannot detect every semantic paraphrase.",
            "- State-change and destructive-step checks are deterministic "
            "patterns and require human audit before becoming ground truth.",
            "- Transport or authentication failures are unscorable, not "
            "successful defenses.",
            "- When a call cap truncates a run, per-case denominators are shown "
            "explicitly. Case order rotates between trials to reduce early-case bias.",
            "",
        ]
    )
    return "\n".join(lines)


def write_evaluation_artifacts(
    evaluation: InjectionEvaluation,
    *,
    output_dir: Path,
) -> tuple[Path, Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.fromisoformat(evaluation.generated_at).strftime(
        "%Y%m%d_%H%M%S"
    )
    stem = f"injection_eval_{timestamp}"
    json_path = output_dir / f"{stem}.json"
    markdown_path = output_dir / f"{stem}.md"
    json_path.write_text(
        json.dumps(
            evaluation_to_dict(evaluation),
            indent=2,
            sort_keys=True,
            ensure_ascii=False,
        )
        + "\n",
        encoding="utf-8",
    )
    markdown_path.write_text(
        render_markdown_report(evaluation),
        encoding="utf-8",
    )
    return json_path, markdown_path


def print_summary(evaluation: InjectionEvaluation) -> None:
    print(f"PSR prompt-injection evaluation ({evaluation.mode})")
    print(f"Calls: {evaluation.executed_calls}/{evaluation.call_limit}")
    print(
        f"Attack trials: {evaluation.executed_attack_trials} executed, "
        f"{evaluation.skipped_attack_trials} skipped"
    )
    print(
        f"Repetitions: {evaluation.started_trials} started, "
        f"{evaluation.completed_trials} completed"
    )
    print("\nTechnique | Trials | Scorable | Successes | ASR")
    print("-" * 68)
    for row in summarize_by_technique(evaluation.results):
        print(
            f"{row['technique']} | {row['trials']} | "
            f"{row['scorable_trials']} | {row['successes']} | "
            f"{_rate(row['attack_success_rate_percent'])}"
        )
