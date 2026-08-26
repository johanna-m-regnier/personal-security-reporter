from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from findings import Finding

TRIAGE_CONFIDENCE_LEVELS = frozenset(
    {
        "low",
        "medium",
        "high",
    }
)

TRIAGE_VERDICTS = frozenset(
    {
        "accurate",
        "wrong",
        "unsure",
    }
)


@dataclass(frozen=True)
class ListenerRecord:
    command: str
    pid: int | None
    user: str | None
    address: str
    port: str
    family: str
    is_loopback: bool


@dataclass(frozen=True)
class ProcessRecord:
    pid: int
    executable: str
    display_name: str
    cpu_percent: float
    mem_percent: float


@dataclass(frozen=True)
class DiskInfo:
    mount: str
    total_gb: float
    used_gb: float
    free_gb: float
    percent_used: float


@dataclass
class ListenerSummary:
    records: list[ListenerRecord]
    socket_count: int
    network_ports: list[str]
    local_only_ports: list[str]
    network_port_owners: dict[str, list[str]]
    local_only_port_owners: dict[str, list[str]]


@dataclass
class HostState:
    computer_name: str
    operating_system: str
    platform_system: str
    current_user: str
    uptime_text: str
    process_count: int
    top_processes: list[ProcessRecord]
    disk: DiskInfo | None
    listeners: ListenerSummary | None


@dataclass(frozen=True)
class TriageResponse:
    explanation: str
    likely_benign: bool
    investigation_steps: tuple[str, ...]
    confidence: str

    @classmethod
    def from_dict(
        cls,
        data: dict[str, Any],
    ) -> TriageResponse:
        expected_keys = {
            "explanation",
            "likely_benign",
            "investigation_steps",
            "confidence",
        }

        if set(data) != expected_keys:
            missing = sorted(expected_keys - set(data))
            unexpected = sorted(set(data) - expected_keys)
            problems: list[str] = []

            if missing:
                problems.append(
                    "missing keys: "
                    f"{', '.join(missing)}"
                )

            if unexpected:
                problems.append(
                    "unexpected keys: "
                    f"{', '.join(unexpected)}"
                )

            raise ValueError(
                "Invalid triage response structure ("
                f"{'; '.join(problems)})."
            )

        explanation_value = data["explanation"]

        if not isinstance(explanation_value, str):
            raise TypeError(
                "Triage field 'explanation' must be a string."
            )

        explanation = explanation_value.strip()

        if not explanation:
            raise ValueError(
                "Triage field 'explanation' cannot be empty."
            )

        likely_benign = data["likely_benign"]

        if type(likely_benign) is not bool:
            raise TypeError(
                "Triage field 'likely_benign' must be a boolean."
            )

        raw_steps = data["investigation_steps"]

        if not isinstance(raw_steps, list):
            raise TypeError(
                "Triage field 'investigation_steps' must be a list."
            )

        investigation_steps: list[str] = []

        for index, raw_step in enumerate(raw_steps):
            if not isinstance(raw_step, str):
                raise TypeError(
                    "Triage investigation step "
                    f"{index + 1} must be a string."
                )

            step = raw_step.strip()

            if not step:
                raise ValueError(
                    "Triage investigation steps cannot be empty."
                )

            investigation_steps.append(step)

        if not investigation_steps:
            raise ValueError(
                "Triage field 'investigation_steps' must contain "
                "at least one step."
            )

        if len(investigation_steps) > 8:
            raise ValueError(
                "Triage field 'investigation_steps' cannot contain "
                "more than eight steps."
            )

        confidence_value = data["confidence"]

        if not isinstance(confidence_value, str):
            raise TypeError(
                "Triage field 'confidence' must be a string."
            )

        confidence = confidence_value.strip().lower()

        if confidence not in TRIAGE_CONFIDENCE_LEVELS:
            raise ValueError(
                "Triage field 'confidence' must be "
                "low, medium, or high."
            )

        return cls(
            explanation=explanation,
            likely_benign=likely_benign,
            investigation_steps=tuple(
                investigation_steps
            ),
            confidence=confidence,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "explanation": self.explanation,
            "likely_benign": self.likely_benign,
            "investigation_steps": list(
                self.investigation_steps
            ),
            "confidence": self.confidence,
        }


@dataclass(frozen=True)
class TriageAnnotation:
    finding_id: str
    run_id: str
    model: str
    prompt_hash: str
    response: TriageResponse
    created_at: str
    human_verdict: str | None = None
    verdict_at: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "run_id": self.run_id,
            "model": self.model,
            "prompt_hash": self.prompt_hash,
            "response": self.response.to_dict(),
            "created_at": self.created_at,
            "human_verdict": self.human_verdict,
            "verdict_at": self.verdict_at,
        }


@dataclass
class ReportContext:
    report_time_local: str
    report_time_iso: str
    run_id: str
    host: HostState
    findings: list[Finding]
    summary: dict[str, Any]
    baseline_status: str
    new_network_ports: list[str]
    removed_network_ports: list[str]
    comparison_performed: bool
    missed_runs: list[dict[str, Any]]
    triage_annotations: dict[str, TriageAnnotation]
    triage_errors: dict[str, str]
    triage_eligible_count: int
    triage_cache_hits: int
    triage_api_calls: int
    triage_limit_skipped_count: int
