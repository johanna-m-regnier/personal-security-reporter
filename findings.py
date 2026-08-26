from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

KIND_NEW_LISTENER = "new_listener"
KIND_REMOVED_LISTENER = "removed_listener"
KIND_SERVICE_MOVED = "service_moved"
KIND_DISK_USAGE = "disk_usage"
KIND_COLLECTOR_ERROR = "collector_error"
KIND_NO_CHANGES = "no_changes"
KIND_FIRST_RUN = "first_run"
KIND_HOST_MISMATCH = "host_mismatch"

FINDING_KINDS = frozenset(
    {
        KIND_NEW_LISTENER,
        KIND_REMOVED_LISTENER,
        KIND_SERVICE_MOVED,
        KIND_DISK_USAGE,
        KIND_COLLECTOR_ERROR,
        KIND_NO_CHANGES,
        KIND_FIRST_RUN,
        KIND_HOST_MISMATCH,
    }
)


class Severity(str, Enum):
    INFO = "INFO"
    WARNING = "WARNING"
    CRITICAL = "CRITICAL"


@dataclass
class Finding:
    kind: str
    severity: Severity
    message: str
    identity: dict[str, Any]
    details: dict[str, Any]
    id: str = field(default="", init=False)
    remediation: dict[str, Any] | None = None
    verification: dict[str, Any] | None = None
    approval: dict[str, Any] | None = None
    acknowledged: bool = False

    def __post_init__(self) -> None:
        if self.kind not in FINDING_KINDS:
            raise ValueError(f"Unknown finding kind: {self.kind}")

        self.id = compute_finding_id(
            kind=self.kind,
            identity=self.identity,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "kind": self.kind,
            "severity": self.severity.value,
            "message": self.message,
            "identity": dict(self.identity),
            "details": dict(self.details),
            "remediation": self.remediation,
            "verification": self.verification,
            "approval": self.approval,
            "acknowledged": self.acknowledged,
        }


def compute_finding_id(
    kind: str,
    identity: dict[str, Any],
) -> str:
    payload = json.dumps(
        {
            "kind": kind,
            **identity,
        },
        sort_keys=True,
        separators=(",", ":"),
    )

    return hashlib.sha256(
        payload.encode("utf-8")
    ).hexdigest()[:12]


def _normalize_owners(
    owners: list[str],
) -> list[str]:
    normalized = sorted(
        {
            owner.strip()
            for owner in owners
            if owner.strip()
        }
    )

    if normalized:
        return normalized

    return ["Unknown process"]


def make_new_listener_finding(
    port: str,
    owners: list[str],
) -> Finding:
    normalized_owners = _normalize_owners(owners)

    return Finding(
        kind=KIND_NEW_LISTENER,
        severity=Severity.WARNING,
        message=(
            "New network-reachable listener detected on "
            f"port {port}, owned by "
            f"{', '.join(normalized_owners)}."
        ),
        identity={
            "port": port,
            "owners": normalized_owners,
        },
        details={
            "port": port,
            "owners": normalized_owners,
        },
    )


def make_removed_listener_finding(
    port: str,
    owners: list[str],
) -> Finding:
    normalized_owners = _normalize_owners(owners)

    return Finding(
        kind=KIND_REMOVED_LISTENER,
        severity=Severity.INFO,
        message=(
            "A baseline listener is no longer present on "
            f"port {port}. Previous owner: "
            f"{', '.join(normalized_owners)}."
        ),
        identity={
            "port": port,
            "owners": normalized_owners,
        },
        details={
            "port": port,
            "owners": normalized_owners,
        },
    )


def make_service_moved_finding(
    from_port: str,
    to_port: str,
    owners: list[str],
) -> Finding:
    normalized_owners = _normalize_owners(owners)
    owner_text = ", ".join(normalized_owners)

    return Finding(
        kind=KIND_SERVICE_MOVED,
        severity=Severity.INFO,
        message=(
            "A listener with the same command name "
            f"({owner_text}) moved from port "
            f"{from_port} to port {to_port}."
        ),
        identity={
            "from_port": from_port,
            "to_port": to_port,
            "owners": normalized_owners,
        },
        details={
            "from_port": from_port,
            "to_port": to_port,
            "owners": normalized_owners,
            "match_method": "command_name",
            "match_confidence": "heuristic",
        },
    )


def make_disk_finding(
    mount: str,
    percent_used: float,
    band: Severity,
) -> Finding:
    return Finding(
        kind=KIND_DISK_USAGE,
        severity=band,
        message=(
            f"Disk usage on {mount} is "
            f"{percent_used:.2f}%."
        ),
        identity={
            "mount": mount,
            "band": band.value,
        },
        details={
            "mount": mount,
            "percent_used": percent_used,
            "band": band.value,
        },
    )


def make_collector_error_finding(
    collector_name: str,
    error: str,
) -> Finding:
    return Finding(
        kind=KIND_COLLECTOR_ERROR,
        severity=Severity.WARNING,
        message=(
            f"The {collector_name} collector failed. "
            "Some data is unavailable for this run."
        ),
        identity={
            "collector": collector_name,
        },
        details={
            "collector": collector_name,
            "error": error,
        },
    )


def make_no_changes_finding() -> Finding:
    return Finding(
        kind=KIND_NO_CHANGES,
        severity=Severity.INFO,
        message=(
            "No network-reachable listener changes "
            "were detected."
        ),
        identity={},
        details={},
    )


def make_first_run_finding() -> Finding:
    return Finding(
        kind=KIND_FIRST_RUN,
        severity=Severity.INFO,
        message=(
            "No listener baseline existed at the start of "
            "this run. No listener comparison was performed."
        ),
        identity={},
        details={},
    )


def make_host_mismatch_finding(
    expected: str,
    actual: str,
) -> Finding:
    return Finding(
        kind=KIND_HOST_MISMATCH,
        severity=Severity.CRITICAL,
        message=(
            "The stored baseline belongs to a different "
            "computer. Listener comparison was skipped."
        ),
        identity={
            "expected": expected,
            "actual": actual,
        },
        details={
            "expected_computer_name": expected,
            "actual_computer_name": actual,
        },
    )