from __future__ import annotations

from dataclasses import replace
from typing import Any

from findings import (
    Finding,
    Severity,
    make_disk_finding,
    make_new_listener_finding,
    make_no_changes_finding,
    make_removed_listener_finding,
    make_service_moved_finding,
)
from models import DiskInfo

DISK_WARNING_THRESHOLD = 80.0
DISK_CRITICAL_THRESHOLD = 90.0

_ACKNOWLEDGED_MARKER = "(acknowledged)"
_UNKNOWN_PROCESS = "Unknown process"


def analyze_disk_usage(
    disk: DiskInfo,
) -> Finding:
    if disk.percent_used >= DISK_CRITICAL_THRESHOLD:
        severity = Severity.CRITICAL
    elif disk.percent_used >= DISK_WARNING_THRESHOLD:
        severity = Severity.WARNING
    else:
        severity = Severity.INFO

    return make_disk_finding(
        mount=disk.mount,
        percent_used=disk.percent_used,
        band=severity,
    )


def compare_ports(
    current_ports: list[str],
    baseline_ports: list[str],
) -> dict[str, list[str]]:
    current_set = set(current_ports)
    baseline_set = set(baseline_ports)

    new_ports = sorted(
        current_set - baseline_set,
        key=int,
    )

    removed_ports = sorted(
        baseline_set - current_set,
        key=int,
    )

    return {
        "new_ports": new_ports,
        "removed_ports": removed_ports,
    }


def _normalize_owners(
    owners: list[str] | None,
) -> tuple[str, ...]:
    normalized = sorted(
        {
            owner.strip()
            for owner in (owners or [])
            if owner.strip()
        }
    )

    if not normalized:
        return (_UNKNOWN_PROCESS,)

    return tuple(normalized)


def _owners_support_move_match(
    current_owners: tuple[str, ...],
    baseline_owners: tuple[str, ...],
) -> bool:
    if current_owners != baseline_owners:
        return False

    # "Unknown process" is not a meaningful process identity.
    # Matching unknown to unknown could hide a genuinely new listener,
    # so uncertain ownership fails toward reporting.
    return current_owners != (_UNKNOWN_PROCESS,)


def analyze_network_port_changes(
    new_ports: list[str],
    removed_ports: list[str],
    current_port_owners: dict[str, list[str]],
    baseline_port_owners: dict[str, list[str]],
) -> list[Finding]:
    findings: list[Finding] = []

    matched_new_ports: set[str] = set()
    matched_removed_ports: set[str] = set()

    for new_port in new_ports:
        current_owners = _normalize_owners(
            current_port_owners.get(new_port)
        )

        for removed_port in removed_ports:
            # A removed port can explain only one new port.
            # Without this check, two new ports owned by the same command
            # could both claim the same removed port as their origin.
            if removed_port in matched_removed_ports:
                continue

            baseline_owners = _normalize_owners(
                baseline_port_owners.get(
                    removed_port
                )
            )

            if not _owners_support_move_match(
                current_owners=current_owners,
                baseline_owners=baseline_owners,
            ):
                continue

            findings.append(
                make_service_moved_finding(
                    from_port=removed_port,
                    to_port=new_port,
                    owners=list(current_owners),
                )
            )

            matched_new_ports.add(new_port)
            matched_removed_ports.add(
                removed_port
            )
            break

    for new_port in new_ports:
        if new_port in matched_new_ports:
            continue

        owners = _normalize_owners(
            current_port_owners.get(new_port)
        )

        findings.append(
            make_new_listener_finding(
                port=new_port,
                owners=list(owners),
            )
        )

    for removed_port in removed_ports:
        if removed_port in matched_removed_ports:
            continue

        owners = _normalize_owners(
            baseline_port_owners.get(
                removed_port
            )
        )

        findings.append(
            make_removed_listener_finding(
                port=removed_port,
                owners=list(owners),
            )
        )

    if not findings:
        findings.append(
            make_no_changes_finding()
        )

    return findings


def apply_acknowledgements(
    findings: list[Finding],
    acknowledged_ids: set[str],
) -> list[Finding]:
    updated_findings: list[Finding] = []

    for finding in findings:
        if finding.id not in acknowledged_ids:
            updated_findings.append(finding)
            continue

        if finding.message.endswith(
            _ACKNOWLEDGED_MARKER
        ):
            acknowledged_message = finding.message
        else:
            acknowledged_message = (
                f"{finding.message} "
                f"{_ACKNOWLEDGED_MARKER}"
            )

        acknowledged_finding = replace(
            finding,
            severity=Severity.INFO,
            message=acknowledged_message,
            acknowledged=True,
        )

        updated_findings.append(
            acknowledged_finding
        )

    return updated_findings


def summarize_findings(
    findings: list[Finding],
) -> dict[str, Any]:
    critical_count = sum(
        finding.severity == Severity.CRITICAL
        for finding in findings
    )

    warning_count = sum(
        finding.severity == Severity.WARNING
        for finding in findings
    )

    info_count = sum(
        finding.severity == Severity.INFO
        for finding in findings
    )

    if critical_count > 0:
        overall_status = Severity.CRITICAL
    elif warning_count > 0:
        overall_status = Severity.WARNING
    else:
        overall_status = Severity.INFO

    return {
        "overall_status": overall_status,
        "critical_count": critical_count,
        "warning_count": warning_count,
        "info_count": info_count,
        "total_count": len(findings),
    }