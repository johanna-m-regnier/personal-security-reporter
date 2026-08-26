from __future__ import annotations

from datetime import datetime
from typing import Any

from findings import Finding, Severity
from models import (
    DiskInfo,
    ListenerRecord,
    ListenerSummary,
    ProcessRecord,
    ReportContext,
    TriageAnnotation,
)

REPORT_SCHEMA_VERSION = 2

_SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.WARNING: 1,
    Severity.INFO: 2,
}


def _severity_text(value: Any) -> str:
    if isinstance(value, Severity):
        return value.value

    return str(value)


def _display_timestamp(value: Any) -> str:
    if value is None:
        return "Not completed"

    timestamp_text = str(value).strip()

    if not timestamp_text:
        return "Unknown"

    try:
        parsed = datetime.fromisoformat(
            timestamp_text
        )
    except ValueError:
        return timestamp_text

    if parsed.tzinfo is None:
        parsed = parsed.astimezone()
    else:
        parsed = parsed.astimezone()

    return parsed.strftime(
        "%Y-%m-%d %H:%M:%S %Z"
    )


def _format_port_list(
    ports: list[str],
) -> str:
    if not ports:
        return "None"

    return ", ".join(ports)


def _render_process_table(
    processes: list[ProcessRecord],
) -> list[str]:
    if not processes:
        return ["No process data available."]

    headers = (
        "PID",
        "PROCESS",
        "CPU %",
        "MEM %",
    )

    rows = [
        (
            str(process.pid),
            process.display_name,
            f"{process.cpu_percent:.1f}",
            f"{process.mem_percent:.1f}",
        )
        for process in processes
    ]

    widths = [
        max(
            len(headers[index]),
            max(
                len(row[index])
                for row in rows
            ),
        )
        for index in range(len(headers))
    ]

    header_line = "  ".join(
        headers[index].ljust(widths[index])
        for index in range(len(headers))
    )

    separator_line = "  ".join(
        "-" * widths[index]
        for index in range(len(headers))
    )

    table_lines = [
        header_line,
        separator_line,
    ]

    for row in rows:
        table_lines.append(
            "  ".join(
                row[index].ljust(widths[index])
                for index in range(len(row))
            )
        )

    return table_lines


def _render_listener_table(
    records: list[ListenerRecord],
) -> list[str]:
    if not records:
        return ["None"]

    headers = (
        "COMMAND",
        "PID",
        "USER",
        "ADDRESS",
        "FAMILY",
    )

    rows = [
        (
            record.command,
            (
                str(record.pid)
                if record.pid is not None
                else "Unknown"
            ),
            record.user or "Unknown",
            record.address,
            record.family,
        )
        for record in records
    ]

    widths = [
        max(
            len(headers[index]),
            max(
                len(row[index])
                for row in rows
            ),
        )
        for index in range(len(headers))
    ]

    header_line = "  ".join(
        headers[index].ljust(widths[index])
        for index in range(len(headers))
    )

    separator_line = "  ".join(
        "-" * widths[index]
        for index in range(len(headers))
    )

    table_lines = [
        header_line,
        separator_line,
    ]

    for row in rows:
        table_lines.append(
            "  ".join(
                row[index].ljust(widths[index])
                for index in range(len(row))
            )
        )

    return table_lines


def _render_triage_annotation(
    annotation: TriageAnnotation,
) -> list[str]:
    response = annotation.response
    likely_benign = (
        "Yes"
        if response.likely_benign
        else "No"
    )

    lines = [
        "  AI triage annotation (not authoritative):",
        f"    Model: {annotation.model}",
        (
            "    Likely benign: "
            f"{likely_benign}"
        ),
        (
            "    Confidence: "
            f"{response.confidence}"
        ),
        (
            "    Explanation: "
            f"{response.explanation}"
        ),
        "    Investigation steps:",
    ]

    lines.extend(
        f"      {index}. {step}"
        for index, step in enumerate(
            response.investigation_steps,
            start=1,
        )
    )

    if annotation.human_verdict is not None:
        lines.append(
            "    Human verdict: "
            f"{annotation.human_verdict}"
        )

    return lines


def _render_findings(
    findings: list[Finding],
    triage_annotations: dict[
        str,
        TriageAnnotation,
    ],
    triage_errors: dict[str, str],
) -> list[str]:
    lines = [
        "Security Findings",
        "-----------------",
    ]

    if not findings:
        lines.append("No findings were produced.")
        return lines

    sorted_findings = sorted(
        findings,
        key=lambda finding: (
            _SEVERITY_ORDER[finding.severity],
            finding.kind,
            finding.id,
        ),
    )

    current_severity: Severity | None = None

    for finding in sorted_findings:
        if finding.severity != current_severity:
            if current_severity is not None:
                lines.append("")

            current_severity = finding.severity
            severity_heading = (
                current_severity.value
            )

            lines.append(severity_heading)
            lines.append(
                "~" * len(severity_heading)
            )

        lines.append(
            f"- [{finding.id}] {finding.message}"
        )

        annotation = triage_annotations.get(
            finding.id
        )

        if annotation is not None:
            lines.extend(
                _render_triage_annotation(
                    annotation
                )
            )
            continue

        triage_error = triage_errors.get(
            finding.id
        )

        if triage_error is not None:
            lines.append(
                "  AI triage unavailable: "
                f"{triage_error}"
            )

    return lines


def _missed_run_reason(
    run: dict[str, Any],
) -> str:
    if run.get("finished_at") is None:
        return (
            "The run started but did not record "
            "a completion."
        )

    if run.get("delivery_status") == "failed":
        return "Email delivery failed."

    if run.get("delivery_status") is None:
        return (
            "The run completed, but no delivery "
            "outcome was recorded."
        )

    return "The run was not delivered."


def _render_missed_runs(
    missed_runs: list[dict[str, Any]],
) -> list[str]:
    if not missed_runs:
        return []

    lines = [
        "Missed or Undelivered Runs",
        "--------------------------",
        (
            "The following earlier runs did not "
            "successfully reach you:"
        ),
        "",
    ]

    for run in missed_runs:
        run_id = str(
            run.get("run_id", "Unknown")
        )

        lines.append(f"Run ID: {run_id}")
        lines.append(
            "Started: "
            f"{_display_timestamp(run.get('started_at'))}"
        )
        lines.append(
            "Finished: "
            f"{_display_timestamp(run.get('finished_at'))}"
        )
        lines.append(
            "Security status: "
            f"{run.get('overall_status') or 'Unknown'}"
        )
        lines.append(
            "Delivery status: "
            f"{run.get('delivery_status') or 'Unknown'}"
        )
        lines.append(
            f"Reason: {_missed_run_reason(run)}"
        )

        delivery_error = run.get(
            "delivery_error"
        )

        if delivery_error:
            lines.append(
                f"Delivery error: {delivery_error}"
            )

        report_txt_path = run.get(
            "report_txt_path"
        )

        report_json_path = run.get(
            "report_json_path"
        )

        if report_txt_path:
            lines.append(
                f"Text report: {report_txt_path}"
            )

        if report_json_path:
            lines.append(
                f"JSON report: {report_json_path}"
            )

        lines.append("")

    return lines


def _render_disk_section(
    disk: DiskInfo | None,
) -> list[str]:
    lines = [
        "Disk Information",
        "----------------",
    ]

    if disk is None:
        lines.append("Disk information unavailable.")
        return lines

    lines.extend(
        [
            f"Mount: {disk.mount}",
            (
                "Total disk space: "
                f"{disk.total_gb:.2f} GB"
            ),
            (
                "Used disk space: "
                f"{disk.used_gb:.2f} GB"
            ),
            (
                "Free disk space: "
                f"{disk.free_gb:.2f} GB"
            ),
            (
                "Disk usage: "
                f"{disk.percent_used:.2f}%"
            ),
        ]
    )

    return lines


def _render_listener_sections(
    listeners: ListenerSummary | None,
) -> list[str]:
    if listeners is None:
        return [
            "Listener Information",
            "--------------------",
            "Listener information unavailable.",
        ]

    network_records = [
        record
        for record in listeners.records
        if not record.is_loopback
    ]

    local_only_records = [
        record
        for record in listeners.records
        if record.is_loopback
    ]

    lines = [
        "Listener Summary",
        "----------------",
        (
            "Logical listening sockets: "
            f"{listeners.socket_count}"
        ),
        (
            "Network-reachable ports: "
            f"{len(listeners.network_ports)}"
        ),
        (
            "Loopback-only ports: "
            f"{len(listeners.local_only_ports)}"
        ),
        "",
        "Potentially Network-Reachable Listeners",
        "---------------------------------------",
    ]

    lines.extend(
        _render_listener_table(
            network_records
        )
    )

    lines.extend(
        [
            "",
            "Loopback-Only Listeners",
            "-----------------------",
        ]
    )

    lines.extend(
        _render_listener_table(
            local_only_records
        )
    )

    return lines


def render_text_report(
    context: ReportContext,
) -> str:
    overall_status = _severity_text(
        context.summary["overall_status"]
    )

    lines = [
        "Personal Security Reporter",
        "",
        f"Overall status: [{overall_status}]",
        (
            "Critical: "
            f"{context.summary['critical_count']}  |  "
            "Warnings: "
            f"{context.summary['warning_count']}  |  "
            "Info: "
            f"{context.summary['info_count']}"
        ),
        f"Run ID: {context.run_id}",
        f"Report time: {context.report_time_local}",
        "",
    ]

    missed_run_lines = _render_missed_runs(
        context.missed_runs
    )

    if missed_run_lines:
        lines.extend(missed_run_lines)

    lines.extend(
        _render_findings(
            context.findings,
            context.triage_annotations,
            context.triage_errors,
        )
    )

    if context.triage_limit_skipped_count:
        lines.extend(
            [
                "",
                (
                    f"{context.triage_limit_skipped_count} findings "
                    "were not triaged due to the per-run cost limit."
                ),
            ]
        )

    lines.extend(
        [
            "",
            "Baseline Comparison",
            "-------------------",
            (
                "Baseline status: "
                f"{context.baseline_status}"
            ),
            (
                "Comparison performed: "
                f"{'Yes' if context.comparison_performed else 'No'}"
            ),
            (
                "New network-reachable ports: "
                f"{_format_port_list(context.new_network_ports)}"
            ),
            (
                "Removed network-reachable ports: "
                f"{_format_port_list(context.removed_network_ports)}"
            ),
            "",
            "Host Information",
            "----------------",
            (
                "Computer name: "
                f"{context.host.computer_name}"
            ),
            (
                "Operating system: "
                f"{context.host.operating_system}"
            ),
            (
                "Platform: "
                f"{context.host.platform_system}"
            ),
            (
                "Current user: "
                f"{context.host.current_user}"
            ),
            (
                "System uptime: "
                f"{context.host.uptime_text}"
            ),
            (
                "Running processes: "
                f"{context.host.process_count}"
            ),
            "",
        ]
    )

    lines.extend(
        _render_disk_section(
            context.host.disk
        )
    )

    lines.extend(
        [
            "",
            "Top CPU Processes",
            "-----------------",
        ]
    )

    lines.extend(
        _render_process_table(
            context.host.top_processes
        )
    )

    lines.append("")

    lines.extend(
        _render_listener_sections(
            context.host.listeners
        )
    )

    return "\n".join(lines).rstrip() + "\n"


def _process_to_dict(
    process: ProcessRecord,
) -> dict[str, Any]:
    return {
        "pid": process.pid,
        "executable": process.executable,
        "display_name": process.display_name,
        "cpu_percent": process.cpu_percent,
        "mem_percent": process.mem_percent,
    }


def _listener_to_dict(
    listener: ListenerRecord,
) -> dict[str, Any]:
    return {
        "command": listener.command,
        "pid": listener.pid,
        "user": listener.user,
        "address": listener.address,
        "port": listener.port,
        "family": listener.family,
        "is_loopback": listener.is_loopback,
    }


def _disk_to_dict(
    disk: DiskInfo | None,
) -> dict[str, Any] | None:
    if disk is None:
        return None

    return {
        "mount": disk.mount,
        "total_gb": disk.total_gb,
        "used_gb": disk.used_gb,
        "free_gb": disk.free_gb,
        "percent_used": disk.percent_used,
    }


def _listeners_to_dict(
    listeners: ListenerSummary | None,
) -> dict[str, Any] | None:
    if listeners is None:
        return None

    return {
        "socket_count": listeners.socket_count,
        "network_ports": list(
            listeners.network_ports
        ),
        "local_only_ports": list(
            listeners.local_only_ports
        ),
        "network_port_owners": {
            port: list(owners)
            for port, owners
            in listeners.network_port_owners.items()
        },
        "local_only_port_owners": {
            port: list(owners)
            for port, owners
            in listeners.local_only_port_owners.items()
        },
        "records": [
            _listener_to_dict(record)
            for record in listeners.records
        ],
    }


def _summary_to_dict(
    summary: dict[str, Any],
) -> dict[str, Any]:
    return {
        "overall_status": _severity_text(
            summary["overall_status"]
        ),
        "critical_count": int(
            summary["critical_count"]
        ),
        "warning_count": int(
            summary["warning_count"]
        ),
        "info_count": int(
            summary["info_count"]
        ),
        "total_count": int(
            summary["total_count"]
        ),
    }


def _triage_to_dict(
    annotation: TriageAnnotation,
) -> dict[str, Any]:
    return {
        "status": "available",
        **annotation.to_dict(),
    }


def _finding_to_dict(
    finding: Finding,
    triage_annotations: dict[
        str,
        TriageAnnotation,
    ],
    triage_errors: dict[str, str],
) -> dict[str, Any]:
    finding_data = finding.to_dict()
    annotation = triage_annotations.get(
        finding.id
    )

    if annotation is not None:
        finding_data["triage"] = (
            _triage_to_dict(annotation)
        )
        return finding_data

    triage_error = triage_errors.get(
        finding.id
    )

    if triage_error is not None:
        finding_data["triage"] = {
            "status": "unavailable",
            "error": triage_error,
        }
        return finding_data

    finding_data["triage"] = None
    return finding_data


def render_json_report(
    context: ReportContext,
) -> dict[str, Any]:
    return {
        "schema_version": REPORT_SCHEMA_VERSION,
        "run_id": context.run_id,
        "report_time": context.report_time_iso,
        "summary": _summary_to_dict(
            context.summary
        ),
        "host": {
            "computer_name": (
                context.host.computer_name
            ),
            "operating_system": (
                context.host.operating_system
            ),
            "platform_system": (
                context.host.platform_system
            ),
            "current_user": (
                context.host.current_user
            ),
            "uptime_text": (
                context.host.uptime_text
            ),
            "process_count": (
                context.host.process_count
            ),
            "disk": _disk_to_dict(
                context.host.disk
            ),
            "top_processes": [
                _process_to_dict(process)
                for process
                in context.host.top_processes
            ],
            "listeners": _listeners_to_dict(
                context.host.listeners
            ),
        },
        "baseline": {
            "status": context.baseline_status,
            "comparison_performed": (
                context.comparison_performed
            ),
            "new_network_ports": list(
                context.new_network_ports
            ),
            "removed_network_ports": list(
                context.removed_network_ports
            ),
        },
        "triage": {
            "eligible_count": (
                context.triage_eligible_count
            ),
            "annotated_count": len(
                context.triage_annotations
            ),
            "unavailable_count": len(
                context.triage_errors
            ),
            "cache_hits": (
                context.triage_cache_hits
            ),
            "api_calls": (
                context.triage_api_calls
            ),
            "limit_skipped_count": (
                context.triage_limit_skipped_count
            ),
        },
        "findings": [
            _finding_to_dict(
                finding,
                context.triage_annotations,
                context.triage_errors,
            )
            for finding in context.findings
        ],
        "missed_runs": [
            dict(run)
            for run in context.missed_runs
        ],
    }