from __future__ import annotations

import argparse
import json
import sys
import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from analysis import (
    analyze_disk_usage,
    analyze_network_port_changes,
    apply_acknowledgements,
    compare_ports,
    summarize_findings,
)
from baseline import (
    BaselineError,
    acknowledge_findings,
    build_baseline,
    check_host_matches,
    load_baseline,
    migrate_baseline,
    save_baseline,
    update_baseline,
)
from collectors import (
    CollectorError,
    collect_basic_system_info,
    collect_disk_info,
    collect_listening_ports,
    collect_process_info,
    collect_system_uptime,
)
from config import (
    ConfigError,
    EmailConfig,
    TriageConfigError,
    load_email_config,
    load_triage_config,
)
from emailer import EmailError, send_report
from findings import (
    KIND_COLLECTOR_ERROR,
    Finding,
    Severity,
    make_collector_error_finding,
    make_first_run_finding,
)
from ledger import (
    LedgerError,
    finish_run,
    get_recent_runs,
    get_undelivered_runs,
    init_ledger,
    mark_catchup_reported,
    record_delivery,
    record_triage_verdict,
    start_run,
)
from models import HostState, ReportContext
from paths import (
    BASELINE_PATH,
    LEDGER_PATH,
    OUTPUT_DIR,
    STATUS_PATH,
)
from report import render_json_report, render_text_report
from triage import triage_findings

EXIT_OK = 0
EXIT_WARNING = 1
EXIT_CRITICAL = 2
EXIT_FATAL = 3


@dataclass(frozen=True)
class _EvaluationResult:
    findings: list[Finding]
    baseline_status: str
    comparison_performed: bool
    new_network_ports: list[str]
    removed_network_ports: list[str]
    baseline_to_save: dict[str, Any] | None
    host_mismatch: bool


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Snapshot this Mac's host state and report changes "
            "to network-reachable TCP listeners."
        )
    )

    special_action_group = (
        parser.add_mutually_exclusive_group()
    )

    special_action_group.add_argument(
        "--acknowledge",
        metavar="ID",
        action="append",
        help=(
            "Persist a finding ID as acknowledged. "
            "May be supplied more than once."
        ),
    )

    special_action_group.add_argument(
        "--history",
        metavar="N",
        nargs="?",
        const=10,
        type=int,
        help=(
            "Print the most recent ledger runs and exit. "
            "Defaults to 10."
        ),
    )

    special_action_group.add_argument(
        "--review",
        metavar="ID",
        help=(
            "Record a human verdict for an existing AI triage "
            "annotation and exit."
        ),
    )

    special_action_group.add_argument(
        "--update-baseline",
        action="store_true",
        help=(
            "Create or replace the stored listener baseline "
            "with the "
            "current listener state after reporting."
        ),
    )

    parser.add_argument(
        "--force",
        action="store_true",
        help=(
            "Allow --update-baseline to proceed despite "
            "unacknowledged WARNING or CRITICAL findings. "
            "Collector errors remain non-blocking."
        ),
    )

    parser.add_argument(
        "--verdict",
        choices=(
            "accurate",
            "wrong",
            "unsure",
        ),
        help=(
            "Human verdict used with --review."
        ),
    )

    parser.add_argument(
        "--no-email",
        action="store_true",
        help=(
            "Skip email delivery while still writing reports "
            "locally."
        ),
    )

    parser.add_argument(
        "--quiet",
        action="store_true",
        help=(
            "Print only the run summary instead of the "
            "complete report."
        ),
    )

    parser.add_argument(
        "--baseline-path",
        type=Path,
        default=BASELINE_PATH,
        help=(
            "Override the baseline path. Primarily intended "
            "for testing."
        ),
    )

    args = parser.parse_args()

    if args.history is not None and args.history < 1:
        parser.error("--history must be at least 1.")

    if args.force and not args.update_baseline:
        parser.error("--force requires --update-baseline.")

    if args.review is not None and args.verdict is None:
        parser.error("--review requires --verdict.")

    if args.verdict is not None and args.review is None:
        parser.error("--verdict requires --review.")

    args.baseline_path = (
        args.baseline_path
        .expanduser()
        .resolve()
    )

    return args


def _latest_report_finding_ids(
) -> tuple[set[str] | None, str | None]:
    report_paths = sorted(
        OUTPUT_DIR.glob("report_*.json")
    )

    if not report_paths:
        return (
            None,
            "No prior JSON report was found.",
        )

    latest_report_path = report_paths[-1]

    try:
        report_data = json.loads(
            latest_report_path.read_text(
                encoding="utf-8"
            )
        )
    except (
        OSError,
        json.JSONDecodeError,
    ) as error:
        return (
            None,
            (
                f"Could not inspect {latest_report_path}: "
                f"{error}"
            ),
        )

    raw_findings = report_data.get(
        "findings",
        [],
    )

    if not isinstance(raw_findings, list):
        return (
            None,
            (
                f"{latest_report_path} has an invalid "
                "findings section."
            ),
        )

    finding_ids = {
        str(item["id"])
        for item in raw_findings
        if (
            isinstance(item, dict)
            and item.get("id")
        )
    }

    return finding_ids, None


def handle_acknowledge(
    args: argparse.Namespace,
) -> int:
    baseline_path: Path = args.baseline_path
    requested_ids: list[str] = (
        args.acknowledge or []
    )

    (
        latest_finding_ids,
        report_warning,
    ) = _latest_report_finding_ids()

    if report_warning is not None:
        print(
            f"Warning: {report_warning}",
            file=sys.stderr,
        )

    for finding_id in requested_ids:
        if (
            latest_finding_ids is not None
            and finding_id
            not in latest_finding_ids
        ):
            print(
                "Warning: finding ID "
                f"{finding_id} was not present in the "
                "latest report. It will still be "
                "acknowledged.",
                file=sys.stderr,
            )

    newly_acknowledged, already_acknowledged = (
        acknowledge_findings(
            finding_ids=requested_ids,
            path=baseline_path,
        )
    )

    for finding_id in already_acknowledged:
        print(
            f"Finding {finding_id} is already acknowledged."
        )

    for finding_id in newly_acknowledged:
        print(
            f"Acknowledged finding {finding_id}."
        )

    return EXIT_OK


def handle_review(
    args: argparse.Namespace,
) -> int:
    finding_id = str(args.review).strip()

    if not finding_id:
        raise LedgerError(
            "Review finding ID cannot be empty."
        )

    annotation = record_triage_verdict(
        path=LEDGER_PATH,
        finding_id=finding_id,
        verdict=str(args.verdict),
        verdict_at=(
            datetime.now()
            .astimezone()
            .isoformat()
        ),
    )

    print(
        "Recorded human verdict "
        f"'{annotation.human_verdict}' for finding "
        f"{annotation.finding_id}, prompt "
        f"{annotation.prompt_hash}, model "
        f"{annotation.model}."
    )

    return EXIT_OK


def _print_history(
    limit: int,
) -> None:
    rows = get_recent_runs(
        path=LEDGER_PATH,
        n=limit,
    )

    if not rows:
        print("No ledger runs were found.")
        return

    print(f"Most recent {len(rows)} run(s)")
    print("-" * 72)

    for row in rows:
        run_id = row.get(
            "run_id",
            "unknown",
        )

        started_at = row.get(
            "started_at",
            "unknown",
        )

        overall_status = (
            row.get("overall_status")
            or "unfinished"
        )

        exit_code = row.get("exit_code")

        delivery_status = (
            row.get("delivery_status")
            or "unknown"
        )

        print(f"Run ID: {run_id}")
        print(f"Started: {started_at}")
        print(f"Status: {overall_status}")
        print(f"Exit code: {exit_code}")
        print(f"Delivery: {delivery_status}")
        print("-" * 72)


def gather_host_state(
    basic_info: Mapping[str, str],
) -> tuple[HostState, list[Finding]]:
    findings: list[Finding] = []

    try:
        uptime_text = collect_system_uptime()
    except CollectorError as error:
        uptime_text = "Unavailable"

        findings.append(
            make_collector_error_finding(
                collector_name="uptime",
                error=str(error),
            )
        )

    try:
        (
            process_count,
            top_processes,
        ) = collect_process_info()

    except CollectorError as error:
        process_count = 0
        top_processes = []

        findings.append(
            make_collector_error_finding(
                collector_name="processes",
                error=str(error),
            )
        )

    try:
        disk_info = collect_disk_info()

    except CollectorError as error:
        disk_info = None

        findings.append(
            make_collector_error_finding(
                collector_name="disk",
                error=str(error),
            )
        )

    # Deliberately not wrapped:
    #
    # Listener enumeration is the primary security signal.
    # Continuing without it could make every baseline port
    # appear removed and create a fabricated report.
    listener_summary = (
        collect_listening_ports()
    )

    host_state = HostState(
        computer_name=basic_info[
            "computer_name"
        ],
        operating_system=basic_info[
            "operating_system"
        ],
        platform_system=basic_info[
            "platform_system"
        ],
        current_user=basic_info[
            "current_user"
        ],
        uptime_text=uptime_text,
        process_count=process_count,
        top_processes=top_processes,
        disk=disk_info,
        listeners=listener_summary,
    )

    return host_state, findings


def evaluate(
    host_state: HostState,
    baseline: dict[str, Any] | None,
    existing_findings: list[Finding],
    now_iso: str,
    baseline_update_requested: bool = False,
) -> _EvaluationResult:
    findings = list(existing_findings)

    if host_state.disk is not None:
        findings.append(
            analyze_disk_usage(
                host_state.disk
            )
        )

    listeners = host_state.listeners

    if listeners is None:
        raise CollectorError(
            "Listener data is unavailable. "
            "Port comparison was aborted."
        )

    if baseline is None:
        findings.append(
            make_first_run_finding()
        )

        if baseline_update_requested:
            baseline_to_save = build_baseline(
                host_state=host_state,
                listeners=listeners,
                now_iso=now_iso,
            )

            baseline_status = (
                "Initial baseline creation was requested. "
                "No comparison was performed."
            )

        else:
            baseline_to_save = None
            baseline_status = (
                "No baseline exists. Run with "
                "--update-baseline to create one. "
                "No comparison was performed."
            )

        return _EvaluationResult(
            findings=findings,
            baseline_status=baseline_status,
            comparison_performed=False,
            new_network_ports=[],
            removed_network_ports=[],
            baseline_to_save=baseline_to_save,
            host_mismatch=False,
        )

    host_mismatch_finding = (
        check_host_matches(
            baseline=baseline,
            computer_name=(
                host_state.computer_name
            ),
        )
    )

    if host_mismatch_finding is not None:
        findings.append(
            host_mismatch_finding
        )

        acknowledged_ids = set(
            baseline.get(
                "acknowledged_finding_ids",
                [],
            )
        )

        findings = apply_acknowledgements(
            findings=findings,
            acknowledged_ids=(
                acknowledged_ids
            ),
        )

        return _EvaluationResult(
            findings=findings,
            baseline_status=(
                "Baseline host does not match this "
                "computer. Port comparison was skipped."
            ),
            comparison_performed=False,
            new_network_ports=[],
            removed_network_ports=[],
            baseline_to_save=None,
            host_mismatch=True,
        )

    port_comparison = compare_ports(
        current_ports=(
            listeners.network_ports
        ),
        baseline_ports=baseline.get(
            "network_ports",
            [],
        ),
    )

    new_network_ports = (
        port_comparison["new_ports"]
    )

    removed_network_ports = (
        port_comparison["removed_ports"]
    )

    network_findings = (
        analyze_network_port_changes(
            new_ports=new_network_ports,
            removed_ports=(
                removed_network_ports
            ),
            current_port_owners=(
                listeners.network_port_owners
            ),
            baseline_port_owners=baseline.get(
                "network_port_owners",
                {},
            ),
        )
    )

    findings.extend(network_findings)

    acknowledged_ids = set(
        baseline.get(
            "acknowledged_finding_ids",
            [],
        )
    )

    findings = apply_acknowledgements(
        findings=findings,
        acknowledged_ids=acknowledged_ids,
    )

    return _EvaluationResult(
        findings=findings,
        baseline_status=(
            "Existing baseline loaded."
        ),
        comparison_performed=True,
        new_network_ports=new_network_ports,
        removed_network_ports=(
            removed_network_ports
        ),
        baseline_to_save=None,
        host_mismatch=False,
    )


def _apply_baseline_update_gate(
    *,
    update_requested: bool,
    force: bool,
    evaluation: _EvaluationResult,
    baseline: dict[str, Any] | None,
    host_state: HostState,
    baseline_path: Path,
    now_iso: str,
) -> dict[str, Any] | None:
    """Persist current listener state only after explicit approval."""

    if not update_requested:
        return baseline

    if evaluation.host_mismatch:
        raise BaselineError(
            "Baseline update was refused because the baseline "
            "belongs to a different host."
        )

    blocking_findings = [
        finding
        for finding in evaluation.findings
        if (
            not finding.acknowledged
            and finding.kind != KIND_COLLECTOR_ERROR
            and finding.severity
            in {Severity.WARNING, Severity.CRITICAL}
        )
    ]

    if blocking_findings and not force:
        finding_list = "\n".join(
            (
                f"- {finding.id} "
                f"[{finding.severity.value}] "
                f"{finding.kind}: {finding.message}"
            )
            for finding in blocking_findings
        )

        raise BaselineError(
            "Baseline update was refused because unresolved "
            "WARNING or CRITICAL findings would be absorbed "
            "into the new baseline:\n"
            f"{finding_list}\n"
            "Acknowledge the findings or rerun with --force "
            "after reviewing them."
        )

    if evaluation.baseline_to_save is not None:
        save_baseline(
            data=evaluation.baseline_to_save,
            path=baseline_path,
        )

        return evaluation.baseline_to_save

    if baseline is None:
        raise BaselineError(
            "Baseline update was requested, but no baseline "
            "candidate is available."
        )

    listeners = host_state.listeners

    if listeners is None:
        raise BaselineError(
            "Cannot update the baseline without listener data."
        )

    updated_baseline = update_baseline(
        existing=baseline,
        listeners=listeners,
        now_iso=now_iso,
    )

    save_baseline(
        data=updated_baseline,
        path=baseline_path,
    )

    return updated_baseline


def _severity_value(
    value: Any,
) -> str:
    if isinstance(value, Severity):
        return value.value

    return str(value)


def _exit_code_from_summary(
    summary: Mapping[str, Any],
) -> int:
    if int(
        summary.get(
            "critical_count",
            0,
        )
    ) > 0:
        return EXIT_CRITICAL

    if int(
        summary.get(
            "warning_count",
            0,
        )
    ) > 0:
        return EXIT_WARNING

    return EXIT_OK


def _write_report_files(
    context: ReportContext,
    text_report: str,
    json_report: dict[str, Any],
) -> tuple[Path, Path]:
    OUTPUT_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    report_datetime = datetime.fromisoformat(
        context.report_time_iso
    )

    filename_timestamp = (
        report_datetime.strftime(
            "%Y-%m-%d_%H-%M-%S"
        )
    )

    text_path = (
        OUTPUT_DIR
        / f"report_{filename_timestamp}.txt"
    )

    json_path = (
        OUTPUT_DIR
        / f"report_{filename_timestamp}.json"
    )

    text_path.write_text(
        text_report,
        encoding="utf-8",
    )

    json_path.write_text(
        json.dumps(
            json_report,
            indent=4,
            ensure_ascii=False,
        )
        + "\n",
        encoding="utf-8",
    )

    return text_path, json_path


def _write_last_run_status(
    context: ReportContext,
    exit_code: int,
    delivery_status: str,
    delivery_error: str | None,
    text_report_path: Path,
    json_report_path: Path,
    operational_errors: list[str],
) -> None:
    STATUS_PATH.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    overall_status = _severity_value(
        context.summary[
            "overall_status"
        ]
    )

    if exit_code == EXIT_FATAL:
        overall_status = "FATAL"

    lines = [
        f"Run ID: {context.run_id}",
        (
            "Timestamp: "
            f"{context.report_time_iso}"
        ),
        (
            "Overall status: "
            f"[{overall_status}]"
        ),
        f"Exit code: {exit_code}",
        (
            "Critical: "
            f"{context.summary['critical_count']} | "
            "Warnings: "
            f"{context.summary['warning_count']} | "
            "Info: "
            f"{context.summary['info_count']}"
        ),
        (
            "Delivery status: "
            f"{delivery_status}"
        ),
        (
            "Text report: "
            f"{text_report_path}"
        ),
        (
            "JSON report: "
            f"{json_report_path}"
        ),
    ]

    if delivery_error is not None:
        lines.append(
            f"Delivery error: {delivery_error}"
        )

    if operational_errors:
        lines.append(
            "Operational errors:"
        )

        lines.extend(
            f"- {error}"
            for error in operational_errors
        )

    STATUS_PATH.write_text(
        "\n".join(lines) + "\n",
        encoding="utf-8",
    )


def _write_fatal_last_run_status(
    *,
    run_id: str,
    error_message: str,
) -> None:
    """Write a best-effort status record when no report was produced."""

    STATUS_PATH.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    timestamp = (
        datetime.now()
        .astimezone()
        .isoformat()
    )

    lines = [
        f"Run ID: {run_id}",
        f"Timestamp: {timestamp}",
        "Overall status: [FATAL]",
        f"Exit code: {EXIT_FATAL}",
        "Delivery status: not attempted",
        "Text report: unavailable",
        "JSON report: unavailable",
        f"Fatal error: {error_message}",
    ]

    STATUS_PATH.write_text(
        "\n".join(lines) + "\n",
        encoding="utf-8",
    )


def deliver(
    report_text: str,
    context: ReportContext,
    config: EmailConfig | None,
    args: argparse.Namespace,
) -> tuple[str, str | None]:
    if args.no_email:
        return "skipped", None

    if config is None:
        return (
            "failed",
            (
                "Email delivery was enabled but no email "
                "configuration was loaded."
            ),
        )

    overall_status = _severity_value(
        context.summary[
            "overall_status"
        ]
    )

    subject = (
        f"[{overall_status}] "
        "Personal Security Report - "
        f"{context.report_time_local}"
    )

    try:
        send_report(
            config=config,
            subject=subject,
            body=report_text,
        )

    except EmailError as error:
        return "failed", str(error)

    return "sent", None


def _print_quiet_summary(
    context: ReportContext,
    delivery_status: str,
    text_report_path: Path,
    json_report_path: Path,
) -> None:
    overall_status = _severity_value(
        context.summary[
            "overall_status"
        ]
    )

    print(
        f"Overall status: [{overall_status}]"
    )

    print(
        "Critical: "
        f"{context.summary['critical_count']} | "
        "Warnings: "
        f"{context.summary['warning_count']} | "
        "Info: "
        f"{context.summary['info_count']}"
    )

    print(
        f"Delivery: {delivery_status}"
    )

    print(
        f"Text report: {text_report_path}"
    )

    print(
        f"JSON report: {json_report_path}"
    )


def _attempt_fatal_ledger_finish(
    ledger_started: bool,
    run_id: str,
    error_message: str,
) -> None:
    if not ledger_started:
        return

    try:
        finish_run(
            path=LEDGER_PATH,
            run_id=run_id,
            finished_at=(
                datetime.now()
                .astimezone()
                .isoformat()
            ),
            overall_status=None,
            critical_count=None,
            warning_count=None,
            info_count=None,
            exit_code=EXIT_FATAL,
            report_txt_path=None,
            report_json_path=None,
        )

    except LedgerError as ledger_error:
        print(
            "Ledger error while recording fatal run: "
            f"{ledger_error}",
            file=sys.stderr,
        )

    print(
        f"Fatal error: {error_message}",
        file=sys.stderr,
    )


def main() -> int:
    args = parse_args()

    if args.history is not None:
        try:
            init_ledger(LEDGER_PATH)
            _print_history(args.history)

        except LedgerError as error:
            print(
                f"Ledger error: {error}",
                file=sys.stderr,
            )

            return EXIT_FATAL

        return EXIT_OK

    if args.review is not None:
        try:
            init_ledger(LEDGER_PATH)
            return handle_review(args)

        except LedgerError as error:
            print(
                f"Ledger error: {error}",
                file=sys.stderr,
            )

            return EXIT_FATAL

    if args.acknowledge is not None:
        try:
            return handle_acknowledge(
                args
            )

        except BaselineError as error:
            print(
                f"Baseline error: {error}",
                file=sys.stderr,
            )

            return EXIT_FATAL

    run_id = str(uuid.uuid4())
    ledger_started = False
    operational_errors: list[str] = []

    try:
        email_config = (
            None
            if args.no_email
            else load_email_config()
        )

        run_started_at = (
            datetime.now()
            .astimezone()
        )

        started_at_iso = (
            run_started_at.isoformat()
        )

        report_time_local = (
            run_started_at.strftime(
                "%Y-%m-%d %H:%M:%S"
            )
        )

        basic_info = (
            collect_basic_system_info()
        )

        computer_name = basic_info[
            "computer_name"
        ]

        missed_runs: list[
            dict[str, Any]
        ] = []

        pre_collection_findings: list[
            Finding
        ] = []

        ledger_ready = False

        try:
            init_ledger(LEDGER_PATH)
            ledger_ready = True

        except LedgerError as error:
            pre_collection_findings.append(
                make_collector_error_finding(
                    collector_name=(
                        "ledger_init"
                    ),
                    error=str(error),
                )
            )

        if ledger_ready:
            try:
                # Query before inserting the current
                # row so the run cannot report itself
                # as a prior crash.
                missed_runs = (
                    get_undelivered_runs(
                        path=LEDGER_PATH
                    )
                )

            except LedgerError as error:
                pre_collection_findings.append(
                    make_collector_error_finding(
                        collector_name=(
                            "ledger_catchup_query"
                        ),
                        error=str(error),
                    )
                )

                missed_runs = []

            try:
                start_run(
                    path=LEDGER_PATH,
                    run_id=run_id,
                    started_at=(
                        started_at_iso
                    ),
                    computer_name=(
                        computer_name
                    ),
                )

                ledger_started = True

            except LedgerError as error:
                pre_collection_findings.append(
                    make_collector_error_finding(
                        collector_name=(
                            "ledger_start"
                        ),
                        error=str(error),
                    )
                )

        (
            host_state,
            collector_findings,
        ) = gather_host_state(
            basic_info
        )

        initial_findings = [
            *pre_collection_findings,
            *collector_findings,
        ]

        baseline_path: Path = (
            args.baseline_path
        )

        loaded_baseline = load_baseline(
            baseline_path
        )

        baseline: (
            dict[str, Any] | None
        ) = None

        if loaded_baseline is not None:
            baseline = migrate_baseline(
                loaded_baseline
            )

            # Migration is performed in memory. Any persisted
            # baseline change remains gated by --update-baseline.

        evaluation = evaluate(
            host_state=host_state,
            baseline=baseline,
            existing_findings=(
                initial_findings
            ),
            now_iso=started_at_iso,
            baseline_update_requested=(
                args.update_baseline
            ),
        )

        findings = evaluation.findings

        triage_config = None
        triage_unavailable_reason = None

        try:
            triage_config = load_triage_config()
        except TriageConfigError as error:
            triage_unavailable_reason = (
                "AI triage configuration is invalid: "
                f"{error}"
            )

        triage_result = triage_findings(
            findings,
            run_id=run_id,
            ledger_path=LEDGER_PATH,
            config=triage_config,
            ledger_available=ledger_started,
            unavailable_reason=(
                triage_unavailable_reason
            ),
        )

        summary = summarize_findings(
            findings
        )

        exit_code = (
            _exit_code_from_summary(
                summary
            )
        )

        context = ReportContext(
            report_time_local=(
                report_time_local
            ),
            report_time_iso=(
                started_at_iso
            ),
            run_id=run_id,
            host=host_state,
            findings=findings,
            summary=summary,
            baseline_status=(
                evaluation.baseline_status
            ),
            new_network_ports=(
                evaluation.new_network_ports
            ),
            removed_network_ports=(
                evaluation
                .removed_network_ports
            ),
            comparison_performed=(
                evaluation
                .comparison_performed
            ),
            missed_runs=missed_runs,
            triage_annotations=(
                triage_result.annotations
            ),
            triage_errors=(
                triage_result.errors
            ),
            triage_eligible_count=(
                triage_result.eligible_count
            ),
            triage_cache_hits=(
                triage_result.cache_hits
            ),
            triage_api_calls=(
                triage_result.api_calls
            ),
            triage_limit_skipped_count=(
                triage_result.limit_skipped_count
            ),
        )

        text_report = render_text_report(
            context
        )

        json_report = render_json_report(
            context
        )

        (
            text_report_path,
            json_report_path,
        ) = _write_report_files(
            context=context,
            text_report=text_report,
            json_report=json_report,
        )

        try:
            _write_last_run_status(
                context=context,
                exit_code=exit_code,
                delivery_status="pending",
                delivery_error=None,
                text_report_path=(
                    text_report_path
                ),
                json_report_path=(
                    json_report_path
                ),
                operational_errors=(
                    operational_errors
                ),
            )

        except OSError as error:
            operational_errors.append(
                "Could not write "
                "LAST_RUN_STATUS.txt: "
                f"{error}"
            )

        (
            delivery_status,
            delivery_error,
        ) = deliver(
            report_text=text_report,
            context=context,
            config=email_config,
            args=args,
        )

        if delivery_error is not None:
            print(
                "Email delivery failed: "
                f"{delivery_error}",
                file=sys.stderr,
            )

        if ledger_started:
            try:
                record_delivery(
                    path=LEDGER_PATH,
                    run_id=run_id,
                    status=delivery_status,
                    error=delivery_error,
                )

            except LedgerError as error:
                operational_errors.append(
                    "Could not record delivery: "
                    f"{error}"
                )

        if (
            ledger_started
            and delivery_status == "sent"
            and missed_runs
        ):
            missed_run_ids = [
                str(row["run_id"])
                for row in missed_runs
                if row.get("run_id")
            ]

            if missed_run_ids:
                try:
                    mark_catchup_reported(
                        path=LEDGER_PATH,
                        run_ids=(
                            missed_run_ids
                        ),
                    )

                except LedgerError as error:
                    operational_errors.append(
                        "Could not mark catch-up "
                        "runs as reported: "
                        f"{error}"
                    )

        if args.update_baseline:
            try:
                _apply_baseline_update_gate(
                    update_requested=True,
                    force=args.force,
                    evaluation=evaluation,
                    baseline=baseline,
                    host_state=host_state,
                    baseline_path=(
                        baseline_path
                    ),
                    now_iso=(
                        datetime.now()
                        .astimezone()
                        .isoformat()
                    ),
                )

            except BaselineError as error:
                operational_errors.append(
                    "Baseline update failed: "
                    f"{error}"
                )

                exit_code = EXIT_FATAL

        finished_at_iso = (
            datetime.now()
            .astimezone()
            .isoformat()
        )

        if ledger_started:
            try:
                finish_run(
                    path=LEDGER_PATH,
                    run_id=run_id,
                    finished_at=(
                        finished_at_iso
                    ),
                    overall_status=(
                        _severity_value(
                            summary[
                                "overall_status"
                            ]
                        )
                    ),
                    critical_count=int(
                        summary[
                            "critical_count"
                        ]
                    ),
                    warning_count=int(
                        summary[
                            "warning_count"
                        ]
                    ),
                    info_count=int(
                        summary[
                            "info_count"
                        ]
                    ),
                    exit_code=exit_code,
                    report_txt_path=str(
                        text_report_path
                    ),
                    report_json_path=str(
                        json_report_path
                    ),
                )

            except LedgerError as error:
                operational_errors.append(
                    "Could not finish ledger "
                    f"run: {error}"
                )

        try:
            _write_last_run_status(
                context=context,
                exit_code=exit_code,
                delivery_status=(
                    delivery_status
                ),
                delivery_error=(
                    delivery_error
                ),
                text_report_path=(
                    text_report_path
                ),
                json_report_path=(
                    json_report_path
                ),
                operational_errors=(
                    operational_errors
                ),
            )

        except OSError as error:
            operational_errors.append(
                "Could not update "
                "LAST_RUN_STATUS.txt: "
                f"{error}"
            )

        if args.quiet:
            _print_quiet_summary(
                context=context,
                delivery_status=(
                    delivery_status
                ),
                text_report_path=(
                    text_report_path
                ),
                json_report_path=(
                    json_report_path
                ),
            )

        else:
            print(text_report)

            print(
                "Delivery status: "
                f"{delivery_status}"
            )

            print(
                "Text report: "
                f"{text_report_path}"
            )

            print(
                "JSON report: "
                f"{json_report_path}"
            )

        if operational_errors:
            print(
                "Operational warnings:",
                file=sys.stderr,
            )

            for error in operational_errors:
                print(
                    f"- {error}",
                    file=sys.stderr,
                )

        return exit_code

    except (
        ConfigError,
        BaselineError,
        CollectorError,
        OSError,
    ) as error:
        try:
            _write_fatal_last_run_status(
                run_id=run_id,
                error_message=str(error),
            )

        except OSError as status_error:
            print(
                "Could not write LAST_RUN_STATUS.txt "
                "for the fatal run: "
                f"{status_error}",
                file=sys.stderr,
            )

        _attempt_fatal_ledger_finish(
            ledger_started=ledger_started,
            run_id=run_id,
            error_message=str(error),
        )

        if not ledger_started:
            print(
                f"Fatal error: {error}",
                file=sys.stderr,
            )

        return EXIT_FATAL


if __name__ == "__main__":
    sys.exit(main())