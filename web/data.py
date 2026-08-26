from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from baseline import BaselineError, load_baseline, migrate_baseline
from ledger import (
    LedgerError,
    get_recent_runs,
    get_run,
    get_runs,
    get_triage_annotation_history,
    get_triage_verdict_history,
)
from models import TriageAnnotation


class DashboardDataError(Exception):
    """Raised when dashboard data cannot be read safely."""


@dataclass(frozen=True)
class ReportDocument:
    status: str
    filename: str | None
    data: dict[str, Any] | None
    message: str | None = None

    @property
    def available(self) -> bool:
        return self.status == "available" and self.data is not None


@dataclass(frozen=True)
class DashboardData:
    ledger_path: Path
    output_dir: Path
    baseline_path: Path

    def list_runs(self) -> list[dict[str, Any]]:
        if not self.ledger_path.exists():
            return []

        try:
            return get_runs(self.ledger_path)
        except LedgerError as error:
            raise DashboardDataError(str(error)) from error

    def get_run_view(
        self,
        run_id: str,
    ) -> dict[str, Any] | None:
        if not self.ledger_path.exists():
            return None

        try:
            run = get_run(
                path=self.ledger_path,
                run_id=run_id,
            )
        except LedgerError as error:
            raise DashboardDataError(str(error)) from error

        if run is None:
            return None

        report = self._load_report_for_run(run)

        return {
            "run": run,
            "report": report,
            "prepared_report": (
                self._prepare_report(report.data)
                if report.available
                else None
            ),
        }

    def latest_run_view(self) -> dict[str, Any] | None:
        if not self.ledger_path.exists():
            return None

        try:
            runs = get_recent_runs(
                path=self.ledger_path,
                n=1,
            )
        except LedgerError as error:
            raise DashboardDataError(str(error)) from error

        if not runs:
            return None

        run = runs[0]
        report = self._load_report_for_run(run)

        return {
            "run": run,
            "report": report,
            "prepared_report": (
                self._prepare_report(report.data)
                if report.available
                else None
            ),
        }

    def get_finding_view(
        self,
        finding_id: str,
    ) -> dict[str, Any] | None:
        normalized_id = finding_id.strip()

        if not normalized_id:
            return None

        annotations: list[TriageAnnotation] = []
        verdicts: list[dict[str, Any]] = []

        if self.ledger_path.exists():
            try:
                annotations = get_triage_annotation_history(
                    path=self.ledger_path,
                    finding_id=normalized_id,
                )
                verdicts = get_triage_verdict_history(
                    path=self.ledger_path,
                    finding_id=normalized_id,
                )
            except LedgerError as error:
                raise DashboardDataError(str(error)) from error

        runs = self.list_runs()
        occurrences: list[dict[str, Any]] = []
        unavailable_reports: list[dict[str, str]] = []

        for run in runs:
            report = self._load_report_for_run(run)

            if not report.available:
                if run.get("report_json_path"):
                    unavailable_reports.append(
                        {
                            "run_id": str(run.get("run_id", "")),
                            "status": report.status,
                            "message": report.message or "Report unavailable.",
                        }
                    )
                continue

            raw_findings = report.data.get("findings", [])

            if not isinstance(raw_findings, list):
                continue

            for raw_finding in raw_findings:
                if not isinstance(raw_finding, dict):
                    continue

                if str(raw_finding.get("id", "")) != normalized_id:
                    continue

                occurrences.append(
                    {
                        "run": run,
                        "finding": self._prepare_finding(raw_finding),
                    }
                )
                break

        if not occurrences and not annotations and not verdicts:
            return None

        acknowledged, baseline_error = self._acknowledgement_state(
            normalized_id
        )
        verdicts_by_prompt: dict[str, list[dict[str, Any]]] = {}

        for verdict in verdicts:
            prompt_hash = str(verdict.get("prompt_hash", ""))
            verdicts_by_prompt.setdefault(prompt_hash, []).append(verdict)

        prepared_annotations = [
            {
                "annotation": annotation,
                "response": annotation.response.to_dict(),
                "verdict_history": verdicts_by_prompt.get(
                    annotation.prompt_hash,
                    [],
                ),
                "anchor": annotation.prompt_hash[:12],
            }
            for annotation in annotations
        ]

        return {
            "finding_id": normalized_id,
            "latest_occurrence": (
                occurrences[0]
                if occurrences
                else None
            ),
            "occurrences": occurrences,
            "annotations": prepared_annotations,
            "verdicts": verdicts,
            "acknowledged": acknowledged,
            "baseline_error": baseline_error,
            "unavailable_reports": unavailable_reports,
        }

    def _acknowledgement_state(
        self,
        finding_id: str,
    ) -> tuple[bool | None, str | None]:
        try:
            baseline = load_baseline(self.baseline_path)

            if baseline is None:
                return None, "No baseline exists."

            normalized = migrate_baseline(baseline)
        except BaselineError as error:
            return None, str(error)

        acknowledged_ids = {
            str(item)
            for item in normalized.get(
                "acknowledged_finding_ids",
                [],
            )
        }

        return finding_id in acknowledged_ids, None

    def _load_report_for_run(
        self,
        run: dict[str, Any],
    ) -> ReportDocument:
        raw_path = run.get("report_json_path")

        if raw_path is None or not str(raw_path).strip():
            return ReportDocument(
                status="not_recorded",
                filename=None,
                data=None,
                message="This ledger row has no JSON report path.",
            )

        candidate = Path(str(raw_path)).expanduser()

        if not candidate.is_absolute():
            if candidate.parts[:1] == (self.output_dir.name,):
                candidate = self.output_dir.parent / candidate
            else:
                candidate = self.output_dir / candidate

        try:
            output_root = self.output_dir.resolve()
            resolved = candidate.resolve(strict=False)
        except (OSError, RuntimeError) as error:
            return ReportDocument(
                status="unreadable",
                filename=candidate.name,
                data=None,
                message=f"The report path could not be resolved: {error}",
            )

        try:
            resolved.relative_to(output_root)
        except ValueError:
            return ReportDocument(
                status="unsafe_path",
                filename=candidate.name,
                data=None,
                message=(
                    "The ledger report path points outside the configured "
                    "output directory and was not opened."
                ),
            )

        if (
            resolved.suffix.lower() != ".json"
            or not resolved.name.startswith("report_")
        ):
            return ReportDocument(
                status="unsafe_path",
                filename=resolved.name,
                data=None,
                message="The ledger path is not a PSR JSON report.",
            )

        if not resolved.exists():
            return ReportDocument(
                status="missing",
                filename=resolved.name,
                data=None,
                message=(
                    "The report file referenced by the ledger no longer "
                    "exists. It may have been removed while cleaning output/."
                ),
            )

        try:
            raw_text = resolved.read_text(encoding="utf-8")
        except OSError as error:
            return ReportDocument(
                status="unreadable",
                filename=resolved.name,
                data=None,
                message=f"The report could not be read: {error}",
            )

        try:
            data = json.loads(raw_text)
        except json.JSONDecodeError as error:
            return ReportDocument(
                status="invalid",
                filename=resolved.name,
                data=None,
                message=f"The report contains invalid JSON: {error}",
            )

        if not isinstance(data, dict):
            return ReportDocument(
                status="invalid",
                filename=resolved.name,
                data=None,
                message="The report root must be a JSON object.",
            )

        report_run_id = str(data.get("run_id", "")).strip()
        ledger_run_id = str(run.get("run_id", "")).strip()

        if report_run_id != ledger_run_id:
            return ReportDocument(
                status="invalid",
                filename=resolved.name,
                data=None,
                message=(
                    "The report run ID does not match the ledger row, so "
                    "the file was not trusted."
                ),
            )

        return ReportDocument(
            status="available",
            filename=resolved.name,
            data=data,
        )

    def _prepare_report(
        self,
        report: dict[str, Any],
    ) -> dict[str, Any]:
        raw_findings = report.get("findings", [])
        findings: list[dict[str, Any]] = []

        if isinstance(raw_findings, list):
            findings = [
                self._prepare_finding(item)
                for item in raw_findings
                if isinstance(item, dict)
            ]

        grouped = {
            "CRITICAL": [],
            "WARNING": [],
            "INFO": [],
        }

        for finding in findings:
            severity = finding["severity"]
            grouped.setdefault(severity, []).append(finding)

        summary = report.get("summary")
        host = report.get("host")
        triage = report.get("triage")
        baseline = report.get("baseline")

        return {
            "run_id": str(report.get("run_id", "")),
            "report_time": str(report.get("report_time", "")),
            "summary": summary if isinstance(summary, dict) else {},
            "host": host if isinstance(host, dict) else {},
            "triage": triage if isinstance(triage, dict) else {},
            "baseline": baseline if isinstance(baseline, dict) else {},
            "findings": findings,
            "findings_by_severity": grouped,
        }

    @staticmethod
    def _prepare_finding(
        finding: dict[str, Any],
    ) -> dict[str, Any]:
        identity = finding.get("identity")
        details = finding.get("details")
        remediation = finding.get("remediation")
        verification = finding.get("verification")
        approval = finding.get("approval")
        triage = finding.get("triage")

        severity = str(finding.get("severity", "INFO")).upper()

        return {
            "id": str(finding.get("id", "")),
            "kind": str(finding.get("kind", "unknown")),
            "severity": severity,
            "message": str(finding.get("message", "")),
            "acknowledged": bool(finding.get("acknowledged", False)),
            "identity": identity if isinstance(identity, dict) else {},
            "details": details if isinstance(details, dict) else {},
            "remediation": remediation,
            "verification": verification,
            "approval": approval,
            "triage": triage if isinstance(triage, dict) else None,
            "identity_json": json.dumps(
                identity if isinstance(identity, dict) else {},
                indent=2,
                sort_keys=True,
                ensure_ascii=False,
            ),
            "details_json": json.dumps(
                details if isinstance(details, dict) else {},
                indent=2,
                sort_keys=True,
                ensure_ascii=False,
            ),
        }
