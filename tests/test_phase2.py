from __future__ import annotations

import html
import json
import re
from pathlib import Path

from fastapi.testclient import TestClient

from baseline import load_baseline, save_baseline
from findings import make_new_listener_finding
from ledger import (
    finish_run,
    get_triage_annotation,
    get_triage_verdict_history,
    init_ledger,
    record_triage_annotation,
    start_run,
)
from models import TriageAnnotation, TriageResponse
from web.app import create_app

_STARTED_AT = "2026-07-24T10:00:00-04:00"
_FINISHED_AT = "2026-07-24T10:00:10-04:00"
_CREATED_AT = "2026-07-24T10:00:05-04:00"


def _write_baseline(path: Path) -> None:
    save_baseline(
        {
            "schema_version": 2,
            "created_at": _STARTED_AT,
            "updated_at": _STARTED_AT,
            "host": {
                "computer_name": "test-mac",
                "operating_system": "macOS test",
                "platform_system": "Darwin",
            },
            "network_ports": [],
            "local_only_ports": [],
            "network_port_owners": {},
            "acknowledged_finding_ids": [],
        },
        path=path,
    )


def _write_run(
    *,
    ledger_path: Path,
    output_dir: Path,
    run_id: str,
    findings: list[dict[str, object]],
    write_report: bool = True,
) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    report_path = output_dir / f"report_{run_id}.json"

    init_ledger(ledger_path)
    start_run(
        path=ledger_path,
        run_id=run_id,
        started_at=_STARTED_AT,
        computer_name="test-mac",
    )

    if write_report:
        report_path.write_text(
            json.dumps(
                {
                    "schema_version": 2,
                    "run_id": run_id,
                    "report_time": _STARTED_AT,
                    "summary": {
                        "overall_status": "WARNING",
                        "critical_count": 0,
                        "warning_count": len(findings),
                        "info_count": 0,
                        "total_count": len(findings),
                    },
                    "host": {
                        "computer_name": "test-mac",
                        "operating_system": "macOS test",
                        "platform_system": "Darwin",
                        "current_user": "tester",
                        "uptime_text": "1 day",
                        "process_count": 1,
                    },
                    "baseline": {
                        "status": "loaded",
                        "comparison_performed": True,
                    },
                    "triage": {
                        "eligible_count": len(findings),
                        "annotated_count": 0,
                        "unavailable_count": 0,
                        "cache_hits": 0,
                        "api_calls": 0,
                        "limit_skipped_count": 0,
                    },
                    "findings": findings,
                    "missed_runs": [],
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )

    finish_run(
        path=ledger_path,
        run_id=run_id,
        finished_at=_FINISHED_AT,
        overall_status="WARNING",
        critical_count=0,
        warning_count=len(findings),
        info_count=0,
        exit_code=1,
        report_txt_path=str(
            output_dir / f"report_{run_id}.txt"
        ),
        report_json_path=str(report_path),
    )

    return report_path


def _client(
    *,
    ledger_path: Path,
    output_dir: Path,
    baseline_path: Path,
) -> TestClient:
    app = create_app(
        ledger_path=ledger_path,
        output_dir=output_dir,
        baseline_path=baseline_path,
        session_secret="phase2-test-secret",
        allowed_hosts=("testserver",),
    )
    return TestClient(app)


def _csrf_token(body: str) -> str:
    match = re.search(
        r'name="csrf_token" value="([^"]+)"',
        body,
    )
    assert match is not None
    return html.unescape(match.group(1))


def _annotation(
    *,
    finding_id: str,
    run_id: str,
    prompt_hash: str,
    created_at: str,
) -> TriageAnnotation:
    return TriageAnnotation(
        finding_id=finding_id,
        run_id=run_id,
        model="gpt-test-2026-07-01",
        prompt_hash=prompt_hash,
        response=TriageResponse(
            explanation="Review the listener owner and expected exposure.",
            likely_benign=False,
            investigation_steps=(
                "Confirm the process binary and parent process.",
            ),
            confidence="medium",
        ),
        created_at=created_at,
    )


def test_host_derived_script_content_is_escaped(
    tmp_path: Path,
) -> None:
    ledger_path = tmp_path / "data" / "ledger.db"
    baseline_path = tmp_path / "data" / "baseline.json"
    output_dir = tmp_path / "output"
    payload = "<script>alert(1)</script>"
    finding = make_new_listener_finding(
        port="8080",
        owners=[payload],
    )
    finding_data = finding.to_dict()
    finding_data["triage"] = None

    _write_baseline(baseline_path)
    _write_run(
        ledger_path=ledger_path,
        output_dir=output_dir,
        run_id="run-xss",
        findings=[finding_data],
    )

    with _client(
        ledger_path=ledger_path,
        output_dir=output_dir,
        baseline_path=baseline_path,
    ) as client:
        response = client.get("/")

    assert response.status_code == 200
    assert payload not in response.text
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in response.text
    assert response.headers["cache-control"] == "no-store"
    assert "script-src 'none'" in (
        response.headers["content-security-policy"]
    )


def test_post_without_valid_csrf_token_is_rejected(
    tmp_path: Path,
) -> None:
    ledger_path = tmp_path / "data" / "ledger.db"
    baseline_path = tmp_path / "data" / "baseline.json"
    output_dir = tmp_path / "output"
    finding = make_new_listener_finding(
        port="8080",
        owners=["service"],
    )
    finding_data = finding.to_dict()
    finding_data["triage"] = None

    _write_baseline(baseline_path)
    _write_run(
        ledger_path=ledger_path,
        output_dir=output_dir,
        run_id="run-csrf",
        findings=[finding_data],
    )

    with _client(
        ledger_path=ledger_path,
        output_dir=output_dir,
        baseline_path=baseline_path,
    ) as client:
        response = client.post(
            f"/findings/{finding.id}/acknowledge",
            data={},
            follow_redirects=False,
        )

    assert response.status_code == 403


def test_verdict_round_trip_targets_exact_prompt_hash(
    tmp_path: Path,
) -> None:
    ledger_path = tmp_path / "data" / "ledger.db"
    baseline_path = tmp_path / "data" / "baseline.json"
    output_dir = tmp_path / "output"
    finding = make_new_listener_finding(
        port="8080",
        owners=["service"],
    )
    finding_data = finding.to_dict()
    finding_data["triage"] = None

    _write_baseline(baseline_path)
    _write_run(
        ledger_path=ledger_path,
        output_dir=output_dir,
        run_id="run-verdict",
        findings=[finding_data],
    )

    older_hash = "a" * 64
    newer_hash = "b" * 64
    record_triage_annotation(
        path=ledger_path,
        annotation=_annotation(
            finding_id=finding.id,
            run_id="run-verdict",
            prompt_hash=older_hash,
            created_at=_CREATED_AT,
        ),
    )
    record_triage_annotation(
        path=ledger_path,
        annotation=_annotation(
            finding_id=finding.id,
            run_id="run-verdict",
            prompt_hash=newer_hash,
            created_at="2026-07-24T10:00:06-04:00",
        ),
    )

    with _client(
        ledger_path=ledger_path,
        output_dir=output_dir,
        baseline_path=baseline_path,
    ) as client:
        page = client.get(f"/findings/{finding.id}")
        token = _csrf_token(page.text)
        response = client.post(
            f"/triage/{finding.id}/verdict",
            data={
                "csrf_token": token,
                "prompt_hash": older_hash,
                "verdict": "accurate",
            },
            follow_redirects=False,
        )

    assert response.status_code == 303

    older = get_triage_annotation(
        path=ledger_path,
        finding_id=finding.id,
        prompt_hash=older_hash,
    )
    newer = get_triage_annotation(
        path=ledger_path,
        finding_id=finding.id,
        prompt_hash=newer_hash,
    )
    history = get_triage_verdict_history(
        path=ledger_path,
        finding_id=finding.id,
    )

    assert older is not None
    assert older.human_verdict == "accurate"
    assert newer is not None
    assert newer.human_verdict is None
    assert history[-1]["prompt_hash"] == older_hash
    assert history[-1]["verdict"] == "accurate"


def test_acknowledgement_round_trip_uses_shared_baseline_path(
    tmp_path: Path,
) -> None:
    ledger_path = tmp_path / "data" / "ledger.db"
    baseline_path = tmp_path / "data" / "baseline.json"
    output_dir = tmp_path / "output"
    finding = make_new_listener_finding(
        port="8080",
        owners=["service"],
    )
    finding_data = finding.to_dict()
    finding_data["triage"] = None

    _write_baseline(baseline_path)
    _write_run(
        ledger_path=ledger_path,
        output_dir=output_dir,
        run_id="run-ack",
        findings=[finding_data],
    )

    with _client(
        ledger_path=ledger_path,
        output_dir=output_dir,
        baseline_path=baseline_path,
    ) as client:
        page = client.get(f"/findings/{finding.id}")
        token = _csrf_token(page.text)
        response = client.post(
            f"/findings/{finding.id}/acknowledge",
            data={"csrf_token": token},
            follow_redirects=False,
        )

    assert response.status_code == 303
    baseline = load_baseline(baseline_path)
    assert baseline is not None
    assert finding.id in baseline["acknowledged_finding_ids"]


def test_missing_report_path_degrades_to_visible_state(
    tmp_path: Path,
) -> None:
    ledger_path = tmp_path / "data" / "ledger.db"
    baseline_path = tmp_path / "data" / "baseline.json"
    output_dir = tmp_path / "output"

    _write_baseline(baseline_path)
    _write_run(
        ledger_path=ledger_path,
        output_dir=output_dir,
        run_id="run-missing",
        findings=[],
        write_report=False,
    )

    with _client(
        ledger_path=ledger_path,
        output_dir=output_dir,
        baseline_path=baseline_path,
    ) as client:
        response = client.get("/runs/run-missing")

    assert response.status_code == 200
    assert "no longer exists" in response.text


def test_untrusted_host_header_is_rejected(
    tmp_path: Path,
) -> None:
    app = create_app(
        ledger_path=tmp_path / "ledger.db",
        output_dir=tmp_path / "output",
        baseline_path=tmp_path / "baseline.json",
        session_secret="phase2-test-secret",
        allowed_hosts=("127.0.0.1", "localhost"),
    )

    with TestClient(app, base_url="http://attacker.example") as client:
        response = client.get("/")

    assert response.status_code == 400


def test_cross_origin_post_is_rejected_even_with_valid_token(
    tmp_path: Path,
) -> None:
    ledger_path = tmp_path / "data" / "ledger.db"
    baseline_path = tmp_path / "data" / "baseline.json"
    output_dir = tmp_path / "output"
    finding = make_new_listener_finding(
        port="8080",
        owners=["service"],
    )
    finding_data = finding.to_dict()
    finding_data["triage"] = None

    _write_baseline(baseline_path)
    _write_run(
        ledger_path=ledger_path,
        output_dir=output_dir,
        run_id="run-origin",
        findings=[finding_data],
    )

    with _client(
        ledger_path=ledger_path,
        output_dir=output_dir,
        baseline_path=baseline_path,
    ) as client:
        page = client.get(f"/findings/{finding.id}")
        token = _csrf_token(page.text)
        response = client.post(
            f"/findings/{finding.id}/acknowledge",
            data={"csrf_token": token},
            headers={"Origin": "http://attacker.example"},
            follow_redirects=False,
        )

    assert response.status_code == 403


def test_report_path_outside_output_directory_is_not_opened(
    tmp_path: Path,
) -> None:
    ledger_path = tmp_path / "data" / "ledger.db"
    baseline_path = tmp_path / "data" / "baseline.json"
    output_dir = tmp_path / "output"
    outside_report = tmp_path / "report_outside.json"
    run_id = "run-outside"

    outside_report.write_text(
        json.dumps(
            {
                "run_id": run_id,
                "findings": [],
            }
        ),
        encoding="utf-8",
    )
    _write_baseline(baseline_path)
    init_ledger(ledger_path)
    start_run(
        path=ledger_path,
        run_id=run_id,
        started_at=_STARTED_AT,
        computer_name="test-mac",
    )
    finish_run(
        path=ledger_path,
        run_id=run_id,
        finished_at=_FINISHED_AT,
        overall_status="INFO",
        critical_count=0,
        warning_count=0,
        info_count=0,
        exit_code=0,
        report_txt_path=None,
        report_json_path=str(outside_report),
    )

    with _client(
        ledger_path=ledger_path,
        output_dir=output_dir,
        baseline_path=baseline_path,
    ) as client:
        response = client.get(f"/runs/{run_id}")

    assert response.status_code == 200
    assert "outside the configured output directory" in response.text
    assert outside_report.read_text(encoding="utf-8") not in response.text


def test_finding_page_survives_deleted_source_report_when_annotation_exists(
    tmp_path: Path,
) -> None:
    ledger_path = tmp_path / "data" / "ledger.db"
    baseline_path = tmp_path / "data" / "baseline.json"
    output_dir = tmp_path / "output"
    finding = make_new_listener_finding(
        port="8080",
        owners=["service"],
    )
    finding_data = finding.to_dict()
    finding_data["triage"] = None

    _write_baseline(baseline_path)
    report_path = _write_run(
        ledger_path=ledger_path,
        output_dir=output_dir,
        run_id="run-deleted-detail",
        findings=[finding_data],
    )
    record_triage_annotation(
        path=ledger_path,
        annotation=_annotation(
            finding_id=finding.id,
            run_id="run-deleted-detail",
            prompt_hash="c" * 64,
            created_at=_CREATED_AT,
        ),
    )
    report_path.unlink()

    with _client(
        ledger_path=ledger_path,
        output_dir=output_dir,
        baseline_path=baseline_path,
    ) as client:
        response = client.get(f"/findings/{finding.id}")

    assert response.status_code == 200
    assert "source report is unavailable" in response.text.lower()
    assert "gpt-test-2026-07-01" in response.text
