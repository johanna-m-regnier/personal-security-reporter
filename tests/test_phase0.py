from __future__ import annotations

import argparse
import json
from pathlib import Path

import main
from config import ConfigError
from findings import make_new_listener_finding
from models import HostState, ListenerSummary


def _host_state() -> HostState:
    listeners = ListenerSummary(
        records=[],
        socket_count=0,
        network_ports=[],
        local_only_ports=[],
        network_port_owners={},
        local_only_port_owners={},
    )

    return HostState(
        computer_name="test-mac",
        operating_system="macOS test",
        platform_system="Darwin",
        current_user="tester",
        uptime_text="1 day",
        process_count=0,
        top_processes=[],
        disk=None,
        listeners=listeners,
    )


def test_missing_baseline_is_not_created_without_update_flag() -> None:
    evaluation = main.evaluate(
        host_state=_host_state(),
        baseline=None,
        existing_findings=[],
        now_iso="2026-07-24T10:00:00-04:00",
        baseline_update_requested=False,
    )

    assert evaluation.baseline_to_save is None
    assert "--update-baseline" in evaluation.baseline_status
    assert evaluation.comparison_performed is False


def test_update_flag_builds_and_persists_initial_baseline(
    tmp_path: Path,
) -> None:
    host_state = _host_state()
    baseline_path = tmp_path / "data" / "baseline.json"

    evaluation = main.evaluate(
        host_state=host_state,
        baseline=None,
        existing_findings=[],
        now_iso="2026-07-24T10:00:00-04:00",
        baseline_update_requested=True,
    )

    assert evaluation.baseline_to_save is not None
    assert not baseline_path.exists()

    saved = main._apply_baseline_update_gate(
        update_requested=True,
        force=False,
        evaluation=evaluation,
        baseline=None,
        host_state=host_state,
        baseline_path=baseline_path,
        now_iso="2026-07-24T10:00:01-04:00",
    )

    assert saved == evaluation.baseline_to_save
    assert json.loads(
        baseline_path.read_text(encoding="utf-8")
    ) == saved


def test_baseline_gate_does_not_write_without_explicit_request(
    tmp_path: Path,
    monkeypatch,
) -> None:
    host_state = _host_state()

    evaluation = main.evaluate(
        host_state=host_state,
        baseline=None,
        existing_findings=[],
        now_iso="2026-07-24T10:00:00-04:00",
        baseline_update_requested=True,
    )

    def fail_save(*args, **kwargs) -> None:
        raise AssertionError("save_baseline must not be called")

    monkeypatch.setattr(main, "save_baseline", fail_save)

    assert main._apply_baseline_update_gate(
        update_requested=False,
        force=False,
        evaluation=evaluation,
        baseline=None,
        host_state=host_state,
        baseline_path=tmp_path / "baseline.json",
        now_iso="2026-07-24T10:00:01-04:00",
    ) is None


def test_update_gate_refuses_unacknowledged_warning_without_force(
    tmp_path: Path,
    monkeypatch,
) -> None:
    host_state = _host_state()
    warning = make_new_listener_finding(
        port="0.0.0.0:8080",
        owners=["test-service"],
    )

    evaluation = main.evaluate(
        host_state=host_state,
        baseline=None,
        existing_findings=[warning],
        now_iso="2026-07-24T10:00:00-04:00",
        baseline_update_requested=True,
    )

    def fail_save(*args, **kwargs) -> None:
        raise AssertionError("save_baseline must not be called")

    monkeypatch.setattr(main, "save_baseline", fail_save)

    try:
        main._apply_baseline_update_gate(
            update_requested=True,
            force=False,
            evaluation=evaluation,
            baseline=None,
            host_state=host_state,
            baseline_path=tmp_path / "baseline.json",
            now_iso="2026-07-24T10:00:01-04:00",
        )
    except main.BaselineError as error:
        assert warning.id in str(error)
        assert "--force" in str(error)
    else:
        raise AssertionError("Expected BaselineError")


def test_fatal_error_writes_last_run_status(
    tmp_path: Path,
    monkeypatch,
) -> None:
    status_path = tmp_path / "output" / "LAST_RUN_STATUS.txt"

    args = argparse.Namespace(
        history=None,
        acknowledge=None,
        review=None,
        verdict=None,
        update_baseline=False,
        force=False,
        no_email=False,
        quiet=True,
        baseline_path=tmp_path / "data" / "baseline.json",
    )

    def fail_config() -> None:
        raise ConfigError("missing test credentials")

    monkeypatch.setattr(main, "STATUS_PATH", status_path)
    monkeypatch.setattr(main, "parse_args", lambda: args)
    monkeypatch.setattr(main, "load_email_config", fail_config)

    assert main.main() == main.EXIT_FATAL

    status = status_path.read_text(encoding="utf-8")

    assert "Overall status: [FATAL]" in status
    assert f"Exit code: {main.EXIT_FATAL}" in status
    assert "Delivery status: not attempted" in status
    assert "Fatal error: missing test credentials" in status
