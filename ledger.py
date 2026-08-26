from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Any

from models import (
    TRIAGE_VERDICTS,
    TriageAnnotation,
    TriageResponse,
)

_ALLOWED_DELIVERY_STATUSES = {
    "sent",
    "failed",
    "skipped",
}

_ALLOWED_OVERALL_STATUSES = {
    "INFO",
    "WARNING",
    "CRITICAL",
}


class LedgerError(Exception):
    """Raised when the durable run ledger cannot be read or updated."""


@contextmanager
def _open_connection(
    path: Path,
) -> Iterator[sqlite3.Connection]:
    connection: sqlite3.Connection | None = None

    try:
        connection = sqlite3.connect(
            path,
            timeout=30.0,
        )

        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")

        yield connection

        connection.commit()

    except sqlite3.Error as error:
        if connection is not None:
            connection.rollback()

        raise LedgerError(
            f"Ledger operation failed at {path}: {error}"
        ) from error

    except Exception:
        if connection is not None:
            connection.rollback()

        raise

    finally:
        if connection is not None:
            connection.close()


def _validate_required_text(
    value: str,
    *,
    field_name: str,
) -> str:
    normalized = value.strip()

    if not normalized:
        raise LedgerError(
            f"Ledger field '{field_name}' cannot be empty."
        )

    return normalized


def _validate_timestamp(
    value: str,
    *,
    field_name: str,
) -> str:
    normalized = _validate_required_text(
        value,
        field_name=field_name,
    )

    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as error:
        raise LedgerError(
            f"Ledger field '{field_name}' is not a valid "
            f"ISO 8601 timestamp: {normalized}"
        ) from error

    if parsed.tzinfo is None:
        raise LedgerError(
            f"Ledger field '{field_name}' must include "
            "a UTC offset."
        )

    return parsed.isoformat()


def _validate_optional_count(
    value: int | None,
    *,
    field_name: str,
) -> int | None:
    if value is None:
        return None

    if value < 0:
        raise LedgerError(
            f"Ledger field '{field_name}' cannot be negative."
        )

    return value


def _row_to_dict(
    row: sqlite3.Row,
) -> dict[str, Any]:
    return {
        key: row[key]
        for key in row.keys()  # noqa: SIM118
    }


def _table_exists(
    connection: sqlite3.Connection,
    table_name: str,
) -> bool:
    row = connection.execute(
        """
        SELECT 1
        FROM sqlite_master
        WHERE type = 'table' AND name = ?
        """,
        (table_name,),
    ).fetchone()

    return row is not None


def _create_triage_tables(
    connection: sqlite3.Connection,
) -> None:
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS triage (
            finding_id        TEXT NOT NULL,
            run_id            TEXT NOT NULL,
            model             TEXT NOT NULL,
            prompt_hash       TEXT NOT NULL,
            response          TEXT NOT NULL,
            created_at        TEXT NOT NULL,
            human_verdict     TEXT,
            verdict_at        TEXT,
            PRIMARY KEY (finding_id, prompt_hash),
            FOREIGN KEY (run_id)
                REFERENCES runs (run_id),
            CHECK (
                human_verdict IS NULL
                OR human_verdict IN (
                    'accurate',
                    'wrong',
                    'unsure'
                )
            )
        )
        """
    )

    connection.execute(
        """
        CREATE INDEX IF NOT EXISTS
            idx_triage_run_id_v2
        ON triage (run_id)
        """
    )

    connection.execute(
        """
        CREATE INDEX IF NOT EXISTS
            idx_triage_finding_created_v2
        ON triage (finding_id, created_at DESC)
        """
    )

    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS triage_verdicts (
            verdict_id        INTEGER PRIMARY KEY AUTOINCREMENT,
            finding_id        TEXT NOT NULL,
            prompt_hash       TEXT NOT NULL,
            verdict           TEXT NOT NULL,
            verdict_at        TEXT NOT NULL,
            FOREIGN KEY (finding_id, prompt_hash)
                REFERENCES triage (finding_id, prompt_hash),
            CHECK (
                verdict IN (
                    'accurate',
                    'wrong',
                    'unsure'
                )
            )
        )
        """
    )

    connection.execute(
        """
        CREATE INDEX IF NOT EXISTS
            idx_triage_verdicts_annotation_v2
        ON triage_verdicts (
            finding_id,
            prompt_hash,
            verdict_id
        )
        """
    )


def _migrate_legacy_triage_schema(
    connection: sqlite3.Connection,
) -> None:
    if not _table_exists(connection, "triage"):
        return

    table_info = connection.execute(
        "PRAGMA table_info(triage)"
    ).fetchall()
    primary_key_columns = [
        str(row["name"])
        for row in sorted(
            (
                row
                for row in table_info
                if int(row["pk"]) > 0
            ),
            key=lambda row: int(row["pk"]),
        )
    ]

    if primary_key_columns == [
        "finding_id",
        "prompt_hash",
    ]:
        return

    if primary_key_columns != ["finding_id"]:
        raise LedgerError(
            "Unsupported triage ledger schema; expected legacy "
            "primary key finding_id or current composite key."
        )

    has_verdict_history = _table_exists(
        connection,
        "triage_verdicts",
    )

    connection.execute(
        "DROP INDEX IF EXISTS idx_triage_run_id"
    )
    connection.execute(
        "DROP INDEX IF EXISTS idx_triage_verdicts_finding"
    )

    if has_verdict_history:
        connection.execute(
            """
            ALTER TABLE triage_verdicts
            RENAME TO triage_verdicts_legacy
            """
        )

    connection.execute(
        "ALTER TABLE triage RENAME TO triage_legacy"
    )

    _create_triage_tables(connection)

    connection.execute(
        """
        INSERT INTO triage (
            finding_id,
            run_id,
            model,
            prompt_hash,
            response,
            created_at,
            human_verdict,
            verdict_at
        )
        SELECT
            finding_id,
            run_id,
            model,
            prompt_hash,
            response,
            created_at,
            human_verdict,
            verdict_at
        FROM triage_legacy
        """
    )

    if has_verdict_history:
        connection.execute(
            """
            INSERT INTO triage_verdicts (
                finding_id,
                prompt_hash,
                verdict,
                verdict_at
            )
            SELECT
                verdicts.finding_id,
                annotations.prompt_hash,
                verdicts.verdict,
                verdicts.verdict_at
            FROM triage_verdicts_legacy AS verdicts
            JOIN triage_legacy AS annotations
                ON annotations.finding_id = verdicts.finding_id
            ORDER BY verdicts.verdict_id ASC
            """
        )
        connection.execute(
            "DROP TABLE triage_verdicts_legacy"
        )

    connection.execute("DROP TABLE triage_legacy")


def init_ledger(
    path: Path,
) -> None:
    try:
        path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )
    except OSError as error:
        raise LedgerError(
            f"Could not create ledger directory "
            f"{path.parent}: {error}"
        ) from error

    with _open_connection(path) as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS runs (
                run_id            TEXT PRIMARY KEY,
                started_at        TEXT NOT NULL,
                finished_at       TEXT,
                computer_name     TEXT NOT NULL,
                overall_status    TEXT,
                critical_count    INTEGER,
                warning_count     INTEGER,
                info_count        INTEGER,
                exit_code         INTEGER,
                report_txt_path   TEXT,
                report_json_path  TEXT,
                delivery_status   TEXT,
                delivery_error    TEXT,
                delivered_at      TEXT,
                catchup_reported  INTEGER NOT NULL DEFAULT 0
            )
            """
        )

        connection.execute(
            """
            CREATE INDEX IF NOT EXISTS
                idx_runs_catchup
            ON runs (
                catchup_reported,
                delivery_status,
                finished_at
            )
            """
        )

        _migrate_legacy_triage_schema(connection)
        _create_triage_tables(connection)


def start_run(
    path: Path,
    run_id: str,
    started_at: str,
    computer_name: str,
) -> None:
    normalized_run_id = _validate_required_text(
        run_id,
        field_name="run_id",
    )

    normalized_started_at = _validate_timestamp(
        started_at,
        field_name="started_at",
    )

    normalized_computer_name = (
        _validate_required_text(
            computer_name,
            field_name="computer_name",
        )
    )

    with _open_connection(path) as connection:
        connection.execute(
            """
            INSERT INTO runs (
                run_id,
                started_at,
                computer_name
            )
            VALUES (?, ?, ?)
            """,
            (
                normalized_run_id,
                normalized_started_at,
                normalized_computer_name,
            ),
        )


def finish_run(
    path: Path,
    run_id: str,
    finished_at: str,
    overall_status: str | None,
    critical_count: int | None,
    warning_count: int | None,
    info_count: int | None,
    exit_code: int,
    report_txt_path: str | None,
    report_json_path: str | None,
) -> None:
    normalized_run_id = _validate_required_text(
        run_id,
        field_name="run_id",
    )

    normalized_finished_at = _validate_timestamp(
        finished_at,
        field_name="finished_at",
    )

    if (
        overall_status is not None
        and overall_status
        not in _ALLOWED_OVERALL_STATUSES
    ):
        raise LedgerError(
            "Ledger field 'overall_status' must be "
            "INFO, WARNING, CRITICAL, or None."
        )

    normalized_critical_count = (
        _validate_optional_count(
            critical_count,
            field_name="critical_count",
        )
    )

    normalized_warning_count = (
        _validate_optional_count(
            warning_count,
            field_name="warning_count",
        )
    )

    normalized_info_count = (
        _validate_optional_count(
            info_count,
            field_name="info_count",
        )
    )

    if exit_code not in {0, 1, 2, 3}:
        raise LedgerError(
            "Ledger field 'exit_code' must be "
            "0, 1, 2, or 3."
        )

    with _open_connection(path) as connection:
        cursor = connection.execute(
            """
            UPDATE runs
            SET
                finished_at = ?,
                overall_status = ?,
                critical_count = ?,
                warning_count = ?,
                info_count = ?,
                exit_code = ?,
                report_txt_path = ?,
                report_json_path = ?
            WHERE run_id = ?
            """,
            (
                normalized_finished_at,
                overall_status,
                normalized_critical_count,
                normalized_warning_count,
                normalized_info_count,
                exit_code,
                report_txt_path,
                report_json_path,
                normalized_run_id,
            ),
        )

        if cursor.rowcount != 1:
            raise LedgerError(
                "Cannot finish unknown ledger run: "
                f"{normalized_run_id}"
            )


def record_delivery(
    path: Path,
    run_id: str,
    status: str,
    error: str | None,
) -> None:
    normalized_run_id = _validate_required_text(
        run_id,
        field_name="run_id",
    )

    normalized_status = _validate_required_text(
        status,
        field_name="delivery_status",
    )

    if normalized_status not in _ALLOWED_DELIVERY_STATUSES:
        raise LedgerError(
            "Delivery status must be "
            "'sent', 'failed', or 'skipped'."
        )

    if normalized_status == "sent":
        delivered_at = (
            datetime.now()
            .astimezone()
            .isoformat()
        )
        delivery_error = None
    elif normalized_status == "failed":
        delivered_at = None
        delivery_error = (
            error.strip()
            if error and error.strip()
            else "Unknown delivery error"
        )
    else:
        delivered_at = None
        delivery_error = None

    with _open_connection(path) as connection:
        cursor = connection.execute(
            """
            UPDATE runs
            SET
                delivery_status = ?,
                delivery_error = ?,
                delivered_at = ?
            WHERE run_id = ?
            """,
            (
                normalized_status,
                delivery_error,
                delivered_at,
                normalized_run_id,
            ),
        )

        if cursor.rowcount != 1:
            raise LedgerError(
                "Cannot record delivery for unknown run: "
                f"{normalized_run_id}"
            )


def get_undelivered_runs(
    path: Path,
) -> list[dict[str, Any]]:
    """
    Return prior runs that need catch-up reporting.

    Included:
    - runs that never reached finish_run()
    - runs whose email delivery failed
    - finished runs whose delivery outcome was never recorded

    Deliberately excluded:
    - successfully delivered runs
    - runs intentionally executed with --no-email
    - runs already included in a successful catch-up report
    """

    with _open_connection(path) as connection:
        rows = connection.execute(
            """
            SELECT
                run_id,
                started_at,
                finished_at,
                computer_name,
                overall_status,
                critical_count,
                warning_count,
                info_count,
                exit_code,
                report_txt_path,
                report_json_path,
                delivery_status,
                delivery_error,
                delivered_at,
                catchup_reported
            FROM runs
            WHERE
                catchup_reported = 0
                AND (
                    finished_at IS NULL
                    OR delivery_status = 'failed'
                    OR delivery_status IS NULL
                )
            ORDER BY rowid ASC
            """
        ).fetchall()

    return [
        _row_to_dict(row)
        for row in rows
    ]


def mark_catchup_reported(
    path: Path,
    run_ids: list[str],
) -> None:
    normalized_run_ids = sorted(
        {
            run_id.strip()
            for run_id in run_ids
            if run_id.strip()
        }
    )

    if not normalized_run_ids:
        return

    with _open_connection(path) as connection:
        connection.executemany(
            """
            UPDATE runs
            SET catchup_reported = 1
            WHERE run_id = ?
            """,
            [
                (run_id,)
                for run_id in normalized_run_ids
            ],
        )


def get_recent_runs(
    path: Path,
    n: int,
) -> list[dict[str, Any]]:
    if n < 1:
        raise LedgerError(
            "History limit must be at least 1."
        )

    with _open_connection(path) as connection:
        rows = connection.execute(
            """
            SELECT
                run_id,
                started_at,
                finished_at,
                computer_name,
                overall_status,
                critical_count,
                warning_count,
                info_count,
                exit_code,
                report_txt_path,
                report_json_path,
                delivery_status,
                delivery_error,
                delivered_at,
                catchup_reported
            FROM runs
            ORDER BY rowid DESC
            LIMIT ?
            """,
            (n,),
        ).fetchall()

    return [
        _row_to_dict(row)
        for row in rows
    ]


def get_runs(
    path: Path,
) -> list[dict[str, Any]]:
    """Return all ledger runs, newest first."""

    with _open_connection(path) as connection:
        rows = connection.execute(
            """
            SELECT
                run_id,
                started_at,
                finished_at,
                computer_name,
                overall_status,
                critical_count,
                warning_count,
                info_count,
                exit_code,
                report_txt_path,
                report_json_path,
                delivery_status,
                delivery_error,
                delivered_at,
                catchup_reported
            FROM runs
            ORDER BY rowid DESC
            """
        ).fetchall()

    return [
        _row_to_dict(row)
        for row in rows
    ]


def get_run(
    path: Path,
    run_id: str,
) -> dict[str, Any] | None:
    normalized_run_id = _validate_required_text(
        run_id,
        field_name="run_id",
    )

    with _open_connection(path) as connection:
        row = connection.execute(
            """
            SELECT
                run_id,
                started_at,
                finished_at,
                computer_name,
                overall_status,
                critical_count,
                warning_count,
                info_count,
                exit_code,
                report_txt_path,
                report_json_path,
                delivery_status,
                delivery_error,
                delivered_at,
                catchup_reported
            FROM runs
            WHERE run_id = ?
            """,
            (normalized_run_id,),
        ).fetchone()

    if row is None:
        return None

    return _row_to_dict(row)


def _validate_verdict(
    verdict: str,
) -> str:
    normalized = _validate_required_text(
        verdict,
        field_name="human_verdict",
    ).lower()

    if normalized not in TRIAGE_VERDICTS:
        raise LedgerError(
            "Human verdict must be accurate, wrong, or unsure."
        )

    return normalized


def _triage_row_to_annotation(
    row: sqlite3.Row,
) -> TriageAnnotation:
    try:
        raw_response = json.loads(row["response"])
    except json.JSONDecodeError as error:
        raise LedgerError(
            "Stored triage response for finding "
            f"{row['finding_id']} is invalid JSON."
        ) from error

    if not isinstance(raw_response, dict):
        raise LedgerError(
            "Stored triage response for finding "
            f"{row['finding_id']} is not a JSON object."
        )

    try:
        response = TriageResponse.from_dict(raw_response)
    except (TypeError, ValueError) as error:
        raise LedgerError(
            "Stored triage response for finding "
            f"{row['finding_id']} is invalid: {error}"
        ) from error

    human_verdict = row["human_verdict"]

    if human_verdict is not None:
        human_verdict = _validate_verdict(
            str(human_verdict)
        )

    verdict_at = row["verdict_at"]

    if verdict_at is not None:
        verdict_at = _validate_timestamp(
            str(verdict_at),
            field_name="verdict_at",
        )

    return TriageAnnotation(
        finding_id=str(row["finding_id"]),
        run_id=str(row["run_id"]),
        model=str(row["model"]),
        prompt_hash=str(row["prompt_hash"]),
        response=response,
        created_at=_validate_timestamp(
            str(row["created_at"]),
            field_name="created_at",
        ),
        human_verdict=human_verdict,
        verdict_at=verdict_at,
    )


def get_triage_annotation(
    path: Path,
    finding_id: str,
    prompt_hash: str | None = None,
) -> TriageAnnotation | None:
    normalized_finding_id = _validate_required_text(
        finding_id,
        field_name="finding_id",
    )

    with _open_connection(path) as connection:
        if prompt_hash is None:
            row = connection.execute(
                """
                SELECT
                    finding_id,
                    run_id,
                    model,
                    prompt_hash,
                    response,
                    created_at,
                    human_verdict,
                    verdict_at
                FROM triage
                WHERE finding_id = ?
                ORDER BY created_at DESC, rowid DESC
                LIMIT 1
                """,
                (normalized_finding_id,),
            ).fetchone()
        else:
            normalized_prompt_hash = _validate_required_text(
                prompt_hash,
                field_name="prompt_hash",
            )
            row = connection.execute(
                """
                SELECT
                    finding_id,
                    run_id,
                    model,
                    prompt_hash,
                    response,
                    created_at,
                    human_verdict,
                    verdict_at
                FROM triage
                WHERE finding_id = ? AND prompt_hash = ?
                """,
                (
                    normalized_finding_id,
                    normalized_prompt_hash,
                ),
            ).fetchone()

    if row is None:
        return None

    return _triage_row_to_annotation(row)


def get_triage_annotations(
    path: Path,
    cache_keys: list[tuple[str, str]],
) -> dict[tuple[str, str], TriageAnnotation]:
    normalized_keys = sorted(
        {
            (
                _validate_required_text(
                    finding_id,
                    field_name="finding_id",
                ),
                _validate_required_text(
                    prompt_hash,
                    field_name="prompt_hash",
                ),
            )
            for finding_id, prompt_hash in cache_keys
        }
    )

    if not normalized_keys:
        return {}

    predicates = " OR ".join(
        "(finding_id = ? AND prompt_hash = ?)"
        for _ in normalized_keys
    )
    parameters = tuple(
        value
        for cache_key in normalized_keys
        for value in cache_key
    )

    with _open_connection(path) as connection:
        rows = connection.execute(
            f"""
            SELECT
                finding_id,
                run_id,
                model,
                prompt_hash,
                response,
                created_at,
                human_verdict,
                verdict_at
            FROM triage
            WHERE {predicates}
            """,
            parameters,
        ).fetchall()

    annotations = [
        _triage_row_to_annotation(row)
        for row in rows
    ]

    return {
        (
            annotation.finding_id,
            annotation.prompt_hash,
        ): annotation
        for annotation in annotations
    }


def get_triage_annotation_history(
    path: Path,
    finding_id: str,
) -> list[TriageAnnotation]:
    normalized_finding_id = _validate_required_text(
        finding_id,
        field_name="finding_id",
    )

    with _open_connection(path) as connection:
        rows = connection.execute(
            """
            SELECT
                finding_id,
                run_id,
                model,
                prompt_hash,
                response,
                created_at,
                human_verdict,
                verdict_at
            FROM triage
            WHERE finding_id = ?
            ORDER BY created_at DESC, rowid DESC
            """,
            (normalized_finding_id,),
        ).fetchall()

    return [
        _triage_row_to_annotation(row)
        for row in rows
    ]


def record_triage_annotation(
    path: Path,
    annotation: TriageAnnotation,
) -> None:
    finding_id = _validate_required_text(
        annotation.finding_id,
        field_name="finding_id",
    )
    run_id = _validate_required_text(
        annotation.run_id,
        field_name="run_id",
    )
    model = _validate_required_text(
        annotation.model,
        field_name="model",
    )
    prompt_hash = _validate_required_text(
        annotation.prompt_hash,
        field_name="prompt_hash",
    )
    created_at = _validate_timestamp(
        annotation.created_at,
        field_name="created_at",
    )

    if annotation.human_verdict is not None:
        raise LedgerError(
            "New triage annotations cannot include a human verdict."
        )

    if annotation.verdict_at is not None:
        raise LedgerError(
            "New triage annotations cannot include a verdict timestamp."
        )

    response_text = json.dumps(
        annotation.response.to_dict(),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )

    with _open_connection(path) as connection:
        try:
            connection.execute(
                """
                INSERT INTO triage (
                    finding_id,
                    run_id,
                    model,
                    prompt_hash,
                    response,
                    created_at,
                    human_verdict,
                    verdict_at
                )
                VALUES (?, ?, ?, ?, ?, ?, NULL, NULL)
                """,
                (
                    finding_id,
                    run_id,
                    model,
                    prompt_hash,
                    response_text,
                    created_at,
                ),
            )
        except sqlite3.IntegrityError as error:
            if (
                "UNIQUE constraint failed: triage.finding_id, "
                "triage.prompt_hash"
                in str(error)
            ):
                raise LedgerError(
                    "A triage annotation already exists for finding "
                    f"{finding_id} and prompt hash {prompt_hash}; "
                    "model responses are immutable."
                ) from error

            raise


def record_triage_verdict(
    path: Path,
    finding_id: str,
    verdict: str,
    verdict_at: str,
    prompt_hash: str | None = None,
) -> TriageAnnotation:
    normalized_finding_id = _validate_required_text(
        finding_id,
        field_name="finding_id",
    )
    normalized_verdict = _validate_verdict(verdict)
    normalized_verdict_at = _validate_timestamp(
        verdict_at,
        field_name="verdict_at",
    )

    normalized_prompt_hash = (
        _validate_required_text(
            prompt_hash,
            field_name="prompt_hash",
        )
        if prompt_hash is not None
        else None
    )

    with _open_connection(path) as connection:
        if normalized_prompt_hash is None:
            target = connection.execute(
                """
                SELECT prompt_hash
                FROM triage
                WHERE finding_id = ?
                ORDER BY created_at DESC, rowid DESC
                LIMIT 1
                """,
                (normalized_finding_id,),
            ).fetchone()

            if target is None:
                raise LedgerError(
                    "Cannot review unknown triage finding: "
                    f"{normalized_finding_id}"
                )

            normalized_prompt_hash = str(
                target["prompt_hash"]
            )
        else:
            target = connection.execute(
                """
                SELECT 1
                FROM triage
                WHERE finding_id = ? AND prompt_hash = ?
                """,
                (
                    normalized_finding_id,
                    normalized_prompt_hash,
                ),
            ).fetchone()

            if target is None:
                raise LedgerError(
                    "Cannot review unknown triage annotation: "
                    f"{normalized_finding_id}/"
                    f"{normalized_prompt_hash}"
                )

        cursor = connection.execute(
            """
            UPDATE triage
            SET
                human_verdict = ?,
                verdict_at = ?
            WHERE finding_id = ? AND prompt_hash = ?
            """,
            (
                normalized_verdict,
                normalized_verdict_at,
                normalized_finding_id,
                normalized_prompt_hash,
            ),
        )

        if cursor.rowcount != 1:
            raise LedgerError(
                "Cannot review unknown triage annotation: "
                f"{normalized_finding_id}/"
                f"{normalized_prompt_hash}"
            )

        connection.execute(
            """
            INSERT INTO triage_verdicts (
                finding_id,
                prompt_hash,
                verdict,
                verdict_at
            )
            VALUES (?, ?, ?, ?)
            """,
            (
                normalized_finding_id,
                normalized_prompt_hash,
                normalized_verdict,
                normalized_verdict_at,
            ),
        )

        row = connection.execute(
            """
            SELECT
                finding_id,
                run_id,
                model,
                prompt_hash,
                response,
                created_at,
                human_verdict,
                verdict_at
            FROM triage
            WHERE finding_id = ? AND prompt_hash = ?
            """,
            (
                normalized_finding_id,
                normalized_prompt_hash,
            ),
        ).fetchone()

    if row is None:
        raise LedgerError(
            "Reviewed triage annotation disappeared unexpectedly: "
            f"{normalized_finding_id}/"
            f"{normalized_prompt_hash}"
        )

    return _triage_row_to_annotation(row)


def get_triage_verdict_history(
    path: Path,
    finding_id: str,
) -> list[dict[str, Any]]:
    normalized_finding_id = _validate_required_text(
        finding_id,
        field_name="finding_id",
    )

    with _open_connection(path) as connection:
        rows = connection.execute(
            """
            SELECT
                verdict_id,
                finding_id,
                prompt_hash,
                verdict,
                verdict_at
            FROM triage_verdicts
            WHERE finding_id = ?
            ORDER BY verdict_id ASC
            """,
            (normalized_finding_id,),
        ).fetchall()

    return [
        _row_to_dict(row)
        for row in rows
    ]
