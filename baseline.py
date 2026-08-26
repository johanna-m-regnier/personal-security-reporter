from __future__ import annotations

import json
import os
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any

from findings import Finding, make_host_mismatch_finding
from models import HostState, ListenerSummary
from paths import BASELINE_PATH

BASELINE_SCHEMA_VERSION = 2


class BaselineError(Exception):
    """Raised when the stored security baseline cannot be used safely."""


def _normalize_timestamp(
    value: str,
    *,
    field_name: str,
) -> str:
    timestamp_text = value.strip()

    if not timestamp_text:
        raise BaselineError(
            f"Baseline field '{field_name}' is empty."
        )

    try:
        parsed = datetime.fromisoformat(timestamp_text)
    except ValueError as error:
        raise BaselineError(
            f"Baseline field '{field_name}' is not a valid "
            f"ISO 8601 timestamp: {timestamp_text}"
        ) from error

    if parsed.tzinfo is None:
        # A legacy V1 timestamp was stored as naive local time.
        # astimezone() interprets it in this Mac's local timezone and
        # attaches the correct UTC offset for that date.
        parsed = parsed.astimezone()

    return parsed.isoformat()


def _normalize_ports(
    value: Any,
    *,
    field_name: str,
) -> list[str]:
    if not isinstance(value, list):
        raise BaselineError(
            f"Baseline field '{field_name}' must be a list."
        )

    ports: set[str] = set()

    for raw_port in value:
        port = str(raw_port).strip()

        if not port or not port.isdigit():
            raise BaselineError(
                f"Baseline field '{field_name}' contains "
                f"an invalid port: {raw_port!r}"
            )

        ports.add(port)

    return sorted(ports, key=int)


def _normalize_owner_map(
    value: Any,
    *,
    field_name: str,
) -> dict[str, list[str]]:
    if not isinstance(value, dict):
        raise BaselineError(
            f"Baseline field '{field_name}' must be an object."
        )

    normalized: dict[str, list[str]] = {}

    for raw_port, raw_owners in value.items():
        port = str(raw_port).strip()

        if not port or not port.isdigit():
            raise BaselineError(
                f"Baseline field '{field_name}' contains "
                f"an invalid port key: {raw_port!r}"
            )

        if not isinstance(raw_owners, list):
            raise BaselineError(
                f"Baseline owners for port {port} must be a list."
            )

        owners = sorted(
            {
                str(owner).strip()
                for owner in raw_owners
                if str(owner).strip()
            }
        )

        if not owners:
            owners = ["Unknown process"]

        normalized[port] = owners

    return {
        port: normalized[port]
        for port in sorted(normalized, key=int)
    }


def _normalize_acknowledged_ids(
    value: Any,
) -> list[str]:
    if not isinstance(value, list):
        raise BaselineError(
            "Baseline field 'acknowledged_finding_ids' "
            "must be a list."
        )

    return sorted(
        {
            str(finding_id).strip()
            for finding_id in value
            if str(finding_id).strip()
        }
    )


def _normalize_host(
    value: Any,
) -> dict[str, str]:
    if not isinstance(value, dict):
        raise BaselineError(
            "Baseline field 'host' must be an object."
        )

    computer_name = str(
        value.get("computer_name", "")
    ).strip()

    operating_system = str(
        value.get("operating_system", "")
    ).strip()

    platform_system = str(
        value.get("platform_system", "")
    ).strip()

    if not computer_name:
        raise BaselineError(
            "Baseline host is missing 'computer_name'."
        )

    if not operating_system:
        raise BaselineError(
            "Baseline host is missing 'operating_system'."
        )

    if not platform_system:
        raise BaselineError(
            "Baseline host is missing 'platform_system'."
        )

    return {
        "computer_name": computer_name,
        "operating_system": operating_system,
        "platform_system": platform_system,
    }


def _normalize_v2_baseline(
    data: dict[str, Any],
) -> dict[str, Any]:
    created_at_value = data.get("created_at")

    if not isinstance(created_at_value, str):
        raise BaselineError(
            "Baseline is missing a valid 'created_at' timestamp."
        )

    updated_at_value = data.get(
        "updated_at",
        created_at_value,
    )

    if not isinstance(updated_at_value, str):
        raise BaselineError(
            "Baseline is missing a valid 'updated_at' timestamp."
        )

    return {
        "schema_version": BASELINE_SCHEMA_VERSION,
        "created_at": _normalize_timestamp(
            created_at_value,
            field_name="created_at",
        ),
        "updated_at": _normalize_timestamp(
            updated_at_value,
            field_name="updated_at",
        ),
        "host": _normalize_host(data.get("host")),
        "network_ports": _normalize_ports(
            data.get("network_ports", []),
            field_name="network_ports",
        ),
        "local_only_ports": _normalize_ports(
            data.get("local_only_ports", []),
            field_name="local_only_ports",
        ),
        "network_port_owners": _normalize_owner_map(
            data.get("network_port_owners", {}),
            field_name="network_port_owners",
        ),
        "acknowledged_finding_ids": (
            _normalize_acknowledged_ids(
                data.get(
                    "acknowledged_finding_ids",
                    [],
                )
            )
        ),
    }


def load_baseline(
    path: Path = BASELINE_PATH,
) -> dict[str, Any] | None:
    if not path.exists():
        return None

    try:
        raw_text = path.read_text(
            encoding="utf-8"
        )
    except OSError as error:
        raise BaselineError(
            f"Could not read baseline at {path}: {error}"
        ) from error

    try:
        data = json.loads(raw_text)
    except json.JSONDecodeError as error:
        raise BaselineError(
            f"Baseline at {path} contains invalid JSON: "
            f"{error}"
        ) from error

    if not isinstance(data, dict):
        raise BaselineError(
            f"Baseline at {path} must contain a JSON object."
        )

    return data


def migrate_baseline(
    data: dict[str, Any],
) -> dict[str, Any]:
    raw_version = data.get("schema_version")

    if raw_version is None or raw_version == 1:
        created_at = data.get("created_at")

        if not isinstance(created_at, str):
            raise BaselineError(
                "Legacy baseline is missing a valid "
                "'created_at' timestamp."
            )

        migrated = {
            "schema_version": BASELINE_SCHEMA_VERSION,
            "created_at": created_at,
            # Migration is not a new observation.
            "updated_at": created_at,
            "host": {
                "computer_name": data.get(
                    "computer_name",
                    "",
                ),
                "operating_system": data.get(
                    "operating_system",
                    "",
                ),
                "platform_system": data.get(
                    "platform_system",
                    "Darwin",
                ),
            },
            "network_ports": data.get(
                "network_ports",
                [],
            ),
            "local_only_ports": data.get(
                "local_only_ports",
                [],
            ),
            "network_port_owners": data.get(
                "network_port_owners",
                {},
            ),
            "acknowledged_finding_ids": data.get(
                "acknowledged_finding_ids",
                [],
            ),
        }

        return _normalize_v2_baseline(migrated)

    if not isinstance(raw_version, int):
        raise BaselineError(
            "Baseline 'schema_version' must be an integer."
        )

    if raw_version > BASELINE_SCHEMA_VERSION:
        raise BaselineError(
            "Baseline schema version "
            f"{raw_version} is newer than the supported "
            f"version {BASELINE_SCHEMA_VERSION}."
        )

    if raw_version != BASELINE_SCHEMA_VERSION:
        raise BaselineError(
            "Unsupported baseline schema version: "
            f"{raw_version}"
        )

    return _normalize_v2_baseline(data)


def save_baseline(
    data: dict[str, Any],
    path: Path = BASELINE_PATH,
) -> None:
    normalized = migrate_baseline(data)

    try:
        path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )
    except OSError as error:
        raise BaselineError(
            f"Could not create baseline directory "
            f"{path.parent}: {error}"
        ) from error

    temporary_path: Path | None = None

    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as temporary_file:
            temporary_path = Path(
                temporary_file.name
            )

            json.dump(
                normalized,
                temporary_file,
                indent=4,
                ensure_ascii=False,
            )

            temporary_file.write("\n")
            temporary_file.flush()
            os.fsync(temporary_file.fileno())

        os.replace(
            temporary_path,
            path,
        )

    except (OSError, TypeError, ValueError) as error:
        if temporary_path is not None:
            try:
                temporary_path.unlink(
                    missing_ok=True
                )
            except OSError:
                pass

        raise BaselineError(
            f"Could not save baseline at {path}: {error}"
        ) from error


def acknowledge_findings(
    finding_ids: list[str],
    path: Path = BASELINE_PATH,
) -> tuple[list[str], list[str]]:
    """Persist finding acknowledgements in the shared baseline.

    Returns two sorted lists: newly acknowledged IDs and IDs that
    were already acknowledged. Both the CLI and web dashboard call
    this function so acknowledgement semantics cannot diverge.
    """

    normalized_ids = sorted(
        {
            str(finding_id).strip()
            for finding_id in finding_ids
            if str(finding_id).strip()
        }
    )

    if not normalized_ids:
        raise BaselineError(
            "At least one finding ID is required for acknowledgement."
        )

    existing = load_baseline(path)

    if existing is None:
        raise BaselineError(
            "Cannot acknowledge findings because no "
            f"baseline exists at {path}."
        )

    baseline = migrate_baseline(existing)
    acknowledged_ids = set(
        baseline.get(
            "acknowledged_finding_ids",
            [],
        )
    )

    newly_acknowledged: list[str] = []
    already_acknowledged: list[str] = []

    for finding_id in normalized_ids:
        if finding_id in acknowledged_ids:
            already_acknowledged.append(finding_id)
            continue

        acknowledged_ids.add(finding_id)
        newly_acknowledged.append(finding_id)

    baseline["acknowledged_finding_ids"] = sorted(
        acknowledged_ids
    )

    if newly_acknowledged or baseline != existing:
        save_baseline(
            data=baseline,
            path=path,
        )

    return newly_acknowledged, already_acknowledged


def build_baseline(
    host_state: HostState,
    listeners: ListenerSummary,
    now_iso: str,
) -> dict[str, Any]:
    normalized_now = _normalize_timestamp(
        now_iso,
        field_name="now_iso",
    )

    baseline = {
        "schema_version": BASELINE_SCHEMA_VERSION,
        "created_at": normalized_now,
        "updated_at": normalized_now,
        "host": {
            "computer_name": (
                host_state.computer_name
            ),
            "operating_system": (
                host_state.operating_system
            ),
            "platform_system": (
                host_state.platform_system
            ),
        },
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
        "acknowledged_finding_ids": [],
    }

    return _normalize_v2_baseline(baseline)


def update_baseline(
    existing: dict[str, Any],
    listeners: ListenerSummary,
    now_iso: str,
) -> dict[str, Any]:
    baseline = migrate_baseline(existing)

    updated = {
        **baseline,
        "updated_at": _normalize_timestamp(
            now_iso,
            field_name="now_iso",
        ),
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
        "acknowledged_finding_ids": list(
            baseline[
                "acknowledged_finding_ids"
            ]
        ),
    }

    return _normalize_v2_baseline(updated)


def check_host_matches(
    baseline: dict[str, Any],
    computer_name: str,
) -> Finding | None:
    normalized = migrate_baseline(baseline)

    expected_name = normalized["host"][
        "computer_name"
    ]

    actual_name = computer_name.strip()

    if expected_name == actual_name:
        return None

    return make_host_mismatch_finding(
        expected=expected_name,
        actual=actual_name,
    )