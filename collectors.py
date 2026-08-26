from __future__ import annotations

import getpass
import platform
import shlex
import shutil
import subprocess
from collections.abc import Iterable

from listener_parsers import (
    deduplicate_listeners,
    parse_lsof,
)
from models import (
    DiskInfo,
    ListenerRecord,
    ListenerSummary,
    ProcessRecord,
)
from process_parsers import parse_ps, top_by_cpu

SUPPORTED_PLATFORMS = {"Darwin"}

_BYTES_PER_GIBIBYTE = 1024**3
_DEFAULT_COMMAND_TIMEOUT = 30


class CollectorError(Exception):
    """Raised when host-state collection cannot be completed safely."""


def _command_text(command: list[str]) -> str:
    return shlex.join(command)


def _run(
    command: list[str],
    *,
    tolerate_nonzero: bool = False,
    timeout: int = _DEFAULT_COMMAND_TIMEOUT,
) -> str:
    """
    Execute a system command and return its standard output.

    When tolerate_nonzero is true, a nonzero exit is accepted only when
    the command still produced nonempty standard output. This exists for
    lsof, which can emit valid results while also returning a warning
    status for inaccessible processes.
    """

    if not command:
        raise CollectorError(
            "Cannot run an empty command."
        )

    executable = command[0]

    if shutil.which(executable) is None:
        raise CollectorError(
            f"Required command is unavailable: {executable}"
        )

    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=not tolerate_nonzero,
        )
    except subprocess.TimeoutExpired as error:
        raise CollectorError(
            "Command timed out after "
            f"{timeout} seconds: {_command_text(command)}"
        ) from error
    except subprocess.CalledProcessError as error:
        stderr = (error.stderr or "").strip()
        error_detail = (
            stderr
            if stderr
            else "no error output was provided"
        )

        raise CollectorError(
            f"Command failed: {_command_text(command)}. "
            f"Error: {error_detail}"
        ) from error
    except OSError as error:
        raise CollectorError(
            f"Could not execute {_command_text(command)}: "
            f"{error}"
        ) from error

    if completed.returncode != 0:
        if (
            tolerate_nonzero
            and completed.stdout.strip()
        ):
            return completed.stdout

        stderr = completed.stderr.strip()
        error_detail = (
            stderr
            if stderr
            else "no error output was provided"
        )

        raise CollectorError(
            f"Command failed: {_command_text(command)}. "
            f"Error: {error_detail}"
        )

    return completed.stdout


def _require_supported_platform() -> None:
    system = platform.system()

    if system not in SUPPORTED_PLATFORMS:
        raise CollectorError(
            f"Unsupported platform: {system}. "
            "This version supports macOS only."
        )


def collect_basic_system_info() -> dict[str, str]:
    return {
        "computer_name": platform.node(),
        "operating_system": platform.platform(),
        "platform_system": platform.system(),
        "current_user": getpass.getuser(),
    }


def collect_system_uptime() -> str:
    raw_uptime = _run(["uptime"])
    uptime_text = raw_uptime.strip()

    if not uptime_text:
        raise CollectorError(
            "The uptime command returned no data."
        )

    return uptime_text


def collect_process_info() -> tuple[int, list[ProcessRecord]]:
    _require_supported_platform()

    raw_processes = _run(
        [
            "ps",
            "-Awwxo",
            "pid=,pcpu=,pmem=,comm=",
        ]
    )

    process_records = parse_ps(raw_processes)

    if not process_records and raw_processes.strip():
        raise CollectorError(
            "Process output was received, but no process "
            "records could be parsed."
        )

    return (
        len(process_records),
        top_by_cpu(process_records, n=5),
    )


def collect_disk_info(
    mount: str = "/",
) -> DiskInfo:
    try:
        usage = shutil.disk_usage(mount)
    except OSError as error:
        raise CollectorError(
            f"Could not read disk usage for {mount}: "
            f"{error}"
        ) from error

    total_gb = usage.total / _BYTES_PER_GIBIBYTE
    used_gb = usage.used / _BYTES_PER_GIBIBYTE
    free_gb = usage.free / _BYTES_PER_GIBIBYTE

    if usage.total == 0:
        percent_used = 0.0
    else:
        percent_used = (
            usage.used / usage.total
        ) * 100

    return DiskInfo(
        mount=mount,
        total_gb=total_gb,
        used_gb=used_gb,
        free_gb=free_gb,
        percent_used=percent_used,
    )


def _build_port_owner_map(
    records: Iterable[ListenerRecord],
) -> dict[str, list[str]]:
    owner_sets: dict[str, set[str]] = {}

    for record in records:
        owners = owner_sets.setdefault(
            record.port,
            set(),
        )

        owners.add(
            record.command
            if record.command
            else "Unknown process"
        )

    return {
        port: sorted(owner_sets[port])
        for port in sorted(
            owner_sets,
            key=int,
        )
    }


def collect_listening_ports() -> ListenerSummary:
    _require_supported_platform()

    raw_listeners = _run(
        [
            "lsof",
            "-nP",
            "-iTCP",
            "-sTCP:LISTEN",
            "-F",
            "pcnLft",
            "+c",
            "0",
        ],
        tolerate_nonzero=True,
    )

    parsed_records = parse_lsof(raw_listeners)

    if not parsed_records and raw_listeners.strip():
        raise CollectorError(
            "Listener output was received, but no listener "
            "records could be parsed."
        )

    records = deduplicate_listeners(
        parsed_records
    )

    network_records = [
        record
        for record in records
        if not record.is_loopback
    ]

    local_only_records = [
        record
        for record in records
        if record.is_loopback
    ]

    network_ports = sorted(
        {
            record.port
            for record in network_records
        },
        key=int,
    )

    local_only_ports = sorted(
        {
            record.port
            for record in local_only_records
        },
        key=int,
    )

    network_port_owners = _build_port_owner_map(
        network_records
    )

    local_only_port_owners = _build_port_owner_map(
        local_only_records
    )

    return ListenerSummary(
        records=records,
        socket_count=len(records),
        network_ports=network_ports,
        local_only_ports=local_only_ports,
        network_port_owners=network_port_owners,
        local_only_port_owners=local_only_port_owners,
    )