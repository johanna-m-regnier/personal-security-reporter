from __future__ import annotations

from pathlib import Path

from models import ProcessRecord


def parse_ps(raw: str) -> list[ProcessRecord]:
    """
    Parse headerless macOS ps output.

    Expected command:

        ps -Awwxo pid=,pcpu=,pmem=,comm=

    The executable field is last so split(None, 3) preserves paths
    containing spaces.
    """

    records: list[ProcessRecord] = []

    for raw_line in raw.splitlines():
        line = raw_line.strip()

        if not line:
            continue

        parts = line.split(None, 3)

        if len(parts) != 4:
            continue

        pid_text, cpu_text, memory_text, executable = parts

        executable = executable.strip()

        if not executable:
            continue

        try:
            pid = int(pid_text)
            cpu_percent = float(cpu_text)
            mem_percent = float(memory_text)
        except ValueError:
            # Malformed process rows are skipped rather than causing
            # the entire process collector to fail.
            continue

        records.append(
            ProcessRecord(
                pid=pid,
                executable=executable,
                display_name=Path(executable).name,
                cpu_percent=cpu_percent,
                mem_percent=mem_percent,
            )
        )

    return records


def top_by_cpu(
    records: list[ProcessRecord],
    n: int = 5,
) -> list[ProcessRecord]:
    """Return up to n processes ordered by highest CPU usage."""

    if n <= 0:
        return []

    return sorted(
        records,
        key=lambda record: record.cpu_percent,
        reverse=True,
    )[:n]