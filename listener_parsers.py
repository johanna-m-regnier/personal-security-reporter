from __future__ import annotations

import ipaddress
import re
from dataclasses import replace

from models import ListenerRecord

_HEX_ESCAPE_PATTERN = re.compile(r"\\x([0-9A-Fa-f]{2})")

_FAMILY_IPV4 = "IPv4"
_FAMILY_IPV6 = "IPv6"
_FAMILY_BOTH = "IPv4+IPv6"
_FAMILY_UNKNOWN = "unknown"


def _unescape_hex_sequences(value: str) -> str:
    """Convert lsof-style hexadecimal escapes such as \\x20 to characters."""

    def replace_match(match: re.Match[str]) -> str:
        return chr(int(match.group(1), 16))

    return _HEX_ESCAPE_PATTERN.sub(
        replace_match,
        value,
    )


def _parse_pid(value: str) -> int | None:
    try:
        return int(value.strip())
    except ValueError:
        return None


def _normalize_family(value: str) -> str:
    normalized = value.strip().lower()

    if normalized == "ipv4":
        return _FAMILY_IPV4

    if normalized == "ipv6":
        return _FAMILY_IPV6

    return _FAMILY_UNKNOWN

# dont even know 
def _strip_listener_suffix(address: str) -> str:
    cleaned = address.strip()

    cleaned = cleaned.removesuffix(" (LISTEN)")

    return cleaned.strip()


def _split_host_port(
    address: str,
) -> tuple[str, str]:
    cleaned = _strip_listener_suffix(address)

    if not cleaned:
        return "", ""

    if cleaned.startswith("["):
        closing_bracket = cleaned.find("]")

        if closing_bracket == -1:
            return "", ""

        host = cleaned[1:closing_bracket]
        remainder = cleaned[closing_bracket + 1 :]

        if not remainder.startswith(":"):
            return "", ""

        port = remainder[1:]
        return host.strip(), port.strip()

    if ":" not in cleaned:
        return "", ""

    host, port = cleaned.rsplit(":", 1)

    return host.strip(), port.strip()


def classify_address(
    address: str,
) -> tuple[str, str, bool]:
    """
    Return the listener port, address family, and loopback status.

    Unparseable hosts default to non-loopback so malformed input cannot
    accidentally hide a potentially exposed listener.
    """

    host, port = _split_host_port(address)

    if not port or not port.isdigit():
        return "", _FAMILY_UNKNOWN, False

    if host == "*":
        return port, _FAMILY_UNKNOWN, False

    host_for_parsing = host

    # IPv6 link-local addresses may include an interface zone such as
    # fe80::1%lo0. ipaddress only needs the address portion.
    if "%" in host_for_parsing:
        host_for_parsing = host_for_parsing.split(
            "%",
            1,
        )[0]

    try:
        parsed_address = ipaddress.ip_address(
            host_for_parsing
        )
    except ValueError:
        return port, _FAMILY_UNKNOWN, False

    if parsed_address.version == 4:
        family = _FAMILY_IPV4
    else:
        family = _FAMILY_IPV6

    return port, family, parsed_address.is_loopback


def parse_lsof(raw: str) -> list[ListenerRecord]:
    """
    Parse lsof field output produced with -F pcnLft.

    Process fields remain active until the next p field. File-specific
    fields such as type are reset when a new f field begins.
    """

    records: list[ListenerRecord] = []

    current_pid: int | None = None
    current_command = "Unknown process"
    current_user: str | None = None
    current_family = _FAMILY_UNKNOWN

    for raw_line in raw.splitlines():
        line = raw_line.rstrip("\r\n")

        if not line:
            continue

        field_id = line[0]
        value = line[1:]

        if field_id == "p":
            current_pid = _parse_pid(value)
            current_command = "Unknown process"
            current_user = None
            current_family = _FAMILY_UNKNOWN
            continue

        if field_id == "c":
            command = _unescape_hex_sequences(
                value.strip()
            )

            current_command = (
                command
                if command
                else "Unknown process"
            )
            continue

        if field_id == "L":
            user = value.strip()
            current_user = user if user else None
            continue

        if field_id == "f":
            # A new file descriptor begins a new file-specific field set.
            current_family = _FAMILY_UNKNOWN
            continue

        if field_id == "t":
            current_family = _normalize_family(value)
            continue

        if field_id != "n":
            # Unknown and malformed fields are deliberately ignored.
            continue

        address = value.strip()
        port, inferred_family, is_loopback = (
            classify_address(address)
        )

        if not port:
            continue

        family = (
            current_family
            if current_family != _FAMILY_UNKNOWN
            else inferred_family
        )

        records.append(
            ListenerRecord(
                command=current_command,
                pid=current_pid,
                user=current_user,
                address=_strip_listener_suffix(
                    address
                ),
                port=port,
                family=family,
                is_loopback=is_loopback,
            )
        )

    return records


def _binding_class(
    record: ListenerRecord,
) -> str:
    host, _ = _split_host_port(record.address)

    if record.is_loopback:
        return "loopback"

    if host in {"*", "0.0.0.0", "::"}:
        return "wildcard"

    return f"specific:{host}"


def _family_components(
    family: str,
) -> set[str]:
    if family == _FAMILY_IPV4:
        return {_FAMILY_IPV4}

    if family == _FAMILY_IPV6:
        return {_FAMILY_IPV6}

    if family == _FAMILY_BOTH:
        return {
            _FAMILY_IPV4,
            _FAMILY_IPV6,
        }

    return set()


def _can_merge_address_families(
    existing: ListenerRecord,
    candidate: ListenerRecord,
) -> bool:
    same_listener_identity = (
        existing.command == candidate.command
        and existing.pid == candidate.pid
        and existing.user == candidate.user
        and existing.port == candidate.port
        and existing.is_loopback
        == candidate.is_loopback
    )

    if not same_listener_identity:
        return False

    existing_binding = _binding_class(existing)
    candidate_binding = _binding_class(candidate)

    if existing_binding != candidate_binding:
        return False

    # Only equivalent wildcard or loopback bindings are merged.
    # Specific interface addresses remain separate so information is
    # not hidden merely because the process and port match.
    if existing_binding not in {
        "wildcard",
        "loopback",
    }:
        return False

    combined_families = (
        _family_components(existing.family)
        | _family_components(candidate.family)
    )

    return combined_families == {
        _FAMILY_IPV4,
        _FAMILY_IPV6,
    }


def deduplicate_listeners(
    records: list[ListenerRecord],
) -> list[ListenerRecord]:
    """
    Remove exact duplicates and combine equivalent IPv4/IPv6 sockets.

    A loopback binding is never merged with a network-reachable binding.
    Distinct specific interface addresses are also preserved.
    """

    deduplicated: list[ListenerRecord] = []

    for record in records:
        if record in deduplicated:
            continue

        merged = False

        for index, existing in enumerate(
            deduplicated
        ):
            if not _can_merge_address_families(
                existing,
                record,
            ):
                continue

            deduplicated[index] = replace(
                existing,
                family=_FAMILY_BOTH,
            )

            merged = True
            break

        if not merged:
            deduplicated.append(record)

    return deduplicated