"""
IP Filtering Utility

Centralized IP helpers for public/private checks and Zscaler post-detection filtering.
"""

from __future__ import annotations

import csv
import ipaddress
from bisect import bisect_right
from functools import lru_cache
from typing import Dict, Iterable, List, Optional, Set, Tuple

from core.config import get_settings
from core.logging import get_logger

logger = get_logger(__name__)


def is_ip_excluded(ip: Optional[str]) -> bool:
    """
    Check if an IP address should be ignored by public-IP correlation checks.

    This does not include Zscaler CSV ranges. Zscaler filtering happens only
    after deterministic detection for selected rule names.

    An IP is ignored here if it is:
    - None or empty
    - Private (RFC1918: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
    - Loopback (127.0.0.0/8, ::1)
    - Link-local (169.254.0.0/16, fe80::/10)

    Args:
        ip: IP address string to check

    Returns:
        True if IP should be ignored for public-IP checks, False otherwise
    """
    if not ip:
        return True
    
    try:
        ip_obj = ipaddress.ip_address(ip)
        
        return ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local

    except ValueError:
        # Invalid IP address
        logger.debug(f"Invalid IP address format: {ip}")
        return True


def is_ip_public(ip: Optional[str]) -> bool:
    """
    Check if an IP address is public (not excluded).
    
    This is the inverse of is_ip_excluded() and is provided for
    convenience and readability in threat detection code.
    
    Args:
        ip: IP address string to check
        
    Returns:
        True if IP is public and should be analyzed, False otherwise
    """
    return not is_ip_excluded(ip)


def _merge_intervals(intervals: List[Tuple[int, int]]) -> Tuple[Tuple[int, int], ...]:
    if not intervals:
        return ()

    intervals.sort()
    merged: List[Tuple[int, int]] = []
    start, end = intervals[0]
    for next_start, next_end in intervals[1:]:
        if next_start <= end + 1:
            end = max(end, next_end)
        else:
            merged.append((start, end))
            start, end = next_start, next_end
    merged.append((start, end))
    return tuple(merged)


@lru_cache(maxsize=1)
def _get_zscaler_lookup() -> Tuple[
    frozenset[int],
    frozenset[int],
    Tuple[Tuple[int, int], ...],
    Tuple[int, ...],
    Tuple[Tuple[int, int], ...],
    Tuple[int, ...],
]:
    """Load Zscaler source IP ranges as exact-IP sets and merged integer intervals."""
    settings = get_settings()
    csv_path = settings.data_dir / "Zscalar_ip_ranges.csv"
    exact_v4: Set[int] = set()
    exact_v6: Set[int] = set()
    range_v4: List[Tuple[int, int]] = []
    range_v6: List[Tuple[int, int]] = []
    total_ranges = 0

    if not csv_path.exists():
        logger.warning(f"Zscaler IP ranges file not found: {csv_path}")
        return frozenset(), frozenset(), (), (), (), ()

    try:
        with open(csv_path, "r", encoding="utf-8") as f:
            reader = csv.reader(f)
            for row_num, row in enumerate(reader, start=1):
                if not row or not row[0].strip():
                    continue

                raw_range = row[0].strip().lstrip(chr(65279))
                if row_num == 1 and raw_range.lower() in {"ip_range", "ip", "cidr", "range"}:
                    continue

                try:
                    network = ipaddress.ip_network(raw_range, strict=False)
                except ValueError as exc:
                    logger.warning(
                        f"Invalid Zscaler IP range at line {row_num}: {raw_range} - {exc}"
                    )
                    continue

                total_ranges += 1
                start = int(network.network_address)
                end = int(network.broadcast_address)
                if network.num_addresses == 1:
                    if network.version == 4:
                        exact_v4.add(start)
                    else:
                        exact_v6.add(start)
                elif network.version == 4:
                    range_v4.append((start, end))
                else:
                    range_v6.append((start, end))
    except Exception as exc:
        logger.error(f"Error loading Zscaler IP ranges from {csv_path}: {exc}")

    merged_v4 = _merge_intervals(range_v4)
    merged_v6 = _merge_intervals(range_v6)
    starts_v4 = tuple(start for start, _ in merged_v4)
    starts_v6 = tuple(start for start, _ in merged_v6)
    if total_ranges:
        logger.info(
            f"Loaded {total_ranges} Zscaler IP range(s) from {csv_path} "
            f"| exact_v4={len(exact_v4)}, exact_v6={len(exact_v6)}, "
            f"merged_v4={len(merged_v4)}, merged_v6={len(merged_v6)}"
        )

    return frozenset(exact_v4), frozenset(exact_v6), merged_v4, starts_v4, merged_v6, starts_v6


def _ip_int_in_intervals(
    ip_int: int,
    intervals: Tuple[Tuple[int, int], ...],
    starts: Tuple[int, ...],
) -> bool:
    if not intervals:
        return False

    idx = bisect_right(starts, ip_int) - 1
    return idx >= 0 and ip_int <= intervals[idx][1]


@lru_cache(maxsize=200000)
def is_zscaler_ip(ip: Optional[str]) -> bool:
    """Return True when ip belongs to the configured Zscaler source ranges."""
    if not ip or ip == "-":
        return False

    try:
        ip_obj = ipaddress.ip_address(ip)
    except ValueError:
        return False

    ip_int = int(ip_obj)
    exact_v4, exact_v6, range_v4, starts_v4, range_v6, starts_v6 = _get_zscaler_lookup()
    if ip_obj.version == 4:
        return ip_int in exact_v4 or _ip_int_in_intervals(ip_int, range_v4, starts_v4)
    return ip_int in exact_v6 or _ip_int_in_intervals(ip_int, range_v6, starts_v6)


def get_zscaler_source_ips(ips: Iterable[str | None]) -> Set[str]:
    """Return the unique input IP strings that are in the Zscaler source ranges."""
    return {
        ip
        for ip in set(ips)
        if ip and ip != "-" and is_zscaler_ip(ip)
    }


def get_excluded_ranges_summary() -> Dict[str, any]:
    """
    Get a summary of built-in public-IP exclusions for diagnostics.

    Returns:
        Dictionary with exclusion configuration details
    """
    return {
        "raw_config": "",
        "parsed_ranges": [],
        "total_ranges": 0,
        "builtin_exclusions": [
            "Private IPs (RFC1918)",
            "Loopback addresses",
            "Link-local addresses",
        ],
    }
