"""
Behavioral Summarization Service

Converts chunks into semantic summaries ready for AI agent processing.
"""

from __future__ import annotations

from typing import Any

from behavior_summary.extended_analysis import ExtendedThreatAnalysisMixin
from behavior_summary.helpers import BehaviorSummaryHelpers
from core.logging import get_logger
from shared_models.chunks import (
    BehavioralChunk,
    ChunkSummary,
    TemporalPattern,
)

logger = get_logger(__name__)


class BehaviorSummaryService(BehaviorSummaryHelpers, ExtendedThreatAnalysisMixin):
    """
    Service for creating semantic summaries from behavioral chunks.

    Summaries are the ONLY input format for AI agents.
    No raw data is ever sent to the LLM.
    """

    # Port service mappings
    PORT_SERVICES = {
        20: "FTP-Data",
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        67: "DHCP",
        68: "DHCP",
        80: "HTTP",
        110: "POP3",
        123: "NTP",
        143: "IMAP",
        161: "SNMP",
        389: "LDAP",
        443: "HTTPS",
        445: "SMB",
        465: "SMTPS",
        514: "Syslog",
        587: "SMTP-Submission",
        636: "LDAPS",
        993: "IMAPS",
        995: "POP3S",
        1433: "MSSQL",
        1521: "Oracle",
        2049: "NFS",
        3306: "MySQL",
        3389: "RDP",
        5432: "PostgreSQL",
        5672: "AMQP",
        5900: "VNC",
        6379: "Redis",
        8080: "HTTP-Proxy",
        8443: "HTTPS-Alt",
        27017: "MongoDB",
    }

    # Temporal pattern descriptions
    TEMPORAL_DESCRIPTIONS = {
        TemporalPattern.STEADY: "Consistent, steady rate of activity throughout the observation window",
        TemporalPattern.BURSTY: "Brief, high-intensity bursts of activity",
        TemporalPattern.BURSTY_THEN_IDLE: "Initial burst of activity followed by a quiet period",
        TemporalPattern.IDLE_THEN_BURSTY: "Quiet period followed by sudden burst of activity",
        TemporalPattern.PERIODIC: "Regular, periodic intervals of activity suggesting automation",
        TemporalPattern.ESCALATING: "Activity frequency increasing over time",
        TemporalPattern.DECLINING: "Activity frequency decreasing over time",
        TemporalPattern.RANDOM: "No discernible temporal pattern",
    }

    def __init__(self):
        self.summaries_created = 0

    def summarize(self, chunk: BehavioralChunk) -> ChunkSummary:
        """
        Create a semantic summary from a behavioral chunk.

        Args:
            chunk: Behavioral chunk

        Returns:
            ChunkSummary ready for AI processing
        """
        # Build time window string
        time_window_str = self._format_time_window(chunk)

        # Detect temporal patterns
        temporal_pattern = self._analyze_temporal_pattern(chunk)

        # Calculate anomaly score
        anomaly_score, suspicion_reasons = self._calculate_anomaly_score(chunk)

        # ========== ANALYZE HTTP PATTERNS ==========
        http_analysis = self._analyze_http_patterns(chunk)

        # Build comprehensive summary matching ChunkSummary schema
        time_window_str = f"{chunk.time_window.start.strftime('%H:%M')}–{chunk.time_window.end.strftime('%H:%M')} UTC"
        duration_minutes = chunk.time_window.duration_minutes
        red_flags = list(dict.fromkeys(suspicion_reasons + self._compute_red_flags(chunk)))

        # Convert actor to dict
        actor_dict = {}
        if chunk.actor.src_ip:
            actor_dict["src_ip"] = chunk.actor.src_ip
        if chunk.actor.username:
            actor_dict["username"] = chunk.actor.username
        actor_dict["is_internal"] = chunk.actor.is_internal

        # Convert activity profile to dict
        activity_dict = {
            "total_events": chunk.activity_profile.total_events,
            "allow_count": chunk.activity_profile.allow_count,
            "deny_count": chunk.activity_profile.deny_count,
            "failure_rate": chunk.activity_profile.failure_rate,
            "events_per_minute": chunk.activity_profile.events_per_minute,
        }

        # Port descriptions
        port_map = {
            22: "SSH", 23: "Telnet", 80: "HTTP", 443: "HTTPS",
            3389: "RDP", 3306: "MySQL", 5432: "PostgreSQL",
        }
        port_descriptions = [
            f"{port_map.get(p, 'Unknown')} ({p})"
            for p in chunk.ports[:10]
        ]

        # Context dict
        context_dict = {
            "environment": chunk.context.environment,
            "network_zone": chunk.context.network_zone,
        }

        self.summaries_created += 1

        # Build comprehensive summary
        summary = ChunkSummary(
            chunk_id=chunk.chunk_id,
            time_window_str=time_window_str,
            duration_minutes=duration_minutes,
            actor=self._build_actor_dict(chunk),
            activity_profile=self._build_activity_dict(chunk),
            ports=chunk.ports[:15],
            port_descriptions=self._describe_ports(chunk.ports),
            temporal_pattern=temporal_pattern.value,
            temporal_description=self.TEMPORAL_DESCRIPTIONS.get(temporal_pattern, "Unknown pattern"),
            context=self._build_context_dict(chunk),
            red_flags=red_flags,
            anomaly_score=anomaly_score,
            reason_codes=self._build_reason_codes(red_flags, http_analysis),
            target_context=self._build_target_context(chunk),
            activity_ratios=self._build_activity_ratios(chunk),
            sample_evidence_refs=self._extract_sample_evidence_refs(chunk, http_analysis),
            # HTTP/Web attack patterns
            http_methods_seen=http_analysis.get("methods"),
            http_status_codes=http_analysis.get("status_codes"),
            suspicious_uri_patterns=http_analysis.get("suspicious_uris"),
            user_agents_seen=http_analysis.get("user_agents"),
            http_attack_indicators=http_analysis.get("attack_indicators"),
        )
        return summary

    def summarize_batch(self, chunks: list[BehavioralChunk]) -> list[ChunkSummary]:
        """Summarize multiple chunks."""
        return [self.summarize(chunk) for chunk in chunks]

    def _format_time_window(self, chunk: BehavioralChunk) -> str:
        """Format time window as human-readable string."""
        start = chunk.time_window.start
        end = chunk.time_window.end

        # Same day
        if start.date() == end.date():
            return f"{start.strftime('%Y-%m-%d')} {start.strftime('%H:%M')}–{end.strftime('%H:%M')} UTC"
        else:
            return f"{start.strftime('%Y-%m-%d %H:%M')}–{end.strftime('%Y-%m-%d %H:%M')} UTC"

    def _build_actor_dict(self, chunk: BehavioralChunk) -> dict[str, Any]:
        """Build actor dictionary for summary."""
        actor: dict[str, Any] = {}

        if chunk.actor.src_ip:
            actor["src_ip"] = chunk.actor.src_ip

        if chunk.actor.src_ips:
            actor["src_ips"] = chunk.actor.src_ips[:10]
            actor["src_ip_count"] = len(chunk.actor.src_ips)

        if chunk.actor.username:
            actor["username"] = chunk.actor.username

        if chunk.actor.hostname:
            actor["hostname"] = chunk.actor.hostname

        if chunk.actor.is_internal is not None:
            actor["is_internal"] = chunk.actor.is_internal
            actor["network_position"] = "Internal" if chunk.actor.is_internal else "External"

        return actor

    def _build_activity_dict(self, chunk: BehavioralChunk) -> dict[str, Any]:
        """Build activity profile dictionary."""
        profile = chunk.activity_profile

        activity: dict[str, Any] = {
            "total_events": profile.total_events,
            "events_per_minute": round(profile.events_per_minute, 2),
        }

        # Action breakdown
        if profile.allow_count > 0:
            activity["allowed"] = profile.allow_count
        if profile.deny_count > 0:
            activity["denied"] = profile.deny_count
            activity["denial_rate"] = f"{profile.failure_rate:.0%}"

        # Target information
        if profile.unique_dst_ips > 1:
            activity["unique_destination_ips"] = profile.unique_dst_ips
        if profile.unique_dst_hosts > 0:
            activity["unique_destination_hosts"] = profile.unique_dst_hosts
        if profile.unique_ports > 1:
            activity["unique_ports_accessed"] = profile.unique_ports

        # Traffic volume
        if profile.total_bytes_sent > 0:
            activity["bytes_sent"] = self._format_bytes(profile.total_bytes_sent)
        if profile.total_bytes_received > 0:
            activity["bytes_received"] = self._format_bytes(profile.total_bytes_received)

        return activity

    def _describe_ports(self, ports: list[int]) -> list[str]:
        """Create human-readable port descriptions."""
        descriptions = []

        for port in ports[:15]:
            service = self.PORT_SERVICES.get(port)
            if service:
                descriptions.append(f"{service} ({port})")
            elif port < 1024:
                descriptions.append(f"Well-known ({port})")
            elif port < 49152:
                descriptions.append(f"Registered ({port})")
            else:
                descriptions.append(f"Ephemeral ({port})")

        return descriptions

    def _build_context_dict(self, chunk: BehavioralChunk) -> dict[str, Any]:
        """Build environment context dictionary."""
        context: dict[str, Any] = {}

        if chunk.context.environment:
            context["environment"] = chunk.context.environment

        if chunk.context.network_zone:
            context["network_zone"] = chunk.context.network_zone

        if chunk.context.asset_criticality:
            context["asset_criticality"] = chunk.context.asset_criticality

        # Add target context
        if chunk.targets.dst_hosts:
            context["target_hosts"] = chunk.targets.dst_hosts[:5]

        if chunk.targets.unique_target_count > 0:
            context["total_targets"] = chunk.targets.unique_target_count

        return context

    def _compute_red_flags(self, chunk: BehavioralChunk) -> list[str]:
        """Compute deterministic red flags for the chunk."""
        flags = []
        profile = chunk.activity_profile

        # High denial rate
        if profile.failure_rate >= 0.5 and profile.deny_count >= 5:
            flags.append(
                f"High denial rate: {profile.failure_rate:.0%} "
                f"({profile.deny_count} blocked events)"
            )

        # Many targets
        if chunk.targets.unique_target_count >= 5:
            flags.append(
                f"Multiple targets: {chunk.targets.unique_target_count} unique destinations"
            )

        # Sensitive port access with failures
        sensitive_ports = {22, 23, 3389, 445, 135, 139, 5900}
        accessed_sensitive = set(chunk.ports) & sensitive_ports
        if accessed_sensitive and profile.deny_count > 0:
            port_names = [
                self.PORT_SERVICES.get(p, str(p))
                for p in accessed_sensitive
            ]
            flags.append(
                f"Blocked access to sensitive services: {', '.join(port_names)}"
            )

        # High event rate
        if profile.events_per_minute > 20:
            flags.append(
                f"High event rate: {profile.events_per_minute:.1f} events/minute "
                "(possible automation)"
            )

        # Bursty pattern with high volume
        if chunk.temporal_pattern == TemporalPattern.BURSTY:
            if profile.total_events > 50:
                flags.append("Bursty activity pattern with high volume")

        # Escalating activity
        if chunk.temporal_pattern == TemporalPattern.ESCALATING:
            flags.append("Escalating activity frequency")

        # External actor accessing multiple internal targets
        if chunk.actor.is_internal is False:
            if chunk.targets.unique_target_count >= 3:
                flags.append(
                    "External source accessing multiple internal targets"
                )

        return flags

    def _format_bytes(self, byte_count: int) -> str:
        """Format byte count as human-readable string."""
        if byte_count < 1024:
            return f"{byte_count} B"
        elif byte_count < 1024 * 1024:
            return f"{byte_count / 1024:.1f} KB"
        elif byte_count < 1024 * 1024 * 1024:
            return f"{byte_count / (1024 * 1024):.1f} MB"
        else:
            return f"{byte_count / (1024 * 1024 * 1024):.1f} GB"

    def _build_reason_codes(self, red_flags: list[str], http_analysis: dict[str, Any]) -> list[str]:
        """Create compact deterministic reason codes for prompt grounding."""
        codes = []
        for flag in red_flags:
            lowered = flag.lower()
            if "failure" in lowered or "denial" in lowered or "blocked" in lowered:
                codes.append("high_failure_or_denial_rate")
            if "auth" in lowered:
                codes.append("authentication_anomaly")
            if "target" in lowered or "scanning" in lowered:
                codes.append("multi_target_activity")
            if "event rate" in lowered or "volume" in lowered or "bursty" in lowered:
                codes.append("high_volume_or_automation")
        if http_analysis.get("attack_indicators"):
            codes.append("http_attack_indicators")
        if http_analysis.get("status_codes"):
            status_codes = http_analysis["status_codes"]
            if sum(count for code, count in status_codes.items() if code.startswith("4")) > 0:
                codes.append("http_client_error_pattern")
            if sum(count for code, count in status_codes.items() if code.startswith("5")) > 0:
                codes.append("http_server_error_pattern")
        return list(dict.fromkeys(codes))

    def _build_target_context(self, chunk: BehavioralChunk) -> dict[str, Any]:
        """Build compact target context for agent prompts."""
        return {
            "unique_target_count": chunk.targets.unique_target_count,
            "dst_ip": chunk.targets.dst_ip,
            "dst_ips": chunk.targets.dst_ips[:10],
            "dst_host": chunk.targets.dst_host,
            "dst_hosts": chunk.targets.dst_hosts[:10],
        }

    def _build_activity_ratios(self, chunk: BehavioralChunk) -> dict[str, float]:
        """Build numeric ratios that help agents reason without recalculating."""
        total = max(chunk.activity_profile.total_events, 1)
        return {
            "allow_rate": round(chunk.activity_profile.allow_count / total, 4),
            "deny_rate": round(chunk.activity_profile.deny_count / total, 4),
            "failure_rate": round(chunk.activity_profile.failure_rate, 4),
            "events_per_minute": round(chunk.activity_profile.events_per_minute, 4),
        }

    def _extract_sample_evidence_refs(
        self,
        chunk: BehavioralChunk,
        http_analysis: dict[str, Any],
    ) -> list[str]:
        """Extract compact representative evidence without sending raw log dumps."""
        refs: list[str] = []
        for event_id in chunk.source_event_ids[:5]:
            refs.append(f"event_id:{event_id}")
        for uri in (http_analysis.get("suspicious_uris") or [])[:3]:
            refs.append(f"suspicious_uri:{str(uri)[:160]}")
        for indicator in (http_analysis.get("attack_indicators") or [])[:5]:
            refs.append(f"indicator:{indicator}")
        return refs[:12]

    def get_stats(self) -> dict[str, Any]:
        """Get summarization statistics."""
        return {
            "summaries_created": self.summaries_created,
        }
