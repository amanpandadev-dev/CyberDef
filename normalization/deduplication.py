"""
Deduplication Service

Collapses identical normalized events into a single canonical event.
Duplicate rows are discarded and are not counted by downstream detection.
"""

from __future__ import annotations

import json
from pathlib import Path

from core.logging import get_logger
from shared_models.events import NormalizedEvent

logger = get_logger(__name__)


class Deduplicator:
    """
    Service for deduplicating normalized events.

    Groups events by a composite identity key and keeps the first event.
    """

    def deduplicate(self, events: list[NormalizedEvent]) -> list[NormalizedEvent]:
        """
        Deduplicate a list of normalized events.

        Uses row_hash as the primary deterministic identifier, ensuring consistent
        deduplication across multiple runs of the same file.

        Args:
            events: List of normalized events

        Returns:
            Deduplicated list of events
        """
        if not events:
            return []

        logger.debug(f"Deduplicating batch | input_size={len(events)}")

        unique_events: dict[str, NormalizedEvent] = {}

        for event in events:
            # Use row_hash as the primary deterministic identifier.
            # row_hash is computed from raw data and is stable across runs.
            # This ensures consistent deduplication regardless of event_id or timing variations.
            identity_key = event.row_hash

            if identity_key in unique_events:
                logger.debug(f"Duplicate detected | row_hash={identity_key}")
                continue

            # Store a copy so mutations here never bleed back into the caller's list.
            # Downstream detection treats each deduped row as one event.
            unique_events[identity_key] = event.model_copy()

        deduplicated = list(unique_events.values())

        logger.info(
            f"Deduplication complete | input={len(events)}, output={len(deduplicated)}, "
            f"reduction={1.0 - (len(deduplicated) / len(events)) if len(events) > 0 else 0:.1%}"
        )

        return deduplicated

    def write_jsonl(
        self,
        events: list[NormalizedEvent],
        output_dir: str | Path,
        file_id: str,
    ) -> Path:
        """Write the deduplicated normalized events used by the pipeline."""
        normalized_dir = Path(output_dir) / "normalized"
        normalized_dir.mkdir(parents=True, exist_ok=True)
        output_path = normalized_dir / f"{file_id}_normalized_dedup.jsonl"

        with output_path.open("w", encoding="utf-8") as f:
            for event in events:
                f.write(json.dumps(event.model_dump(mode="json"), ensure_ascii=False))
                f.write("\n")

        logger.info(
            f"Deduplicated normalized file written | path={output_path}, events={len(events)}"
        )
        return output_path

    def read_jsonl(self, path: str | Path) -> list[NormalizedEvent]:
        """Read deduplicated normalized events from JSONL."""
        input_path = Path(path)
        events: list[NormalizedEvent] = []

        with input_path.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    events.append(NormalizedEvent.model_validate_json(line))

        logger.info(
            f"Deduplicated normalized file loaded | path={input_path}, events={len(events)}"
        )
        return events
