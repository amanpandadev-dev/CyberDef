# Bugfix Requirements Document

## Introduction

The JSON incident report output (`*_incidents.json`) generated after threat analysis contains incorrect or null values for critical parameters like `source_ip`, `destination_ip`, `hostname`, and `suspicious_indicator`. However, the markdown report (`report.md`) correctly maps these same fields, indicating the data exists but is not being properly extracted or mapped in the JSON generation path.

This bug affects incident visibility, correlation accuracy, and downstream security analysis. The issue manifests differently across the three detection tiers:
- **Tier 3 (AI-generated incidents)**: `source_ip` shows `null` instead of extracting from `chunk.actor.src_ip`
- **Tier 3 (AI-generated incidents)**: `destination_ip` shows `null` instead of extracting from chunk targets or events
- **All tiers**: `suspicious_indicator` field contains the string `"null"` instead of actual `null` or a derived keyword
- **Tier 2 (Correlation incidents)**: Destination IP extraction needs enhancement with event parsing fallback

Additionally, the correlation tier (Tier 2) has 9 rules with threshold and IP extraction logic that may need review for optimal detection accuracy.

## Bug Analysis

### Current Behavior (Defect)

1.1 WHEN an AI-generated incident (Tier 3) is created via `create_from_agent_output()` THEN the system sets `source_ip` to `null` even though `chunk.actor.src_ip` contains a valid IP address

1.2 WHEN an AI-generated incident (Tier 3) is created via `create_from_agent_output()` THEN the system sets `destination_ip` to `null` even though chunk targets or event data contains destination information

1.3 WHEN any incident is created and `_derive_indicator_from_corpus()` cannot find a matching keyword THEN the system returns the string `"null"` instead of Python `None`

1.4 WHEN a correlation incident (Tier 2) is created via `create_from_correlation()` THEN the system may fail to extract `destination_ip` from evidence text when IP addresses are present in the raw event data

1.5 WHEN the JSON report is generated via `_incident_to_json()` in `reports/writer.py` THEN the system correctly extracts `source_ip` from `data.get("source_ip") or data.get("primary_actor_ip")` demonstrating the correct extraction pattern

1.6 WHEN the JSON report is generated via `_incident_to_json()` in `reports/writer.py` THEN the system correctly extracts `destination_ip` from `data.get("destination_ip")` or falls back to `affected_hosts[0]` demonstrating the correct fallback pattern

1.7 WHEN the JSON report is generated via `_incident_to_json()` in `reports/writer.py` THEN the system correctly extracts `hostname` from `destination_ip` or `affected_hosts[0]` demonstrating proper hostname derivation

1.8 WHEN correlation rules in `threat_state/correlator.py` evaluate actor behavior THEN the system uses fixed thresholds (e.g., 50 auth failures, 200 URIs, 3 attack categories) that may not be optimal for all environments

1.9 WHEN correlation rules detect patterns THEN the system may miss destination IP information that could be extracted from actor state or evidence data

### Expected Behavior (Correct)

2.1 WHEN an AI-generated incident (Tier 3) is created via `create_from_agent_output()` THEN the system SHALL extract `source_ip` from `chunk.actor.src_ip` as the primary source, matching the pattern used in `reports/writer.py`

2.2 WHEN an AI-generated incident (Tier 3) is created via `create_from_agent_output()` THEN the system SHALL extract `destination_ip` from chunk targets or parse event data with proper fallback logic, matching the pattern used in `reports/writer.py`

2.3 WHEN `_derive_indicator_from_corpus()` cannot find a matching keyword THEN the system SHALL return Python `None` instead of the string `"null"`

2.4 WHEN a correlation incident (Tier 2) is created via `create_from_correlation()` THEN the system SHALL enhance `_extract_destination_ip_from_text()` with event data parsing to extract destination IPs from evidence when available

2.5 WHEN `_extract_destination_ip_from_chunk()` is called THEN the system SHALL add a fallback that parses chunk events for destination IP fields (e.g., `dst_ip`, `dest_ip`, `destination_ip`) before returning `None`

2.6 WHEN correlation rules in `threat_state/correlator.py` evaluate patterns THEN the system SHALL use reviewed and potentially adjusted thresholds that balance detection accuracy with false positive rates

2.7 WHEN correlation findings are created THEN the system SHALL attempt to extract destination IP information from actor state evidence or event data when available

2.8 WHEN the JSON report is generated THEN the system SHALL produce output with correctly populated `source_ip`, `destination_ip`, `hostname`, and `suspicious_indicator` fields matching the accuracy of the markdown report

2.9 WHEN incidents are created from any tier (deterministic, correlation, or AI) THEN the system SHALL consistently apply the same extraction and mapping logic to ensure field consistency across all incident types

### Unchanged Behavior (Regression Prevention)

3.1 WHEN the markdown report (`report.md`) is generated via `reports/writer.py` THEN the system SHALL CONTINUE TO correctly map and display all incident fields including source IPs, destination IPs, hostnames, and attack details

3.2 WHEN deterministic incidents (Tier 1) are created via `create_from_deterministic_threat()` THEN the system SHALL CONTINUE TO correctly extract `source_ip` from `threat.src_ip` and `destination_ip` from evidence text

3.3 WHEN the JSON report structure is generated THEN the system SHALL CONTINUE TO include all existing fields (`incident_id`, `title`, `status`, `priority`, `mitre_tactic`, `mitre_technique`, `correlation`, etc.) without modification

3.4 WHEN `_incident_to_json()` builds the correlation context THEN the system SHALL CONTINUE TO populate `signature_attacks`, `correlation_reason`, and `raw_logs` arrays correctly

3.5 WHEN incidents are persisted to `incidents_data.json` THEN the system SHALL CONTINUE TO save and load incident data without data loss or corruption

3.6 WHEN correlation rules detect multi-vector attacks, kill-chain progression, or campaign patterns THEN the system SHALL CONTINUE TO create correlation findings with appropriate severity and confidence scores

3.7 WHEN `_extract_raw_log_from_chunk()` extracts log samples THEN the system SHALL CONTINUE TO search through event dictionaries for log fields (`raw_log`, `logevent`, `message`, `request`, `uri`) in the correct priority order

3.8 WHEN `_apply_mitre_fallback()` assigns MITRE ATT&CK mappings to incidents without AI-provided mappings THEN the system SHALL CONTINUE TO use the rule and family mapping dictionaries correctly

3.9 WHEN the incident service creates timeline entries THEN the system SHALL CONTINUE TO record detection events, analysis completion, and correlation events with proper timestamps and descriptions
