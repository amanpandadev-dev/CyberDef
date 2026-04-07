# JSON Mapping & Correlation Fixes Bugfix Design

## Overview

This bugfix addresses 9 defects in incident field extraction and mapping across three detection tiers (Tier 1: Deterministic, Tier 2: Correlation, Tier 3: AI). The primary issues are:

1. **AI incidents** fail to extract `source_ip` from `chunk.actor.src_ip`
2. **AI incidents** fail to extract `destination_ip` from chunk targets/events
3. **All incidents** return string `"null"` instead of Python `None` from `_derive_indicator_from_corpus()`
4. **Correlation incidents** lack robust destination IP extraction from evidence
5. **Correlation rules** use fixed thresholds that may need tuning
6. **Field consistency** varies across incident creation methods

The markdown report (`reports/writer.py`) correctly extracts these fields, demonstrating the proper patterns. This fix will replicate that logic in `incidents/service.py` to ensure JSON output matches markdown accuracy.

## Glossary

- **Bug_Condition (C)**: The condition that triggers incorrect field mapping - when incident creation methods fail to extract IP addresses or return string "null" instead of None
- **Property (P)**: The desired behavior - incidents should have correctly populated source_ip, destination_ip, and suspicious_indicator fields matching the patterns in reports/writer.py
- **Preservation**: All existing incident creation, persistence, timeline, and MITRE mapping logic must remain unchanged
- **Tier 1 (Deterministic)**: Rule-based threat detection in `rules_engine/`
- **Tier 2 (Correlation)**: Cross-batch pattern detection in `threat_state/correlator.py`
- **Tier 3 (AI)**: Agent-based behavioral analysis creating incidents via `create_from_agent_output()`
- **chunk.actor.src_ip**: The source IP field in BehavioralChunk that should be extracted for AI incidents
- **chunk.targets**: The targets object containing dst_ips and dst_hosts arrays
- **_derive_indicator_from_corpus()**: Helper method in incidents/service.py that derives suspicious indicator keywords from text

## Bug Details

### Bug Condition

The bug manifests when incident creation methods in `incidents/service.py` fail to properly extract IP addresses and indicator fields. The methods `create_from_agent_output()`, `create_from_correlation()`, and helper functions `_extract_destination_ip_from_chunk()` and `_derive_indicator_from_corpus()` either extract from wrong fields, lack fallback logic, or return incorrect null representations.

**Formal Specification:**
```
FUNCTION isBugCondition(input)
  INPUT: input of type (IncidentCreationContext, FieldName)
  OUTPUT: boolean
  
  RETURN (
    (input.method == "create_from_agent_output" AND input.field == "source_ip" AND input.value == None)
    OR (input.method == "create_from_agent_output" AND input.field == "destination_ip" AND input.value == None)
    OR (input.method == "_derive_indicator_from_corpus" AND input.value == "null" AND input.expected == None)
    OR (input.method == "create_from_correlation" AND input.field == "destination_ip" AND input.evidence_contains_ip == True AND input.value == None)
    OR (input.method == "_extract_destination_ip_from_chunk" AND input.chunk_has_event_ips == True AND input.value == None)
  )
END FUNCTION
```

### Examples

- **AI Incident Source IP Bug**: When `create_from_agent_output()` is called with a chunk containing `chunk.actor.src_ip = "192.168.1.100"`, the incident's `source_ip` field is set to `None` instead of `"192.168.1.100"`

- **AI Incident Destination IP Bug**: When `create_from_agent_output()` is called with a chunk where `chunk.targets.dst_ips = ["10.0.0.5"]`, the incident's `destination_ip` field is set to `None` instead of `"10.0.0.5"`

- **Indicator String Null Bug**: When `_derive_indicator_from_corpus()` is called with text `"unknown behavior"` that matches no keywords, it returns the string `"null"` instead of Python `None`

- **Correlation Destination IP Bug**: When `create_from_correlation()` is called with a finding where `evidence` contains raw event data with `"dst_ip": "172.16.0.10"`, the incident's `destination_ip` field is set to `None` instead of extracting `"172.16.0.10"` from the evidence

- **Event Parsing Fallback Missing**: When `_extract_destination_ip_from_chunk()` is called with a chunk where `chunk.events[0] = {"dst_ip": "192.168.50.1"}`, it returns `None` instead of parsing the event dictionary for destination IP fields

## Expected Behavior

### Preservation Requirements

**Unchanged Behaviors:**
- Markdown report generation in `reports/writer.py` must continue to work exactly as before
- Deterministic incident creation via `create_from_deterministic_threat()` must continue extracting fields correctly
- JSON report structure with all existing fields (incident_id, title, status, priority, mitre_tactic, mitre_technique, correlation context) must remain unchanged
- Incident persistence to `incidents_data.json` must continue without data loss
- Timeline entry creation must continue recording detection, analysis, and correlation events
- MITRE fallback mapping via `_apply_mitre_fallback()` must continue using rule and family dictionaries
- Correlation rule detection logic for multi-vector, kill-chain, campaign patterns must remain unchanged
- Raw log extraction via `_extract_raw_log_from_chunk()` must continue searching event dictionaries in correct priority order
- Incident status updates, filtering, and sorting must continue working correctly

**Scope:**
All inputs that do NOT involve the specific buggy field extraction paths should be completely unaffected by this fix. This includes:
- Mouse clicks and UI interactions with incident data
- Database queries and incident retrieval operations
- Incident summary generation and list views
- Report file generation and storage

## Hypothesized Root Cause

Based on the bug description and code analysis, the most likely issues are:

1. **Incorrect Field Assignment in AI Incidents**: The `create_from_agent_output()` method assigns `source_ip` from `triage.source_ip` (which may be None) instead of using `chunk.actor.src_ip` as the primary source. Line ~280 shows:
   ```python
   source_ip = triage.source_ip if triage and triage.source_ip else chunk.actor.src_ip
   ```
   This logic is backwards - it should prioritize `chunk.actor.src_ip` first.

2. **Missing Destination IP Extraction Logic**: The `_extract_destination_ip_from_chunk()` helper only checks `chunk.targets.dst_ips` and `chunk.targets.dst_hosts`, but doesn't parse `chunk.events` for destination IP fields like `dst_ip`, `dest_ip`, or `destination_ip`.

3. **String "null" Instead of None**: The `_derive_indicator_from_corpus()` method returns the string `"null"` on line ~1050 instead of Python `None`:
   ```python
   return "null"  # Should be: return None
   ```

4. **Weak Correlation Destination IP Extraction**: The `_extract_destination_ip_from_text()` method uses basic regex to find IPs in text but doesn't parse structured evidence data that may contain destination IP fields.

5. **Fixed Correlation Thresholds**: The 9 correlation rules in `threat_state/correlator.py` use hardcoded thresholds (e.g., 50 auth failures, 200 URIs, 3 attack categories) that may not be optimal for all environments.

## Correctness Properties

Property 1: Bug Condition - Field Extraction Correctness

_For any_ incident creation where the bug condition holds (isBugCondition returns true), the fixed functions SHALL extract source_ip from chunk.actor.src_ip, destination_ip from chunk targets or events, and return None instead of "null" from _derive_indicator_from_corpus().

**Validates: Requirements 2.1, 2.2, 2.3, 2.4, 2.5**

Property 2: Preservation - Non-Buggy Path Behavior

_For any_ incident creation or field extraction that does NOT involve the buggy paths (isBugCondition returns false), the fixed code SHALL produce exactly the same behavior as the original code, preserving all existing functionality for markdown reports, deterministic incidents, JSON structure, persistence, timelines, MITRE mapping, and correlation detection.

**Validates: Requirements 3.1, 3.2, 3.3, 3.4, 3.5, 3.6, 3.7, 3.8, 3.9**

## Fix Implementation

### Changes Required

Assuming our root cause analysis is correct:

**File**: `incidents/service.py`

**Function**: `create_from_agent_output()`

**Specific Changes**:

1. **Fix Source IP Extraction (Line ~280)**:
   - **Current**: `source_ip = triage.source_ip if triage and triage.source_ip else chunk.actor.src_ip`
   - **Fixed**: `source_ip = chunk.actor.src_ip or (triage.source_ip if triage else None)`
   - **Rationale**: Prioritize chunk.actor.src_ip as primary source, matching reports/writer.py pattern

2. **Fix Destination IP Extraction (Line ~281)**:
   - **Current**: `destination_ip = triage.destination_ip if triage and triage.destination_ip else self._extract_destination_ip_from_chunk(chunk)`
   - **Fixed**: Keep this line but enhance `_extract_destination_ip_from_chunk()` to parse events
   - **Rationale**: The fallback logic is correct, but the helper needs event parsing capability

3. **Enhance _extract_destination_ip_from_chunk() (Line ~1030)**:
   - **Add**: Event parsing fallback before returning None
   - **Implementation**:
     ```python
     # After checking targets.dst_ips and targets.dst_hosts
     # Add event parsing fallback
     events = getattr(chunk, "events", []) or []
     for event in events[:5]:  # Check first 5 events
         if isinstance(event, dict):
             for key in ("dst_ip", "dest_ip", "destination_ip", "target_ip"):
                 value = event.get(key)
                 if value:
                     return str(value)
             # Check nested raw_data
             raw_data = event.get("raw_data")
             if isinstance(raw_data, dict):
                 for key in ("dst_ip", "dest_ip", "destination_ip"):
                     value = raw_data.get(key)
                     if value:
                         return str(value)
     return None
     ```
   - **Rationale**: Matches the pattern used in `_extract_raw_log_from_chunk()` for searching event dictionaries

4. **Fix _derive_indicator_from_corpus() Return Value (Line ~1050)**:
   - **Current**: `return "null"`
   - **Fixed**: `return None`
   - **Rationale**: Python None is the correct null representation, not the string "null"

5. **Enhance _extract_destination_ip_from_text() for Correlation (Line ~1040)**:
   - **Add**: Structured data parsing before regex fallback
   - **Implementation**:
     ```python
     def _extract_destination_ip_from_text(self, value: str | dict) -> str | None:
         """Best-effort destination IP extraction from text or structured data."""
         import re
         
         # If value is a dict (structured evidence), try to extract destination IP fields
         if isinstance(value, dict):
             for key in ("dst_ip", "dest_ip", "destination_ip", "target_ip", "affected_host"):
                 ip_value = value.get(key)
                 if ip_value:
                     return str(ip_value)
             # Check nested structures
             for nested_key in ("evidence", "raw_data", "event"):
                 nested = value.get(nested_key)
                 if isinstance(nested, dict):
                     for key in ("dst_ip", "dest_ip", "destination_ip"):
                         ip_value = nested.get(key)
                         if ip_value:
                             return str(ip_value)
         
         # Fallback to string parsing
         text = str(value) if value else ""
         if not text:
             return None
         ip_matches = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text)
         if len(ip_matches) >= 2:
             return ip_matches[1]
         return None
     ```
   - **Rationale**: Correlation evidence often contains structured data, not just text

6. **Update create_from_correlation() to Pass Evidence Dict (Line ~380)**:
   - **Current**: `destination_ip=self._extract_destination_ip_from_text(str(getattr(finding, "evidence", "")))`
   - **Fixed**: `destination_ip=self._extract_destination_ip_from_text(getattr(finding, "evidence", ""))`
   - **Rationale**: Pass the evidence object directly so structured parsing can work

7. **Review Correlation Rule Thresholds (threat_state/correlator.py)**:
   - **Rules to Review**:
     - `_check_low_slow_brute_force`: Currently 50 auth failures - consider environment-specific tuning
     - `_check_distributed_recon`: Currently 200 unique URIs - may need adjustment for smaller sites
     - `_check_multi_vector`: Currently 3 attack categories - threshold seems reasonable
     - `_check_scanner_persistence`: Currently 3 batches - threshold seems reasonable
     - `_check_rate_acceleration`: Currently 2x rate increase and >50 requests - may need tuning
     - `_check_off_hours`: Currently 5 off-hours attacks - threshold seems reasonable
     - `_check_data_exfil`: Currently >100 successful requests with >50% success ratio - may need tuning
     - `_check_campaign`: Currently 3 IPs with same signature - threshold seems reasonable
   - **Action**: Document current thresholds and add comments explaining rationale. Consider making thresholds configurable in future enhancement.
   - **Rationale**: Fixed thresholds may not suit all environments, but changing them requires careful testing

8. **Extract Destination IPs from Correlation Evidence (threat_state/correlator.py)**:
   - **Enhancement**: Add destination IP extraction to correlation findings where actor state contains target information
   - **Implementation**: In each correlation rule, check if actor state has destination IP information and include in evidence dict
   - **Example** (in `_check_low_slow_brute_force`):
     ```python
     evidence = {
         "auth_failures": actor.auth_failures_total,
         "batches": actor.batches_seen_in,
     }
     # Add destination IPs if available
     if hasattr(actor, 'target_ips') and actor.target_ips:
         evidence["target_ips"] = list(actor.target_ips)[:5]
     ```
   - **Rationale**: Correlation findings should include as much context as possible for incident enrichment

9. **Ensure Field Consistency Across All Tiers**:
   - **Verification**: Review `create_from_deterministic_threat()` and `create_from_multiple_outputs()` to ensure they use the same extraction patterns
   - **Current State**: Deterministic already uses `threat.src_ip` correctly and calls `_extract_destination_ip_from_text()` on evidence
   - **Action**: Verify that all three creation methods produce consistent field mappings
   - **Rationale**: Consistency across tiers ensures predictable JSON output

## Testing Strategy

### Validation Approach

The testing strategy follows a two-phase approach: first, surface counterexamples that demonstrate the bugs on unfixed code, then verify the fixes work correctly and preserve existing behavior.

### Exploratory Bug Condition Checking

**Goal**: Surface counterexamples that demonstrate the bugs BEFORE implementing the fix. Confirm or refute the root cause analysis. If we refute, we will need to re-hypothesize.

**Test Plan**: Write unit tests that create incidents with known chunk data and assert that fields are correctly extracted. Run these tests on the UNFIXED code to observe failures and understand the root cause.

**Test Cases**:
1. **AI Incident Source IP Test**: Create incident from agent output with `chunk.actor.src_ip = "192.168.1.100"` and `triage.source_ip = None`, assert `incident.source_ip == "192.168.1.100"` (will fail on unfixed code showing None)
2. **AI Incident Destination IP Test**: Create incident from agent output with `chunk.targets.dst_ips = ["10.0.0.5"]`, assert `incident.destination_ip == "10.0.0.5"` (will fail on unfixed code showing None)
3. **Indicator Null String Test**: Call `_derive_indicator_from_corpus("unknown behavior")`, assert result is `None` not `"null"` (will fail on unfixed code showing string "null")
4. **Correlation Destination IP Test**: Create correlation incident with evidence containing `{"dst_ip": "172.16.0.10"}`, assert `incident.destination_ip == "172.16.0.10"` (will fail on unfixed code showing None)
5. **Event Parsing Fallback Test**: Create incident with chunk where `chunk.events[0] = {"dst_ip": "192.168.50.1"}` but `chunk.targets.dst_ips = []`, assert `incident.destination_ip == "192.168.50.1"` (will fail on unfixed code showing None)

**Expected Counterexamples**:
- Source IP fields show None when chunk.actor.src_ip contains valid IP
- Destination IP fields show None when chunk targets or events contain valid IPs
- Suspicious indicator shows string "null" instead of Python None
- Possible causes: incorrect field priority, missing event parsing, wrong null representation

### Fix Checking

**Goal**: Verify that for all inputs where the bug condition holds, the fixed functions produce the expected behavior.

**Pseudocode:**
```
FOR ALL input WHERE isBugCondition(input) DO
  result := fixed_incident_creation(input)
  ASSERT expectedBehavior(result)
END FOR
```

**Expected Behavior:**
- `result.source_ip` is extracted from `chunk.actor.src_ip` when available
- `result.destination_ip` is extracted from chunk targets or events when available
- `_derive_indicator_from_corpus()` returns Python `None` when no keyword matches
- Correlation incidents extract destination IPs from structured evidence data

### Preservation Checking

**Goal**: Verify that for all inputs where the bug condition does NOT hold, the fixed functions produce the same result as the original functions.

**Pseudocode:**
```
FOR ALL input WHERE NOT isBugCondition(input) DO
  ASSERT original_behavior(input) = fixed_behavior(input)
END FOR
```

**Testing Approach**: Property-based testing is recommended for preservation checking because:
- It generates many test cases automatically across the input domain
- It catches edge cases that manual unit tests might miss
- It provides strong guarantees that behavior is unchanged for all non-buggy inputs

**Test Plan**: Observe behavior on UNFIXED code first for markdown reports, deterministic incidents, and JSON structure, then write property-based tests capturing that behavior.

**Test Cases**:
1. **Markdown Report Preservation**: Generate markdown reports before and after fix, assert identical output for same incident data
2. **Deterministic Incident Preservation**: Create deterministic incidents before and after fix, assert field extraction remains identical
3. **JSON Structure Preservation**: Generate JSON reports before and after fix, assert all existing fields (incident_id, title, status, priority, correlation context) remain unchanged
4. **Persistence Preservation**: Save and load incidents before and after fix, assert no data loss or corruption
5. **Timeline Preservation**: Create incidents with timeline entries before and after fix, assert timeline structure and content unchanged
6. **MITRE Fallback Preservation**: Create incidents without AI MITRE mappings before and after fix, assert fallback logic produces same results
7. **Correlation Detection Preservation**: Run correlation rules before and after fix, assert same findings are detected (threshold review is separate)
8. **Raw Log Extraction Preservation**: Extract raw logs from chunks before and after fix, assert same log samples are returned

### Unit Tests

- Test `create_from_agent_output()` with various chunk configurations (source IP present, destination IP in targets, destination IP in events, both missing)
- Test `_derive_indicator_from_corpus()` with text matching each keyword category and text matching no keywords
- Test `_extract_destination_ip_from_chunk()` with targets present, targets missing but events present, both missing
- Test `_extract_destination_ip_from_text()` with string input, dict input with destination IP fields, dict input without destination IP fields
- Test `create_from_correlation()` with evidence as string and evidence as structured dict
- Test edge cases: empty chunks, None values, malformed event dictionaries

### Property-Based Tests

- Generate random BehavioralChunk objects with varying field populations and verify AI incidents extract IPs correctly
- Generate random correlation findings with varying evidence structures and verify destination IP extraction
- Generate random text corpora and verify `_derive_indicator_from_corpus()` returns None or valid keyword (never string "null")
- Test that all incident creation methods produce consistent field mappings across many random inputs

### Integration Tests

- Test full pipeline: ingest CSV → create chunks → run Tier 1/2/3 → create incidents → generate JSON report → verify all fields populated correctly
- Test incident persistence: create incidents → save to file → restart service → load from file → verify fields unchanged
- Test markdown vs JSON consistency: generate both reports for same incidents → verify source_ip, destination_ip, hostname match between formats
- Test correlation rule execution: accumulate actor state across multiple batches → trigger correlation rules → verify findings have destination IPs when available
