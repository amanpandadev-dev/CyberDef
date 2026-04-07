# Implementation Plan

## Overview
This task list implements fixes for 9 field extraction defects across three detection tiers (Tier 1: Deterministic, Tier 2: Correlation, Tier 3: AI). The fixes ensure JSON incident reports correctly populate source_ip, destination_ip, hostname, and suspicious_indicator fields matching the accuracy of markdown reports.

## Task Execution Order
1. Write bug condition exploration test (BEFORE fix) - test will FAIL on unfixed code
2. Write preservation property tests (BEFORE fix) - tests will PASS on unfixed code
3. Implement the fix with 9 specific code changes
4. Verify exploration test now passes (confirms bug is fixed)
5. Verify preservation tests still pass (confirms no regressions)

---

## Phase 1: Exploratory Bug Condition Testing

- [ ] 1. Write bug condition exploration test
  - **Property 1: Bug Condition** - Field Extraction Correctness Across All Tiers
  - **CRITICAL**: This test MUST FAIL on unfixed code - failure confirms the bugs exist
  - **DO NOT attempt to fix the test or the code when it fails**
  - **NOTE**: This test encodes the expected behavior - it will validate the fix when it passes after implementation
  - **GOAL**: Surface counterexamples that demonstrate the 9 field extraction bugs exist
  - **Scoped PBT Approach**: Test concrete failing cases for each of the 9 bugs to ensure reproducibility
  - Test implementation details from Bug Condition in design:
    - AI incident source_ip extraction from chunk.actor.src_ip (currently returns None)
    - AI incident destination_ip extraction from chunk targets/events (currently returns None)
    - _derive_indicator_from_corpus() returns Python None instead of string "null"
    - Correlation destination IP extraction from structured evidence (currently returns None)
    - Event parsing fallback in _extract_destination_ip_from_chunk() (currently missing)
  - The test assertions should match the Expected Behavior Properties from design:
    - source_ip extracted from chunk.actor.src_ip as primary source
    - destination_ip extracted from chunk targets or events with fallback logic
    - _derive_indicator_from_corpus() returns None (not "null") when no keyword matches
    - Correlation incidents extract destination IPs from structured evidence
    - Field consistency across all three tiers
  - Run test on UNFIXED code
  - **EXPECTED OUTCOME**: Test FAILS (this is correct - it proves the bugs exist)
  - Document counterexamples found to understand root cause:
    - AI incident with chunk.actor.src_ip="192.168.1.100" shows source_ip=None
    - AI incident with chunk.targets.dst_ips=["10.0.0.5"] shows destination_ip=None
    - _derive_indicator_from_corpus("unknown behavior") returns "null" not None
    - Correlation incident with evidence={"dst_ip": "172.16.0.10"} shows destination_ip=None
    - Chunk with events[0]={"dst_ip": "192.168.50.1"} shows destination_ip=None
  - Mark task complete when test is written, run, and failures are documented
  - _Requirements: 1.1, 1.2, 1.3, 1.4, 1.5, 1.6, 1.7, 1.8, 1.9_

---

## Phase 2: Preservation Property Testing

- [ ] 2. Write preservation property tests (BEFORE implementing fix)
  - **Property 2: Preservation** - Non-Buggy Path Behavior Unchanged
  - **IMPORTANT**: Follow observation-first methodology
  - Observe behavior on UNFIXED code for non-buggy inputs:
    - Markdown report generation produces correct field mappings
    - Deterministic incidents extract source_ip from threat.src_ip correctly
    - JSON report structure includes all existing fields unchanged
    - Incident persistence saves and loads data without corruption
    - Timeline entries record detection, analysis, and correlation events
    - MITRE fallback mapping uses rule and family dictionaries correctly
    - Correlation rule detection logic for multi-vector, kill-chain, campaign patterns works
    - Raw log extraction searches event dictionaries in correct priority order
  - Write property-based tests capturing observed behavior patterns from Preservation Requirements:
    - Test markdown report generation before and after fix produces identical output
    - Test deterministic incident creation before and after fix produces identical field extraction
    - Test JSON structure preservation for all existing fields
    - Test persistence round-trip (save → load) produces identical incidents
    - Test timeline structure and content remains unchanged
    - Test MITRE fallback logic produces same results
    - Test correlation detection produces same findings (threshold review is separate)
    - Test raw log extraction returns same samples
  - Property-based testing generates many test cases for stronger guarantees
  - Run tests on UNFIXED code
  - **EXPECTED OUTCOME**: Tests PASS (this confirms baseline behavior to preserve)
  - Mark task complete when tests are written, run, and passing on unfixed code
  - _Requirements: 3.1, 3.2, 3.3, 3.4, 3.5, 3.6, 3.7, 3.8, 3.9_

---

## Phase 3: Implementation

- [ ] 3. Fix field extraction across all detection tiers

  - [ ] 3.1 Fix AI incident source_ip extraction (incidents/service.py ~line 280)
    - Change: `source_ip = triage.source_ip if triage and triage.source_ip else chunk.actor.src_ip`
    - To: `source_ip = chunk.actor.src_ip or (triage.source_ip if triage else None)`
    - Rationale: Prioritize chunk.actor.src_ip as primary source, matching reports/writer.py pattern
    - _Bug_Condition: isBugCondition returns true when create_from_agent_output sets source_ip=None despite chunk.actor.src_ip containing valid IP_
    - _Expected_Behavior: source_ip extracted from chunk.actor.src_ip as primary source (Requirement 2.1)_
    - _Preservation: Deterministic incident source_ip extraction remains unchanged (Requirement 3.2)_
    - _Requirements: 1.1, 2.1, 3.2_

  - [ ] 3.2 Enhance _extract_destination_ip_from_chunk() with event parsing fallback (incidents/service.py ~line 1030)
    - Add event parsing logic after checking targets.dst_ips and targets.dst_hosts
    - Implementation:
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
    - Rationale: Matches pattern used in _extract_raw_log_from_chunk() for searching event dictionaries
    - _Bug_Condition: isBugCondition returns true when chunk has event IPs but _extract_destination_ip_from_chunk returns None_
    - _Expected_Behavior: destination_ip extracted from chunk events when targets are empty (Requirement 2.5)_
    - _Preservation: Raw log extraction priority order remains unchanged (Requirement 3.7)_
    - _Requirements: 1.2, 1.4, 2.2, 2.5, 3.7_

  - [ ] 3.3 Fix _derive_indicator_from_corpus() return value (incidents/service.py ~line 1050)
    - Change: `return "null"`
    - To: `return None`
    - Rationale: Python None is the correct null representation, not the string "null"
    - _Bug_Condition: isBugCondition returns true when _derive_indicator_from_corpus returns string "null" instead of None_
    - _Expected_Behavior: Returns Python None when no keyword matches (Requirement 2.3)_
    - _Preservation: Keyword matching logic for other indicators remains unchanged_
    - _Requirements: 1.3, 2.3_

  - [ ] 3.4 Enhance _extract_destination_ip_from_text() for structured data (incidents/service.py ~line 1040)
    - Add structured data parsing before regex fallback
    - Implementation:
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
          ip_matches = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", value)
          if len(ip_matches) >= 2:
              return ip_matches[1]
          return None
      ```
    - Rationale: Correlation evidence often contains structured data, not just text
    - _Bug_Condition: isBugCondition returns true when correlation evidence contains IP in structured format but extraction returns None_
    - _Expected_Behavior: Destination IPs extracted from structured evidence data (Requirement 2.4)_
    - _Preservation: Existing regex-based text extraction remains as fallback_
    - _Requirements: 1.4, 2.4_

  - [ ] 3.5 Update create_from_correlation() to pass evidence dict (incidents/service.py ~line 380)
    - Change: `destination_ip=self._extract_destination_ip_from_text(str(getattr(finding, "evidence", "")))`
    - To: `destination_ip=self._extract_destination_ip_from_text(getattr(finding, "evidence", ""))`
    - Rationale: Pass evidence object directly so structured parsing can work
    - _Bug_Condition: isBugCondition returns true when correlation evidence dict is converted to string before extraction_
    - _Expected_Behavior: Evidence dict passed to extraction function for structured parsing (Requirement 2.4)_
    - _Preservation: Correlation incident creation logic otherwise unchanged (Requirement 3.6)_
    - _Requirements: 1.4, 2.4, 3.6_

  - [ ] 3.6 Document correlation rule thresholds (threat_state/correlator.py)
    - Add inline comments documenting current thresholds and rationale:
      - _check_low_slow_brute_force: 50 auth failures (tunable for environment)
      - _check_distributed_recon: 200 unique URIs (may need adjustment for smaller sites)
      - _check_multi_vector: 3 attack categories (reasonable threshold)
      - _check_scanner_persistence: 3 batches (reasonable threshold)
      - _check_rate_acceleration: 2x rate increase and >50 requests (may need tuning)
      - _check_off_hours: 5 off-hours attacks (reasonable threshold)
      - _check_data_exfil: >100 successful requests with >50% success ratio (may need tuning)
      - _check_campaign: 3 IPs with same signature (reasonable threshold)
    - Add comment suggesting future enhancement: make thresholds configurable
    - Rationale: Fixed thresholds may not suit all environments, documentation aids future tuning
    - _Bug_Condition: Not a bug, but documentation gap for threshold rationale_
    - _Expected_Behavior: Thresholds documented with rationale (Requirement 2.6)_
    - _Preservation: Correlation detection logic remains unchanged (Requirement 3.6)_
    - _Requirements: 1.8, 2.6, 3.6_

  - [ ] 3.7 Extract destination IPs from correlation evidence (threat_state/correlator.py)
    - Enhance correlation findings to include destination IP information from actor state
    - Example implementation in _check_low_slow_brute_force:
      ```python
      evidence = {
          "auth_failures": actor.auth_failures_total,
          "batches": actor.batches_seen_in,
      }
      # Add destination IPs if available
      if hasattr(actor, 'target_ips') and actor.target_ips:
          evidence["target_ips"] = list(actor.target_ips)[:5]
      ```
    - Apply similar pattern to other correlation rules where actor state has target information
    - Rationale: Correlation findings should include as much context as possible for incident enrichment
    - _Bug_Condition: Correlation findings may miss destination IP information available in actor state_
    - _Expected_Behavior: Destination IPs extracted from actor state when available (Requirement 2.7)_
    - _Preservation: Correlation finding structure and detection logic unchanged (Requirement 3.6)_
    - _Requirements: 1.9, 2.7, 3.6_

  - [ ] 3.8 Verify field consistency across all tiers (incidents/service.py)
    - Review create_from_deterministic_threat() extraction patterns
    - Review create_from_multiple_outputs() extraction patterns
    - Verify all three creation methods use consistent extraction logic:
      - source_ip: prioritize primary actor IP field
      - destination_ip: use enhanced extraction with event parsing fallback
      - suspicious_indicator: return None (not "null") when no keyword matches
    - Rationale: Consistency across tiers ensures predictable JSON output
    - _Bug_Condition: Field extraction patterns may vary across incident creation methods_
    - _Expected_Behavior: Consistent extraction logic across all tiers (Requirement 2.9)_
    - _Preservation: Existing deterministic and multi-output logic unchanged where correct (Requirement 3.2)_
    - _Requirements: 1.1, 1.2, 1.3, 2.9, 3.2_

  - [ ] 3.9 Verify JSON report field mapping (reports/writer.py)
    - Review _incident_to_json() to ensure it correctly uses incident fields
    - Verify source_ip extraction: `data.get("source_ip") or data.get("primary_actor_ip")`
    - Verify destination_ip extraction: `data.get("destination_ip")` with fallback to `affected_hosts[0]`
    - Verify hostname derivation from destination_ip or affected_hosts
    - Verify suspicious_indicator handling (should be None or valid keyword, never "null")
    - Rationale: JSON report should correctly map incident fields without additional transformation
    - _Bug_Condition: JSON report generation may not handle None values correctly_
    - _Expected_Behavior: JSON report produces correctly populated fields (Requirement 2.8)_
    - _Preservation: JSON structure and all existing fields remain unchanged (Requirement 3.3)_
    - _Requirements: 1.5, 1.6, 1.7, 2.8, 3.1, 3.3_

  - [ ] 3.10 Verify bug condition exploration test now passes
    - **Property 1: Expected Behavior** - Field Extraction Correctness Validated
    - **IMPORTANT**: Re-run the SAME test from task 1 - do NOT write a new test
    - The test from task 1 encodes the expected behavior
    - When this test passes, it confirms the expected behavior is satisfied
    - Run bug condition exploration test from step 1
    - **EXPECTED OUTCOME**: Test PASSES (confirms bugs are fixed)
    - Verify all 9 field extraction bugs are resolved:
      - AI incident source_ip extracted from chunk.actor.src_ip
      - AI incident destination_ip extracted from chunk targets/events
      - _derive_indicator_from_corpus() returns None (not "null")
      - Correlation destination IP extracted from structured evidence
      - Event parsing fallback works in _extract_destination_ip_from_chunk()
      - Field consistency across all tiers
      - JSON report fields correctly populated
    - _Requirements: 2.1, 2.2, 2.3, 2.4, 2.5, 2.6, 2.7, 2.8, 2.9_

  - [ ] 3.11 Verify preservation tests still pass
    - **Property 2: Preservation** - No Regressions Introduced
    - **IMPORTANT**: Re-run the SAME tests from task 2 - do NOT write new tests
    - Run preservation property tests from step 2
    - **EXPECTED OUTCOME**: Tests PASS (confirms no regressions)
    - Confirm all non-buggy behaviors preserved:
      - Markdown report generation produces identical output
      - Deterministic incident field extraction unchanged
      - JSON structure with all existing fields unchanged
      - Incident persistence works without data loss
      - Timeline entries unchanged
      - MITRE fallback mapping unchanged
      - Correlation detection produces same findings
      - Raw log extraction unchanged
    - _Requirements: 3.1, 3.2, 3.3, 3.4, 3.5, 3.6, 3.7, 3.8, 3.9_

---

## Phase 4: Validation Checkpoint

- [ ] 4. Checkpoint - Ensure all tests pass
  - Run complete test suite (exploration + preservation + unit tests)
  - Verify all 9 field extraction bugs are fixed
  - Verify no regressions in existing functionality
  - Test full pipeline: ingest CSV → create chunks → run Tier 1/2/3 → create incidents → generate JSON report
  - Verify JSON report fields match markdown report accuracy
  - Ask the user if questions arise or if additional validation is needed

---

## Testing Notes

### Unit Test Coverage
- Test create_from_agent_output() with various chunk configurations
- Test _derive_indicator_from_corpus() with all keyword categories and no-match cases
- Test _extract_destination_ip_from_chunk() with targets, events, and both missing
- Test _extract_destination_ip_from_text() with string input and dict input
- Test create_from_correlation() with string evidence and dict evidence
- Test edge cases: empty chunks, None values, malformed event dictionaries

### Integration Test Coverage
- Full pipeline test: CSV ingestion → incident creation → JSON report generation
- Persistence test: create incidents → save → restart → load → verify fields unchanged
- Markdown vs JSON consistency test: verify source_ip, destination_ip, hostname match
- Correlation rule execution test: accumulate actor state → trigger rules → verify destination IPs

### Property-Based Test Coverage
- Generate random BehavioralChunk objects and verify AI incidents extract IPs correctly
- Generate random correlation findings and verify destination IP extraction
- Generate random text corpora and verify _derive_indicator_from_corpus() returns None or valid keyword
- Test incident creation methods produce consistent field mappings across many random inputs
