# Changes Summary: User ID & AI-Driven Human Review

## Overview
Implemented three key improvements to the incident detection system:

1. **Added User ID (username) tracking throughout the pipeline**
2. **Enhanced correlation display with both IP and User ID**
3. **Made AI agent decide whether human review is needed** (removed hard thresholds)

## Changes Made

### 1. Data Models

#### `shared_models/incidents.py`
- Added `primary_actor_username` and `actor_usernames` fields to `Incident` model
- Added `source_username` field to incident records
- Added `correlation_info` field to display IP & userid associations
- Updated `IncidentSummary` with same fields for API responses

#### `shared_models/agents.py` (TriageResult)
- Added `source_username` field to capture username from events
- Added `ai_needs_human_review` (boolean) - AI's decision on human review need
- Added `ai_review_reason` (string) - AI's explanation for why review is needed

#### `rules_engine/models.py`
- Added `src_username` field to `ThreatMatch` model
- Added `src_username` and `src_usernames` fields to `DeterministicThreat` model

### 2. AI Agent Updates

#### `agents/triage_agent.py`
- Updated prompt to include `source_username` extraction from actor data
- Added AI decision-making for human review with these new fields:
  - `ai_needs_human_review`: Boolean field where AI decides if review is needed
  - `ai_review_reason`: Explanation for why review is recommended
- Updated schema description to reflect new fields
- AI now considers:
  - Evidence ambiguity
  - Attack sophistication
  - Target criticality
  - Potential for false positive
  - Novel attack patterns
  - Low-confidence assessments
  - High-severity incidents

#### `agents/orchestrator.py`
- Modified `_finalize_node()` to use AI's `ai_needs_human_review` decision
- Falls back to old threshold logic only if AI doesn't provide a decision
- Updated merge path to also respect AI's review decision

### 3. Incident Service Updates

#### `incidents/service.py`

**`create_from_agent_output()`:**
- Extracts `source_username` from triage result or chunk actor
- Builds `correlation_info` string showing "IP: x.x.x.x | User: username"
- Populates `primary_actor_username` and `actor_usernames` fields
- Passes username through to incident record

**`create_from_deterministic_threat()`:**
- Extracts username from threat object
- Builds `correlation_info` with IP and username
- Shows additional IPs and usernames if multiple actors involved
- Populates all username fields in incident

**`create_from_correlation()`:**
- Extracts username from correlation finding if available
- Builds correlation info string
- Populates username fields in incident

### 4. Rules Engine Updates

#### `rules_engine/base_rule.py`
- Updated `ThreatRule.match()` to populate `src_username` from event when creating `ThreatMatch`
- All signature-based rules now automatically capture username

#### `rules_engine/engine.py`
- Updated `_group_matches()` to collect and aggregate usernames
- Collects `src_usernames` list from all matches
- Sets `primary_username` as first unique username
- Passes usernames through to `DeterministicThreat` creation

### 5. Key Benefits

#### User ID Tracking
- **Full traceability**: Username tracked from raw event → normalized event → threat match → deterministic threat → incident
- **Multiple actors**: Supports incidents with multiple usernames (credential stuffing, shared IPs, etc.)
- **Correlation display**: Shows both IP and username for better analyst context

#### AI-Driven Human Review
- **No hard thresholds**: Removed rigid confidence/priority thresholds
- **Contextual decisions**: AI considers multiple factors (not just confidence score)
- **Explainable**: AI provides reason when flagging for review
- **Flexible**: Falls back gracefully if AI doesn't provide a decision
- **Reduces noise**: AI can confidently mark simple incidents as not needing review

#### Correlation Information
- **Unified view**: Single field shows "IP: x.x.x.x | User: username"
- **Multiple actors**: Shows additional IPs and users when relevant
- **Always available**: Populated for all incident sources (AI, deterministic, correlation)

## Migration Notes

### Database
If using a persistent database (not just JSON files), you may need to add these columns:
```sql
ALTER TABLE incidents ADD COLUMN primary_actor_username TEXT;
ALTER TABLE incidents ADD COLUMN source_username TEXT;
ALTER TABLE incidents ADD COLUMN correlation_info TEXT;
```

### API Compatibility
- New fields are optional, so existing API consumers won't break
- Consumers can check for `source_username` and `correlation_info` fields
- Old behavior preserved when username data is not available (fields will be null)

### Existing Incidents
- Existing incidents in `incidents_data.json` will load without usernames
- New incidents will have full username tracking
- No data migration needed (optional fields)

## Testing Recommendations

1. **Test username extraction**: Upload logs with username fields and verify they appear in incidents
2. **Test AI review decisions**: Check that `ai_needs_human_review` is populated and reasonable
3. **Test correlation display**: Verify `correlation_info` shows both IP and username
4. **Test fallback behavior**: Ensure system works when usernames are not available
5. **Test multiple actors**: Upload events with multiple IPs/usernames and verify aggregation

## Example Output

### Before
```json
{
  "source_ip": "192.168.1.100",
  "requires_human_review": true
}
```

### After
```json
{
  "source_ip": "192.168.1.100",
  "source_username": "john.doe",
  "correlation_info": "IP: 192.168.1.100 | User: john.doe",
  "requires_human_review": false,
  "ai_needs_human_review": false,
  "ai_review_reason": null
}
```

## Future Enhancements

1. **User-based clustering**: Group incidents by username in addition to IP
2. **User behavior profiles**: Track normal behavior per user
3. **Privileged user tracking**: Flag incidents involving admin/privileged accounts
4. **Cross-user correlation**: Detect patterns across multiple user accounts
5. **User risk scoring**: Calculate risk scores per user over time
