# Implementation Flow: Username & AI-Driven Human Review

## Data Flow: Username Tracking

```
Raw Event (CSV/Log)
    ↓ [username field]
NormalizedEvent
    ↓ [username field]
ThreatMatch (from rules)
    ↓ [src_username field]
DeterministicThreat (grouped)
    ↓ [src_username, src_usernames fields]
Incident
    ↓ [primary_actor_username, actor_usernames, source_username, correlation_info]
JSON Report / API Response
```

## AI Decision Flow: Human Review

### Old Way (Hard Thresholds)
```
Agent Output
    ↓
Check: is_suspicious? → Yes → requires_human_review = True
    ↓
Check: priority in [Critical, High, Medium]? → Yes → requires_human_review = True
    ↓
Check: confidence < threshold? → Yes → requires_human_review = True
    ↓
Otherwise → requires_human_review = False
```

### New Way (AI-Driven)
```
Agent Output (with AI reasoning)
    ↓
Triage Agent analyzes:
  - Evidence ambiguity
  - Attack sophistication
  - Target criticality
  - False positive potential
  - Novel patterns
  - Overall confidence
    ↓
AI sets: ai_needs_human_review = True/False
AI sets: ai_review_reason = "explanation..."
    ↓
Orchestrator uses AI decision:
  requires_human_review = ai_needs_human_review
    ↓
(Fallback to old logic if AI doesn't provide decision)
```

## Correlation Info Format

```python
# Single actor
correlation_info = "IP: 192.168.1.100 | User: john.doe"

# Multiple IPs and users
correlation_info = "IP: 192.168.1.100 | User: john.doe | Additional IPs: 192.168.1.101, 192.168.1.102 | Additional Users: jane.smith, bob.jones"

# IP only (no username)
correlation_info = "IP: 192.168.1.100"

# Username only (no IP)
correlation_info = "User: john.doe"
```

## Modified Files

### Core Models
1. ✅ `shared_models/incidents.py` - Added username & correlation fields
2. ✅ `shared_models/agents.py` - Added AI review decision fields
3. ✅ `rules_engine/models.py` - Added username to ThreatMatch & DeterministicThreat

### AI Agents
4. ✅ `agents/triage_agent.py` - Updated prompt for username & AI review decision
5. ✅ `agents/orchestrator.py` - Use AI's review decision instead of hard thresholds

### Rules Engine
6. ✅ `rules_engine/base_rule.py` - Auto-populate username in ThreatMatch
7. ✅ `rules_engine/engine.py` - Aggregate usernames in threat grouping

### Incident Creation
8. ✅ `incidents/service.py` - Extract & populate username and correlation info

## Key Features

### 1. Username Tracking
- ✅ Captured from raw events
- ✅ Preserved through normalization
- ✅ Included in threat matches
- ✅ Aggregated in threats (handles multiple users)
- ✅ Displayed in incidents
- ✅ Shown in correlation info

### 2. AI-Driven Human Review
- ✅ AI makes contextual decisions
- ✅ AI provides explanation
- ✅ No hard confidence thresholds
- ✅ Graceful fallback if AI fails
- ✅ Reduces false-positive review flags

### 3. Correlation Display
- ✅ Combined IP & username view
- ✅ Shows multiple actors when relevant
- ✅ Available for all incident types
- ✅ Human-readable format

## Testing Checklist

### Username Tracking
- [ ] Upload logs with username field
- [ ] Verify username in normalized events
- [ ] Check username in threat matches
- [ ] Confirm username in incidents
- [ ] Test multiple usernames in same incident
- [ ] Test missing username (should not break)

### AI Human Review Decision
- [ ] Verify `ai_needs_human_review` is set
- [ ] Check `ai_review_reason` is meaningful
- [ ] Test high-severity incidents (likely need review)
- [ ] Test low-severity incidents (likely don't need review)
- [ ] Test ambiguous cases (AI should flag for review)
- [ ] Verify fallback to old logic if AI field missing

### Correlation Info
- [ ] Check format: "IP: x.x.x.x | User: username"
- [ ] Test with only IP (no username)
- [ ] Test with only username (no IP)
- [ ] Test with multiple IPs and users
- [ ] Verify correlation_info in JSON output

### Edge Cases
- [ ] Events without username field
- [ ] Events with null/empty username
- [ ] Events with placeholder usernames ("-", "unknown")
- [ ] Mixed authenticated/unauthenticated events
- [ ] High-volume incidents with many unique users
- [ ] AI timeout or error (should fallback gracefully)

## API Response Example

```json
{
  "incident_id": "123e4567-e89b-12d3-a456-426614174000",
  "title": "[SQL INJECTION] Detected from 192.168.1.100",
  "priority": "high",
  "source_ip": "192.168.1.100",
  "source_username": "john.doe",
  "primary_actor_ip": "192.168.1.100",
  "primary_actor_username": "john.doe",
  "actor_ips": ["192.168.1.100"],
  "actor_usernames": ["john.doe"],
  "correlation_info": "IP: 192.168.1.100 | User: john.doe",
  "requires_human_review": false,
  "ai_needs_human_review": false,
  "ai_review_reason": null,
  "confidence_score": 8,
  "overall_confidence": 0.85,
  "attack_name": "SQL Injection",
  "detection_tier": "deterministic"
}
```

## Backward Compatibility

All new fields are **optional**, ensuring backward compatibility:

- `source_username`: null if not available
- `primary_actor_username`: null if not available  
- `actor_usernames`: empty list if not available
- `correlation_info`: null if neither IP nor username available
- `ai_needs_human_review`: null if AI doesn't provide decision
- `ai_review_reason`: null if review not needed or AI doesn't provide

Existing API consumers will continue to work without modification.
