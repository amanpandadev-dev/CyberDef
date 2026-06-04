# Migration Guide: Triage Agent Refactoring

## Summary of Changes

**Date:** 2026-06-04  
**Change Type:** Breaking API Change  
**Affected Component:** Triage Agent (Tier 3 AI Analysis)

### What Changed?

The Triage Agent has been refactored from a redundant TP/FP validator to a focused priority/response agent.

**Before (Old Behavior):**
- Triage Agent re-validated True Positive vs False Positive decisions
- Output included `suspicious: bool` field
- Created redundancy with Behavioral Agent's `is_suspicious` field
- Prompt was biased toward False Positive detection

**After (New Behavior):**
- Triage Agent TRUSTS Behavioral Agent's TP/FP decision
- Output NO LONGER includes `suspicious` field
- Focuses exclusively on priority, response actions, and narratives
- Prompt is balanced and actionable

---

## Breaking Changes

### 1. TriageResult Model (`shared_models/agents.py`)

**REMOVED FIELD:**
```python
# ❌ This field no longer exists:
suspicious: bool = Field(default=True, description="Whether behavior is suspicious")
```

**Migration:**
```python
# OLD CODE:
if triage_result.suspicious:
    create_incident()

# NEW CODE:
# Use behavioral agent's decision instead:
if behavioral_result.is_suspicious:
    create_incident()

# Or from AgentOutput:
if agent_output.behavioral and agent_output.behavioral.is_suspicious:
    create_incident()
```

### 2. Priority Levels

**REMOVED VALUE:**
```python
# ❌ Informational priority no longer returned by Triage Agent
# (It was only used for False Positives, which Triage no longer decides)

# Priority levels are now:
- Critical
- High
- Medium
- Low
```

**Migration:**
```python
# OLD CODE:
if triage.priority == IncidentPriority.INFORMATIONAL:
    mark_as_false_positive()

# NEW CODE:
# Check behavioral agent instead:
if not behavioral.is_suspicious:
    mark_as_false_positive()
else:
    # Use triage priority for response prioritization
    if triage.priority == IncidentPriority.CRITICAL:
        escalate_immediately()
```

---

## Updated Files

| File | Changes | Status |
|------|---------|--------|
| `agents/triage_agent.py` | Refactored prompts, removed TP/FP logic | ✅ Updated |
| `shared_models/agents.py` | Removed `suspicious` field from TriageResult | ✅ Updated |
| `agents/orchestrator.py` | Changed merge logic to use `behavioral.is_suspicious` | ✅ Updated |
| `main.py` | Updated TP detection logic | ✅ Updated |
| `incidents/service.py` | Updated incident creation logic | ✅ Updated |
| `agents/merge_agent.py` | Updated merge rules documentation | ✅ Updated |
| `tests/test_agent_graph_orchestration.py` | Fixed test fixtures | ✅ Updated |

---

## Code Migration Examples

### Example 1: Checking if Incident is Suspicious

**Before:**
```python
agent_output = await orchestrator.analyze(chunk)
if agent_output.triage and agent_output.triage.suspicious:
    print("Suspicious activity detected!")
```

**After:**
```python
agent_output = await orchestrator.analyze(chunk)
if agent_output.behavioral and agent_output.behavioral.is_suspicious:
    print("Suspicious activity detected!")
```

### Example 2: Creating Incidents

**Before:**
```python
def create_incident(agent_output: AgentOutput):
    triage = agent_output.triage
    is_threat = triage and triage.suspicious
    
    if not is_threat:
        return None  # Skip False Positives
        
    priority = triage.priority if triage else IncidentPriority.MEDIUM
    return Incident(priority=priority, ...)
```

**After:**
```python
def create_incident(agent_output: AgentOutput):
    # Check behavioral agent for TP/FP decision
    behavioral = agent_output.behavioral
    is_threat = behavioral and behavioral.is_suspicious
    
    if not is_threat:
        return None  # Skip False Positives
        
    # Use triage for priority assessment
    triage = agent_output.triage
    priority = triage.priority if triage else IncidentPriority.MEDIUM
    return Incident(priority=priority, ...)
```

### Example 3: Merge Logic

**Before:**
```python
# Pick best result based on triage.suspicious
best = max(outputs, key=lambda o: (
    1 if (o.triage and o.triage.suspicious) else 0,
    o.overall_confidence
))
```

**After:**
```python
# Pick best result based on behavioral.is_suspicious
best = max(outputs, key=lambda o: (
    1 if (o.behavioral and o.behavioral.is_suspicious) else 0,
    o.overall_confidence
))
```

---

## API Response Changes

### AgentOutput JSON Structure

**Before:**
```json
{
  "behavioral": {
    "is_suspicious": true,
    "confidence": 0.85
  },
  "triage": {
    "suspicious": true,  // ❌ Redundant with behavioral
    "priority": "High",
    "confidence": 0.78
  }
}
```

**After:**
```json
{
  "behavioral": {
    "is_suspicious": true,  // ✅ Single source of truth for TP/FP
    "confidence": 0.85
  },
  "triage": {
    // suspicious field removed
    "priority": "High",  // ✅ Focused on prioritization
    "confidence": 0.82
  }
}
```

---

## Database Schema Impact

### If you have persisted TriageResult in database:

**Option 1: Add computed column**
```sql
-- Add virtual column that references behavioral.is_suspicious
ALTER TABLE incidents 
ADD COLUMN suspicious_computed BOOLEAN 
GENERATED ALWAYS AS (
    CASE 
        WHEN behavioral_is_suspicious IS NOT NULL 
        THEN behavioral_is_suspicious 
        ELSE TRUE 
    END
) STORED;
```

**Option 2: Backfill from behavioral agent**
```python
# Migration script
for incident in Incident.query.all():
    if incident.agent_output:
        behavioral = incident.agent_output.get('behavioral', {})
        incident.suspicious = behavioral.get('is_suspicious', True)
        db.session.commit()
```

---

## Testing Checklist

- [ ] Unit tests updated for TriageResult (remove `suspicious` assertions)
- [ ] Integration tests updated for incident creation
- [ ] API response tests verify `suspicious` field removed
- [ ] Report generation tests check behavioral.is_suspicious
- [ ] Merge logic tests verify correct behavior selection
- [ ] Cache invalidation (old cached results have `triage.suspicious`)

---

## Rollback Plan

If you need to rollback:

1. **Restore old triage_agent.py:**
   ```bash
   git checkout HEAD~1 agents/triage_agent.py
   ```

2. **Restore old shared_models/agents.py:**
   ```bash
   git checkout HEAD~1 shared_models/agents.py
   ```

3. **Restore updated caller files:**
   ```bash
   git checkout HEAD~1 main.py incidents/service.py agents/orchestrator.py
   ```

4. **Clear analysis cache** (contains new format):
   ```bash
   rm -rf data/processed/analysis_cache/*
   ```

---

## Benefits of This Change

### Before (Problems):
- ❌ Two agents doing the same TP/FP validation
- ❌ Conflicting verdicts (behavioral says TP, triage says FP)
- ❌ Wasted computation (Intent + MITRE ignored by Triage)
- ❌ Prompt bias toward False Positives
- ❌ Perverse incentive (high FP confidence requirement)

### After (Improvements):
- ✅ Clear separation of concerns
- ✅ Behavioral Agent = TP/FP validation
- ✅ Triage Agent = Priority + Response
- ✅ No conflicting verdicts
- ✅ Better utilization of upstream agent insights
- ✅ Balanced, actionable prompts
- ✅ Faster processing (less redundancy)

---

## Support

If you encounter issues after this change:

1. Check that all references to `triage.suspicious` are updated
2. Verify behavioral agent is working correctly (it's now critical path)
3. Clear analysis cache if seeing format errors
4. Review migration examples above

For questions, see: `TRIAGE_AGENT_ANALYSIS.md`
