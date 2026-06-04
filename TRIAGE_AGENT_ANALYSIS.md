# Triage Agent Analysis - Critical Issues Found

## Executive Summary

**CRITICAL ISSUES IDENTIFIED:**
1. ✅ **Triage Agent receives all prior agent outputs** (behavioral, intent, mitre)
2. ⚠️ **Prompt is biased toward False Positive detection** - not balanced
3. ⚠️ **Redundancy problem** - Behavioral agent already does TP/FP validation, then Triage does it again
4. ⚠️ **Contradictory guidance** in prompts creates confusion

---

## 1. Agent Chain Flow & Data Passing

### Agent Execution Order:
```
Behavioral Agent → Intent Agent → MITRE Agent → Triage Agent
```

### How Agent Outputs Are Passed:

From `orchestrator.py` line 325-335:
```python
async def _triage_node(self, state: AgentGraphState) -> AgentGraphState:
    triage = await self.triage_agent.analyze(
        self._summary_with_context(
            state,
            include=("behavioral", "intent", "mitre"),  # ✅ ALL PRIOR OUTPUTS INCLUDED
            include_errors=True,
        ),
        chunk_id,
    )
```

The `_summary_with_context` method (line 355-373) adds a special `_agent_context` field:
```python
summary["_agent_context"] = {
    "prompt_schema_version": PROMPT_SCHEMA_VERSION,
    "prior_outputs": {
        "behavioral": {
            "interpretation": "...",
            "is_suspicious": true,
            "confidence": 0.85,
            "reasoning": "...",
            "key_indicators": [...]
        },
        "intent": {
            "suspected_intent": "...",
            "kill_chain_stage": "...",
            "confidence": 0.78,
            ...
        },
        "mitre": {
            "technique_id": "T1190",
            "technique_name": "...",
            "confidence": 0.82,
            ...
        }
    },
    "agent_errors": [...]
}
```

**✅ YES - Prior agent outputs ARE being sent to Triage Agent**

---

## 2. Critical Issue: Redundant TP/FP Validation

### Problem: Two Agents Doing the Same Job

#### Behavioral Agent's Role (behavioral_agent.py):
```python
agent_system_prompt = """You are a cybersecurity True Positive / False Positive validator.

Your input is a JSON behavioral chunk from a deterministic security rules engine.
The chunk contains a "flagged_rules" array — each entry was triggered by a regex or scored pattern match.

YOUR ROLE: Confirm or deny whether the rule's evidence represents a real attack.

CRITICAL — THE EVIDENCE IS THE PROOF:
The "flagged_rules[].evidence" field contains the ACTUAL payload or pattern that triggered the rule.
If that evidence contains attack content, it IS a True Positive. Do NOT second-guess the rule.
"""

Output:
{
    "is_suspicious": true/false,  // TP or FP decision
    "confidence": 0.85
}
```

#### Triage Agent's Role (triage_agent.py):
```python
agent_system_prompt = """You are a senior SOC analyst with expertise in incident triage and TP/FP adjudication.

Your task is to make the FINAL decision on whether a pre-flagged security finding is a True Positive (TP) or a False Positive (FP).

If it is a True Positive:
- Set suspicious=true
- Assign the appropriate priority (Critical/High/Medium)

If it is a False Positive:
- Set suspicious=false
- Set priority=Informational
- Set confidence >= 0.9
"""

Output:
{
    "suspicious": true/false,  // TP or FP decision AGAIN
    "priority": "Critical|High|Medium|Low|Informational"
}
```

**🔴 PROBLEM: Both agents are doing TP/FP validation!**

- Behavioral Agent: Already decides `is_suspicious` (TP/FP)
- Triage Agent: Receives behavioral agent's `is_suspicious` decision, then makes the SAME decision again in `suspicious` field

**This creates redundancy and potential conflicts.**

---

## 3. Critical Issue: Prompt Bias Toward False Positives

### Triage Agent Prompt Analysis:

From `triage_agent.py` line 41-60:

```python
agent_system_prompt = """You are a senior SOC analyst with expertise in incident triage and TP/FP adjudication.

Your task is to make the FINAL decision on whether a pre-flagged security finding is a True Positive (TP) or a False Positive (FP).

You do NOT discover new threats. You only evaluate whether the already-flagged finding — and the behavioral evidence in the chunk — justifies creating an incident.

If it is a True Positive:
- Set suspicious=true
- Assign the appropriate priority (Critical/High/Medium)
- Provide a clear technical justification

If it is a False Positive:
- Set suspicious=false
- Set priority=Informational
- Set confidence >= 0.9    # ⚠️ FPs must have HIGH confidence
- Explain concisely why the evidence does NOT support the flag

Priority levels (for True Positives only):
- Critical: Active threat, immediate response required
- High: Likely malicious, investigate within hours  
- Medium: Suspicious pattern, investigate within 24 hours
- Low: Marginal evidence, review when time permits
- Informational: False Positive — no action needed    # ⚠️ Low/Informational conflated

Be specific, actionable, and conservative: only use Critical/High for clear evidence of malicious activity.
"""
```

### ⚠️ **Bias Analysis:**

| Aspect | True Positive | False Positive | Bias Score |
|--------|--------------|----------------|------------|
| **Confidence requirement** | No specific threshold | **Must be >= 0.9** (very high) | 🔴 **FP-biased** |
| **Wording** | "clear evidence" | "concisely explain why NOT" | 🔴 **FP-biased** |
| **Priority guidance** | 4 levels (Critical/High/Medium/Low) | 1 level (Informational) | 🟡 **Neutral** |
| **Conservative stance** | "only use Critical/High for clear evidence" | No conservative guidance | 🔴 **FP-biased** |
| **Default position** | Must prove TP | Assumed FP unless proven | 🔴 **FP-biased** |

### 🔴 **Key Issues:**

1. **Asymmetric confidence requirements:**
   - FP requires `confidence >= 0.9` (explicit)
   - TP has no minimum confidence threshold
   - **This creates pressure to mark things as FP to achieve high confidence**

2. **"Conservative" means different things:**
   - System prompt says "be conservative" → suggests marking as FP when uncertain
   - But conservative in security should mean **err on side of caution = flag as TP**
   - **Contradiction in guidance**

3. **Low vs Informational confusion:**
   - Priority levels include "Low" for TPs
   - But prompt says "Informational: False Positive — no action needed"
   - **What about low-confidence TPs that need review but aren't critical?**

4. **Burden of proof:**
   - TP: "only use Critical/High for **clear evidence**"
   - FP: just "explain concisely why evidence does NOT support"
   - **Higher bar for TP than FP**

---

## 4. Specific Prompt Issues in build_prompt()

From `triage_agent.py` line 72-146:

### Issue 4.1: Conflicting Instructions

```python
prompt = f"""A security finding was raised by upstream rules. You are the final judge. Let the given data decide whether it satisfies the flagged threat.

{rules_section}FLAGGED BEHAVIORAL SUMMARY:
{json.dumps(summary, indent=2)}

You must:
1. Decide whether all the given data satisfies the flagged threat.
2. Provide concrete evidence for your decision.
3. If it is a False Positive (FP), explain exactly why it dropped (why the evidence does not support the rule). Set suspicious=false and priority=Informational.
4. If it is a True Positive (TP), explain exactly why it is a TP with concrete evidence. Set suspicious=true and assign an appropriate priority.
```

**Problem:** 
- Step 3 mentions FP first
- Uses word "dropped" which implies FP is the default
- Step 4 mentions TP second
- **Order matters psychologically - FP presented as primary option**

### Issue 4.2: Rules-Specific Section

```python
if flagged_rules:
    rules_block = json.dumps(flagged_rules, indent=2)
    rules_section = f"""RULES THAT FLAGGED THIS IP (evaluate each one specifically):
{rules_block}

For EACH rule above you MUST address:
- Does the behavioral evidence in this chunk actually support that specific rule's detection logic?
- If NOT, explain concisely WHY the rule fired as a false positive (e.g. "blind_sql_injection: 2xx responses observed but all URIs contain only pagination parameters, not time-delay payloads").
- Your risk_reason must name the specific rule(s) and explain the FP rationale, NOT generic behavioral commentary.
"""
```

**Problem:**
- Bullet 2 is entirely FP-focused: "If NOT, explain... WHY the rule fired as a false positive"
- **No equivalent bullet for "If YES, explain WHY it's a true positive"**
- Example given is an FP example
- **Strong bias toward FP reasoning**

### Issue 4.3: Guidelines Section

```python
Guidelines:
- suspicious=true ONLY if upstream agents confirm concrete malicious evidence.    # ⚠️ HIGH BAR
- suspicious=false if evidence is ambiguous, benign, or a known false positive pattern.    # ⚠️ LOW BAR
- confidence_score must align with confidence (0.0-1.0 mapped to 1-10).
- For False Positives: priority must be Informational, confidence >= 0.9.    # ⚠️ FP GETS SPECIAL RULES
- Do NOT add MITRE techniques or attack names for False Positives.
- tp_justification must cite specific evidence from the chunk AND the specific rule name; set to null for FPs.
- raw_log MUST be extracted from the 'sample_raw_logs' array in the chunk summary, if available.
```

**Problems:**
1. **"ONLY if"** - creates artificial barrier for TPs
2. **Ambiguous = FP** - uncertainty defaults to FP (should be opposite in security)
3. **FP gets 3 special rules, TP gets 1** - unbalanced attention

---

## 5. Impact Assessment

### Current Behavior:

```
Deterministic Rules (Tier 1) 
  ↓ Flag threats with evidence
Behavioral Agent
  ↓ Validates: is_suspicious = true (TP)
  ↓ confidence = 0.85
Intent Agent
  ↓ Maps to kill chain
MITRE Agent  
  ↓ Maps to T1190 (Exploit Public-Facing Application)
Triage Agent
  ↓ Receives: is_suspicious=true from behavioral
  ↓ Prompt bias pushes toward FP
  ↓ Likely outcome: suspicious=false (FP override)
  ↓ Result: Incident marked as Informational
```

### Problems This Causes:

1. **True threats downgraded to FP** due to:
   - Conservative FP-biased wording
   - High confidence requirement for FP (creates incentive)
   - "Ambiguous = FP" guideline

2. **Wasted computational resources**:
   - Behavioral agent already validates TP/FP
   - Intent and MITRE agents analyze attack patterns
   - Triage agent ignores all of this and re-decides from scratch

3. **Inconsistent verdicts**:
   - Behavioral: `is_suspicious = true`
   - Triage: `suspicious = false`
   - **Which one should the system trust?**

4. **Analyst confusion**:
   - Report shows conflicting signals
   - Hard to understand why incident was downgraded

---

## 6. Recommendations

### Option A: Refactor Triage Agent Role

**Change Triage Agent from TP/FP validator → Priority/Action recommender**

Remove TP/FP decision (trust Behavioral Agent's verdict):

```python
agent_system_prompt = """You are a senior SOC analyst specializing in incident prioritization and response planning.

You receive a CONFIRMED threat (already validated as True Positive by upstream agents) and must:
1. Assign appropriate priority (Critical/High/Medium/Low) based on severity and impact
2. Recommend specific investigation steps
3. Provide executive and technical summaries
4. Suggest enrichment data sources

Priority Levels:
- Critical: Active exploitation, data breach, ransomware → Immediate response
- High: Confirmed attack attempt, credential compromise → Investigate within hours
- Medium: Suspicious pattern, reconnaissance activity → Investigate within 24 hours  
- Low: Minor anomaly, low-risk behavior → Review when time permits

Your role is NOT to re-validate TP/FP (already done). Your role is to help analysts prioritize response.
"""
```

**Remove these fields from Triage output:**
- `suspicious` (already in Behavioral.is_suspicious)

**Keep these fields:**
- `priority`
- `recommended_action`
- `executive_summary`
- `technical_summary`
- All MITRE/incident fields

### Option B: Remove Behavioral Agent

If Triage Agent should do TP/FP validation, then **remove Behavioral Agent** entirely:

```
Deterministic Rules → Intent Agent → MITRE Agent → Triage Agent
```

Make Triage Agent the FIRST agent that validates TP/FP.

### Option C: Balance the Prompts (Minimal Change)

If keeping current architecture, fix the bias:

**Changes to triage_agent.py:**

1. **Remove confidence asymmetry:**
```python
# OLD:
- For False Positives: priority must be Informational, confidence >= 0.9.

# NEW:
- For False Positives: priority must be Informational, confidence >= 0.75.
- For True Positives: confidence should reflect certainty of threat classification.
```

2. **Balance the guidelines:**
```python
Guidelines:
- suspicious=true if upstream agents confirm malicious evidence OR if evidence suggests attack behavior
- suspicious=false if evidence is clearly benign or a known false positive pattern
- When evidence is ambiguous, prefer suspicious=true with Low priority and note uncertainty
```

3. **Reorder instructions (TP first):**
```python
You must:
1. Decide whether the given data satisfies the flagged threat.
2. Provide concrete evidence for your decision.
3. If it is a True Positive (TP), explain exactly why with concrete evidence. Set suspicious=true and assign appropriate priority.
4. If it is a False Positive (FP), explain exactly why the evidence does not support the rule. Set suspicious=false and priority=Informational.
```

4. **Add balanced rule evaluation:**
```python
For EACH rule above you MUST address:
- Does the behavioral evidence in this chunk support that specific rule's detection logic?
- If YES, cite the specific evidence that confirms the threat (e.g. "sql_injection: URI contains 'SELECT * FROM' with error-based response patterns")
- If NO, explain why the rule fired as a false positive (e.g. "blind_sql_injection: 2xx responses with normal pagination parameters only")
```

---

## 7. Example Scenario Showing the Problem

### Input to System:
```
Source IP: 89.38.29.78
URI: /admin/config.php?id=1' OR '1'='1
Status: 403
Flagged Rule: sql_injection (Critical, Tier 1)
Evidence: "URI contains: id=1' OR '1'='1"
```

### Behavioral Agent Output:
```json
{
  "is_suspicious": true,
  "confidence": 0.85,
  "reasoning": "Classic SQL injection payload in URI parameter",
  "key_indicators": ["SQL boolean injection pattern", "Access to admin path", "Blocked by WAF"]
}
```

### Current Triage Agent Likely Output (Due to Bias):
```json
{
  "suspicious": false,  // ⚠️ Overrides Behavioral Agent!
  "priority": "Informational",
  "confidence": 0.92,  // High confidence because FP requires >= 0.9
  "risk_reason": "Request was blocked (403), no actual exploitation occurred",
  "tp_justification": null
}
```

**Problem:** System marks a clear SQL injection attempt as FP just because it was blocked!

### What Should Happen:
```json
{
  "suspicious": true,  // Trust Behavioral Agent
  "priority": "High",  // Attack attempt, investigate within hours
  "confidence": 0.85,
  "risk_reason": "SQL injection attack attempt against admin interface",
  "tp_justification": "URI contains boolean-based SQL injection payload '1' OR '1'='1' targeting admin config endpoint. Attack was blocked by WAF but represents targeted reconnaissance."
}
```

---

## 8. Code References

| File | Lines | Issue |
|------|-------|-------|
| `agents/triage_agent.py` | 41-60 | System prompt FP bias |
| `agents/triage_agent.py` | 72-146 | User prompt FP bias |
| `agents/behavioral_agent.py` | 30-50 | Redundant TP/FP validation |
| `agents/orchestrator.py` | 325-335 | Agent output passing (working correctly) |
| `agents/orchestrator.py` | 355-373 | Context building (working correctly) |
| `shared_models/agents.py` | 69-93 | BehavioralInterpretation model |
| `shared_models/agents.py` | 190-230 | TriageResult model |

---

## Conclusion

**Key Findings:**
1. ✅ Agent outputs ARE being passed correctly to downstream agents
2. 🔴 Triage Agent prompt is HEAVILY biased toward False Positive detection
3. 🔴 Redundant TP/FP validation between Behavioral and Triage agents
4. 🔴 Confidence requirements create perverse incentive to mark TPs as FPs

**Recommended Action:** Option A (Refactor Triage Role) - most architecturally sound

**Quick Fix:** Option C (Balance Prompts) - fastest to implement
