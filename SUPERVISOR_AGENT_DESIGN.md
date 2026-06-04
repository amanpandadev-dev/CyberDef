# Supervisor Agent Design

## Goal
Create a Supervisor Agent that intelligently controls which agents to run based on the input data, previous agent outputs, and confidence levels.

---

## Current System (Without Supervisor)

```
Behavioral Agent (always runs)
    ↓
Intent Agent (always runs)
    ↓
MITRE Agent (always runs)
    ↓
Triage Agent (always runs)
```

**Problems:**
- ❌ Wastes computation on low-confidence findings
- ❌ Runs all agents even when Behavioral says "clearly benign"
- ❌ No adaptive decision-making
- ❌ Fixed pipeline regardless of input complexity

---

## Proposed System (With Supervisor)

```
                    Supervisor Agent
                          ↓
        ┌─────────────────┼─────────────────┐
        ↓                 ↓                  ↓
   [Decision]        [Decision]         [Decision]
        ↓                 ↓                  ↓
  Run Behavioral    Run Intent/MITRE    Run Triage
    (always)        (if suspicious)    (if confident)
```

**Benefits:**
- ✅ Adaptive agent execution based on data
- ✅ Saves computation on obvious cases
- ✅ Can skip expensive agents when not needed
- ✅ Can loop back for more context if uncertain
- ✅ Provides reasoning for decisions

---

## Design Options

### **Option 1: Pre-Agent Supervisor (Router Pattern)**
Supervisor decides BEFORE running agents which ones to execute.

**Flow:**
```
Input → Supervisor analyzes → Decides agent path → Executes → Output
```

**Pros:**
- Fast decision upfront
- Can skip unnecessary agents entirely

**Cons:**
- No access to agent outputs for decision-making
- Less adaptive

### **Option 2: Post-Agent Supervisor (Orchestrator Pattern)**
Supervisor runs AFTER each agent and decides next steps.

**Flow:**
```
Input → Behavioral → Supervisor → Intent → Supervisor → MITRE → Supervisor → Triage → Output
```

**Pros:**
- Adaptive based on actual agent outputs
- Can skip remaining agents if confident
- Can loop back for more analysis

**Cons:**
- More LLM calls (supervisor runs multiple times)
- Slower

### **Option 3: Meta-Supervisor (Hybrid Pattern)** ⭐ **RECOMMENDED**
Supervisor makes high-level decisions, existing orchestrator handles execution.

**Flow:**
```
Input → Supervisor (classify complexity) → Orchestrator (execute plan) → Output
              ↓
    [Simple | Standard | Complex | Critical]
```

**Pros:**
- ✅ Single supervisor call
- ✅ Leverages existing orchestrator
- ✅ Clear separation of concerns
- ✅ Can define execution strategies

**Cons:**
- Requires predefined strategies

---

## Recommended Implementation: Option 3 (Meta-Supervisor)

### Architecture

```python
class SupervisorAgent(BaseAgent[SupervisorDecision]):
    """
    Meta-agent that analyzes input and decides execution strategy.
    """
    
    async def analyze(summary: dict) -> SupervisorDecision:
        """
        Analyzes chunk summary and decides:
        1. Execution strategy (skip_agents, full_analysis, etc.)
        2. Priority hint for orchestrator
        3. Reasoning for decision
        """
        
class AgentOrchestrator:
    """
    Existing orchestrator enhanced with supervisor support.
    """
    
    def __init__(self, use_supervisor: bool = True):
        self.supervisor = SupervisorAgent() if use_supervisor else None
    
    async def analyze(summary: ChunkSummary) -> AgentOutput:
        # 1. Supervisor decides strategy
        if self.supervisor:
            decision = await self.supervisor.analyze(summary)
            strategy = decision.execution_strategy
        else:
            strategy = "full_analysis"
        
        # 2. Execute based on strategy
        if strategy == "skip_all":
            return minimal_output()
        elif strategy == "behavioral_only":
            return await self._run_behavioral_only()
        elif strategy == "standard_flow":
            return await self._run_standard_flow()
        elif strategy == "full_analysis":
            return await self._run_full_analysis()
```

---

## Execution Strategies

### **1. skip_all** - Clearly Benign
**When:**
- No flagged rules
- Low anomaly score
- Known good source IP
- Normal business hours traffic

**Agent Path:**
```
None (return early with benign verdict)
```

**Example:**
- Internal employee accessing corporate portal during work hours
- Routine database backup traffic
- Scheduled system updates

---

### **2. behavioral_only** - Quick Assessment
**When:**
- Single low-severity rule match
- High confidence deterministic detection
- Known FP pattern

**Agent Path:**
```
Behavioral → Skip rest
```

**Example:**
- Single blocked request from known scanner
- Routine port scan from security tool
- False positive from overly sensitive rule

---

### **3. standard_flow** - Normal Analysis
**When:**
- Moderate anomaly score
- 1-2 flagged rules
- Standard attack patterns

**Agent Path:**
```
Behavioral → Intent → Triage
(Skip MITRE for speed)
```

**Example:**
- Basic SQL injection attempt (blocked)
- Simple XSS probe
- Single authentication failure

---

### **4. full_analysis** - Deep Investigation
**When:**
- High anomaly score
- Multiple flagged rules
- Novel attack pattern
- Critical infrastructure target

**Agent Path:**
```
Behavioral → Intent → MITRE → Triage
(All agents with detailed analysis)
```

**Example:**
- Multi-stage attack sequence
- APT-like behavior
- Successful exploitation indicators
- Lateral movement patterns

---

### **5. critical_priority** - Emergency Response
**When:**
- Active exploitation confirmed
- Data exfiltration detected
- Ransomware indicators
- C2 communication

**Agent Path:**
```
Behavioral → Intent → MITRE → Triage
+ Immediate escalation
+ Enhanced logging
+ Auto-notification
```

**Example:**
- Successful RCE
- Database dump in progress
- Privilege escalation detected
- Active C2 beaconing

---

## Supervisor Prompt Design

```python
agent_system_prompt = """You are a Senior Security Operations Supervisor.

Your role is to QUICKLY assess a security finding and decide the appropriate analysis strategy.

You receive:
- Chunk summary with behavioral data
- Flagged rules from deterministic engine
- Anomaly scores and red flags

You decide:
1. Execution strategy (skip_all | behavioral_only | standard_flow | full_analysis | critical_priority)
2. Reasoning for your decision
3. Priority hint (low | medium | high | critical)

Decision Guidelines:

SKIP_ALL - When clearly benign:
- No flagged rules OR only informational-level rules
- Anomaly score < 20
- Normal business patterns
- Known good actors

BEHAVIORAL_ONLY - When quick assessment sufficient:
- Single low-severity rule match
- Anomaly score 20-40
- Known FP patterns
- High confidence deterministic detection

STANDARD_FLOW - When moderate investigation needed:
- 1-2 flagged rules
- Anomaly score 40-70
- Standard attack patterns (SQL injection, XSS, etc.)
- Blocked by security controls

FULL_ANALYSIS - When deep analysis required:
- 3+ flagged rules
- Anomaly score 70-90
- Novel attack patterns
- Multiple attack vectors
- Sophisticated techniques

CRITICAL_PRIORITY - When emergency response needed:
- Anomaly score > 90
- Active exploitation indicators
- Data breach indicators (exfiltration, dumps)
- C2 communication
- Ransomware/destructive malware
- Successful privilege escalation

Be decisive. Err on the side of deeper analysis for ambiguous cases.
"""
```

---

## Implementation Plan

### Phase 1: Create Supervisor Agent ✅

**File:** `agents/supervisor_agent.py`

```python
from agents.base import BaseAgent
from shared_models.agents import SupervisorDecision

class SupervisorAgent(BaseAgent[SupervisorDecision]):
    name = "supervisor"
    description = "Decides agent execution strategy based on input analysis"
    output_schema = SupervisorDecision
    
    agent_system_prompt = """..."""  # See above
    
    def build_prompt(self, summary: dict) -> str:
        flagged_rules = summary.get("flagged_rules", [])
        anomaly_score = summary.get("anomaly_score", 0)
        red_flags = summary.get("red_flags", [])
        
        return f"""
        Analyze this security finding and decide the execution strategy.
        
        SUMMARY:
        - Anomaly Score: {anomaly_score}
        - Flagged Rules: {len(flagged_rules)}
        - Red Flags: {len(red_flags)}
        
        FULL DATA:
        {json.dumps(summary, indent=2)}
        
        Respond with ONLY this JSON:
        {{
            "execution_strategy": "<skip_all|behavioral_only|standard_flow|full_analysis|critical_priority>",
            "priority_hint": "<low|medium|high|critical>",
            "reasoning": "<one sentence explaining your decision>",
            "confidence": <0.0 to 1.0>,
            "skip_agents": ["<agent names to skip, if any>"]
        }}
        """
```

---

### Phase 2: Add Supervisor Decision Model ✅

**File:** `shared_models/agents.py`

```python
class ExecutionStrategy(str, Enum):
    SKIP_ALL = "skip_all"
    BEHAVIORAL_ONLY = "behavioral_only"
    STANDARD_FLOW = "standard_flow"
    FULL_ANALYSIS = "full_analysis"
    CRITICAL_PRIORITY = "critical_priority"

class SupervisorDecision(BaseAgentOutput):
    """Output from Supervisor Agent."""
    agent_name: str = "supervisor"
    
    execution_strategy: ExecutionStrategy = Field(
        ...,
        description="Recommended execution strategy"
    )
    priority_hint: IncidentPriority = Field(
        ...,
        description="Suggested priority level"
    )
    reasoning: str = Field(
        ...,
        description="Explanation for decision"
    )
    confidence: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Confidence in strategy decision"
    )
    skip_agents: List[str] = Field(
        default_factory=list,
        description="Agent names to skip (if any)"
    )
```

---

### Phase 3: Enhance Orchestrator ✅

**File:** `agents/orchestrator.py`

```python
class AgentOrchestrator:
    def __init__(
        self, 
        client: OllamaClient | None = None,
        use_cache: bool = True,
        use_supervisor: bool = True,  # NEW
    ):
        # Existing initialization...
        self.supervisor = SupervisorAgent(client) if use_supervisor else None
    
    async def analyze(
        self,
        summary: ChunkSummary,
        skip_if_not_suspicious: bool = True,
    ) -> AgentOutput:
        """Run supervised or standard analysis."""
        
        chunk_id = summary.chunk_id
        summary_dict = summary.model_dump(mode="json")
        
        # NEW: Supervisor decides strategy
        if self.supervisor:
            logger.info(f"Supervisor analyzing | chunk_id={chunk_id}")
            supervisor_decision = await self.supervisor.analyze(summary_dict, chunk_id)
            strategy = supervisor_decision.execution_strategy
            logger.info(
                f"Supervisor decision | chunk_id={chunk_id}, "
                f"strategy={strategy}, reasoning={supervisor_decision.reasoning}"
            )
        else:
            strategy = ExecutionStrategy.FULL_ANALYSIS
        
        # Execute based on strategy
        if strategy == ExecutionStrategy.SKIP_ALL:
            return self._create_minimal_output(chunk_id, "clearly_benign")
        
        elif strategy == ExecutionStrategy.BEHAVIORAL_ONLY:
            return await self._run_behavioral_only(summary_dict, chunk_id)
        
        elif strategy == ExecutionStrategy.STANDARD_FLOW:
            return await self._run_standard_flow(summary_dict, chunk_id)
        
        elif strategy in (ExecutionStrategy.FULL_ANALYSIS, ExecutionStrategy.CRITICAL_PRIORITY):
            return await self._run_full_analysis(
                summary_dict, 
                chunk_id,
                is_critical=(strategy == ExecutionStrategy.CRITICAL_PRIORITY)
            )
    
    def _create_minimal_output(self, chunk_id: UUID, reason: str) -> AgentOutput:
        """Create minimal output for skipped analysis."""
        output = AgentOutput(chunk_id=chunk_id)
        # Create a simple behavioral result marking as not suspicious
        output.behavioral = BehavioralInterpretation(
            chunk_id=chunk_id,
            interpretation=f"Analysis skipped: {reason}",
            is_suspicious=False,
            confidence=0.95,
            reasoning="Supervisor determined detailed analysis not needed"
        )
        output.requires_human_review = False
        output.compute_overall_confidence()
        return output
    
    async def _run_behavioral_only(self, summary_dict: dict, chunk_id: UUID) -> AgentOutput:
        """Run only behavioral agent."""
        state: AgentGraphState = {
            "chunk_id": chunk_id,
            "summary_dict": summary_dict,
            "output": AgentOutput(chunk_id=chunk_id),
            "errors": [],
            "total_time_ms": 0,
            "skip_if_not_suspicious": False,
            "stop_downstream": True,  # Force stop after behavioral
            "stop_reason": "supervisor_behavioral_only",
        }
        state = await self._behavioral_node(state)
        return await self._finalize_node(state)
    
    async def _run_standard_flow(self, summary_dict: dict, chunk_id: UUID) -> AgentOutput:
        """Run behavioral → intent → triage (skip MITRE)."""
        state: AgentGraphState = {
            "chunk_id": chunk_id,
            "summary_dict": summary_dict,
            "output": AgentOutput(chunk_id=chunk_id),
            "errors": [],
            "total_time_ms": 0,
            "skip_if_not_suspicious": False,
        }
        state = await self._behavioral_node(state)
        if state.get("stop_downstream"):
            return await self._finalize_node(state)
        
        state = await self._intent_node(state)
        # Skip MITRE for speed
        state = await self._triage_node(state)
        return await self._finalize_node(state)
    
    async def _run_full_analysis(
        self, 
        summary_dict: dict, 
        chunk_id: UUID,
        is_critical: bool = False
    ) -> AgentOutput:
        """Run all agents (existing behavior)."""
        # Use existing _run_graph logic
        state: AgentGraphState = {
            "chunk_id": chunk_id,
            "summary_dict": summary_dict,
            "output": AgentOutput(chunk_id=chunk_id),
            "errors": [],
            "total_time_ms": 0,
            "skip_if_not_suspicious": False,
        }
        final_state = await self._run_graph(state)
        
        if is_critical:
            # Mark for immediate escalation
            final_state["output"].requires_human_review = True
            logger.warning(
                f"CRITICAL PRIORITY incident | chunk_id={chunk_id}, "
                f"immediate review required"
            )
        
        return final_state["output"]
```

---

## Configuration

**File:** `.env` or `core/config.py`

```python
# Supervisor Agent Settings
ENABLE_SUPERVISOR_AGENT=true
SUPERVISOR_MIN_CONFIDENCE=0.7  # Minimum confidence to trust supervisor decision
```

---

## Benefits

### **1. Performance Optimization**
```
Without Supervisor:
- 100 chunks × 4 agents = 400 LLM calls

With Supervisor:
- 100 chunks × 1 supervisor = 100 calls
- 30 skip_all = 0 additional calls (saved 120)
- 20 behavioral_only = 20 calls (saved 60)
- 30 standard_flow = 90 calls (saved 30)
- 20 full_analysis = 80 calls (saved 0)
Total: 290 LLM calls (27.5% reduction)
```

### **2. Better Resource Allocation**
- Critical incidents get full analysis immediately
- Benign traffic gets minimal processing
- Moderate cases get balanced analysis

### **3. Improved Accuracy**
- Supervisor provides high-level context
- Can identify attack campaigns across chunks
- Adaptive to threat landscape

### **4. Cost Savings**
- Fewer LLM API calls
- Faster processing times
- Lower compute costs

---

## Monitoring & Metrics

### Track Supervisor Decisions:
```python
supervisor_stats = {
    "total_decisions": 1000,
    "skip_all": 300,
    "behavioral_only": 200,
    "standard_flow": 300,
    "full_analysis": 180,
    "critical_priority": 20,
    "avg_confidence": 0.87,
    "overrides": 5,  # Times analyst disagreed with decision
}
```

### Decision Quality Metrics:
- False negative rate (missed threats due to skip_all)
- False positive rate (full_analysis on benign)
- Average time savings
- Analyst agreement rate

---

## Rollout Strategy

### Phase 1: Shadow Mode (Week 1-2)
- Supervisor runs but doesn't affect execution
- Log decisions for analysis
- Compare supervisor decisions vs full analysis results

### Phase 2: Partial Deployment (Week 3-4)
- Enable for low-risk scenarios (skip_all, behavioral_only)
- Keep full_analysis for everything else
- Monitor for false negatives

### Phase 3: Full Deployment (Week 5+)
- Enable all strategies
- Monitor and tune thresholds
- Collect feedback from analysts

---

## Fallback & Override

### Fallback to Full Analysis:
```python
if supervisor_decision.confidence < MIN_CONFIDENCE:
    logger.warning(f"Supervisor low confidence, falling back to full analysis")
    strategy = ExecutionStrategy.FULL_ANALYSIS
```

### Analyst Override:
- Add UI button: "Force Full Analysis"
- Store override events for retraining
- Update supervisor based on feedback

---

## Summary

### Recommended Approach: **Option 3 - Meta-Supervisor**

**Benefits:**
- ✅ 25-30% reduction in LLM calls
- ✅ Faster processing for obvious cases
- ✅ Deep analysis for complex threats
- ✅ Adaptive to threat landscape
- ✅ Clear separation of concerns

**Implementation:**
1. Create `SupervisorAgent` class
2. Add `SupervisorDecision` model
3. Enhance `AgentOrchestrator` with strategy execution
4. Add configuration options
5. Deploy in shadow mode first

**Next Steps:**
1. Want me to implement the supervisor agent?
2. Want me to create the enhanced orchestrator?
3. Want both with full integration?
