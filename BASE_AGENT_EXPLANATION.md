# BaseAgent - What It Does

## Overview

**BaseAgent** is an abstract base class that provides the **core infrastructure** for all AI agents in the CyberDef system. It handles:
1. Communication with Ollama (LLM)
2. Prompt construction and formatting
3. JSON parsing and validation
4. Error handling and retries
5. Performance tracking

Think of it as the **engine** that all specific agents (Behavioral, Intent, MITRE, Triage) inherit and build upon.

---

## Architecture

```
BaseAgent (abstract base class)
    ├── OllamaClient (handles LLM communication)
    └── Common functionality
         ├── analyze() - main entry point
         ├── _parse_json_response() - robust JSON parsing
         └── get_stats() - performance metrics

Specific Agents (inherit from BaseAgent):
    ├── BehavioralInterpretationAgent
    ├── ThreatIntentAgent
    ├── MitreReasoningAgent
    └── TriageNarrativeAgent
```

---

## Key Components

### 1. **OllamaClient** - LLM Communication

**What it does:**
- Manages HTTP connection to local Ollama instance
- Sends prompts to the LLM
- Enforces low temperature (≤ 0.2) for determinism
- Handles retries on failure
- Formats requests with JSON output mode

**Key methods:**
```python
async def generate(prompt, system_prompt, temperature) -> str:
    """Send prompt to Ollama, get JSON response"""
    
async def health_check() -> bool:
    """Check if Ollama is available"""
```

**Example:**
```python
client = OllamaClient()
response = await client.generate(
    prompt="Analyze this behavior...",
    system_prompt="You are a cybersecurity analyst...",
    temperature=0.1
)
# Returns: '{"is_suspicious": true, "confidence": 0.85, ...}'
```

---

### 2. **BaseAgent.analyze()** - Main Workflow

**This is the core method that every agent uses:**

```python
async def analyze(summary: dict, chunk_id: UUID) -> T:
    """
    Main analysis workflow:
    1. Build prompts (system + user)
    2. Call Ollama LLM
    3. Parse JSON response
    4. Validate against Pydantic schema
    5. Add metadata
    6. Return typed result
    """
```

**Step-by-step flow:**

```
1. Agent receives behavioral summary
   ↓
2. build_prompt() - creates user prompt (agent-specific)
   ↓
3. Combines BASE_SYSTEM_PROMPT + agent_system_prompt + schema
   ↓
4. OllamaClient.generate() - sends to LLM
   ↓
5. LLM returns JSON string
   ↓
6. _parse_json_response() - robust JSON parsing
   ↓
7. Add metadata (chunk_id, timestamps, model info)
   ↓
8. Pydantic validation (output_schema.model_validate())
   ↓
9. Return typed result (BehavioralInterpretation, TriageResult, etc.)
```

**Example:**
```python
# Behavioral Agent calls analyze()
result = await behavioral_agent.analyze(chunk_summary, chunk_id)

# BaseAgent does all the work:
# 1. Builds prompt: "A security finding has been raised..."
# 2. Adds system prompt: "You are a TP/FP validator..."
# 3. Calls Ollama: POST /api/generate
# 4. Gets response: '{"is_suspicious": true, ...}'
# 5. Parses JSON: dict
# 6. Validates: BehavioralInterpretation.model_validate()
# 7. Returns: BehavioralInterpretation object
```

---

### 3. **_parse_json_response()** - Robust JSON Parsing

**Problem it solves:**
LLMs don't always return perfect JSON. They might:
- Wrap JSON in markdown code fences: ` ```json {...} ``` `
- Add explanatory text before/after the JSON
- Use Python-style `True`/`False`/`None` instead of JSON `true`/`false`/`null`
- Add trailing commas: `{"key": "value",}`
- Truncate responses mid-JSON

**Solution - 5-stage parsing:**

```python
def _parse_json_response(response: str) -> dict:
    # Stage 1: Strip markdown fences
    ```json {...} ```  →  {...}
    
    # Stage 2: Try direct parse
    try: json.loads(text)
    
    # Stage 3: Brace-depth scanning (finds JSON even with text around it)
    "Here is the result: {...} Thank you"  →  {...}
    
    # Stage 4: Fix common errors
    - Remove trailing commas: {"key": "value",}  →  {"key": "value"}
    - Fix Python bools: True/False/None  →  true/false/null
    
    # Stage 5: Give up, log error
```

**Example:**

```python
# LLM returns this mess:
response = '''
Here is my analysis in JSON format:
```json
{
    "is_suspicious": True,
    "confidence": 0.85,
    "reasoning": "SQL injection detected",
}
```
I hope this helps!
'''

# _parse_json_response() extracts and fixes:
result = {
    "is_suspicious": true,  # Fixed True → true
    "confidence": 0.85,
    "reasoning": "SQL injection detected"  # Removed trailing comma
}
```

---

### 4. **BASE_SYSTEM_PROMPT** - Common Instructions

**Every agent starts with these rules:**

```
You are a cybersecurity intelligence agent.

CRITICAL RULES:
1. Input is structured behavioral summaries only - NOT raw logs
2. Do NOT analyze raw logs or invent data
3. Do NOT hallucinate or make up facts
4. Return ONLY valid JSON - no markdown, no explanation
5. Always include confidence scores (0.0 to 1.0)
6. Be conservative - low confidence is acceptable
7. Your analysis must be based ONLY on the provided data
```

**Then each agent adds its own specific instructions** in `agent_system_prompt`.

---

## How Specific Agents Use BaseAgent

### Example: Behavioral Agent

```python
class BehavioralInterpretationAgent(BaseAgent[BehavioralInterpretation]):
    name = "behavioral_interpretation"
    output_schema = BehavioralInterpretation  # Pydantic model
    
    # Agent-specific system instructions
    agent_system_prompt = """
    You are a TP/FP validator.
    Your task is to confirm or deny whether the rule's evidence 
    represents a real attack...
    """
    
    # Agent-specific prompt builder
    def build_prompt(self, summary: dict) -> str:
        return f"""
        A security finding has been raised. 
        Validate whether this is a True Positive or False Positive.
        
        FLAGGED CHUNK DATA:
        {json.dumps(summary, indent=2)}
        
        Respond with ONLY valid JSON:
        {{"is_suspicious": true/false, "confidence": 0.85, ...}}
        """
    
    def get_output_schema_description(self) -> str:
        return '{"is_suspicious": "boolean", "confidence": "float", ...}'
```

**When orchestrator calls:**
```python
result = await behavioral_agent.analyze(chunk_summary, chunk_id)
```

**BaseAgent.analyze() does:**
1. ✅ Combines BASE_SYSTEM_PROMPT + agent_system_prompt
2. ✅ Calls build_prompt() to create user prompt
3. ✅ Sends to Ollama via OllamaClient
4. ✅ Parses JSON response (handles markdown, errors, etc.)
5. ✅ Validates with BehavioralInterpretation schema
6. ✅ Returns typed BehavioralInterpretation object

---

## Key Features

### ✅ **Low Temperature Enforcement**
```python
if temp > 0.2:
    logger.warning(f"Temperature clamped to 0.2 for determinism")
    temp = 0.2
```
**Why:** Ensures consistent, deterministic outputs (not creative writing)

### ✅ **Automatic Retries**
```python
for attempt in range(1, max_retries + 1):
    try:
        response = await self._client.post(...)
        return response
    except httpx.HTTPError:
        # Retry on network errors
```
**Why:** Handles transient Ollama failures

### ✅ **Structured Logging**
```python
logger.info(f"--- [AGENT: {self.name}] SYSTEM PROMPT ---\n{system_prompt}")
logger.info(f"--- [AGENT: {self.name}] USER PROMPT ---\n{user_prompt}")
logger.info(f"--- [AGENT: {self.name}] RAW LLM RESPONSE ---\n{response}")
```
**Why:** Full audit trail for debugging and prompt engineering

### ✅ **Performance Tracking**
```python
self.invocations = 0  # How many times called
self.errors = 0       # How many failed
processing_time_ms    # How long each call took
```
**Why:** Monitor agent performance and identify bottlenecks

### ✅ **Type Safety**
```python
class BaseAgent(ABC, Generic[T]):
    output_schema: type[T]
    
    async def analyze(...) -> T:
        result = self.output_schema.model_validate(parsed)
        return result  # Type-safe return
```
**Why:** Compile-time type checking, runtime validation

---

## Error Handling

### **Validation Errors**
```python
except ValidationError as e:
    logger.error(f"Agent output validation failed | error={e}")
    raise AgentError(
        f"Output validation failed: {str(e)}",
        agent_name=self.name,
        chunk_id=str(chunk_id),
    )
```
**When:** LLM returns JSON that doesn't match the Pydantic schema

### **Ollama API Errors**
```python
except httpx.HTTPError as e:
    logger.error(f"Ollama API error | error={e}")
    raise AgentError(
        f"Ollama API error: {str(e)}",
        details={"host": self.host, "model": self.model}
    )
```
**When:** Ollama is down, network issue, or model not loaded

### **JSON Parse Errors**
```python
logger.error(
    f"JSON parse failed after all fallbacks | "
    f"raw_response_preview={preview!r}"
)
raise AgentError("Failed to parse JSON from agent response")
```
**When:** LLM returns completely invalid JSON even after all fixes

---

## Summary

### **BaseAgent provides:**

| Feature | Purpose |
|---------|---------|
| **OllamaClient** | Handles all LLM communication |
| **analyze()** | Main workflow: prompt → LLM → parse → validate |
| **_parse_json_response()** | Robust JSON parsing with fallbacks |
| **BASE_SYSTEM_PROMPT** | Common instructions for all agents |
| **Error handling** | Retries, logging, typed exceptions |
| **Performance tracking** | Invocations, errors, timing |
| **Type safety** | Generic types, Pydantic validation |

### **Specific agents provide:**

| Agent-Specific | Example |
|----------------|---------|
| `name` | "behavioral_interpretation" |
| `agent_system_prompt` | "You are a TP/FP validator..." |
| `output_schema` | BehavioralInterpretation (Pydantic model) |
| `build_prompt()` | Formats input data into user prompt |
| `get_output_schema_description()` | Describes expected JSON format |

---

## Analogy

Think of **BaseAgent** as a **car engine**:
- It handles the mechanics (communication, parsing, validation)
- Every car (agent) uses the same engine
- But each car has different controls (prompts) and purpose (TP/FP, priority, MITRE)

**Without BaseAgent:** Each agent would need to implement Ollama communication, JSON parsing, error handling, etc. (code duplication!)

**With BaseAgent:** Agents focus only on their specific logic (prompts and output format). Everything else is handled by the base class.
