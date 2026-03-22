# 🛡️ CyberDef — How the Threat Analysis Works

> A plain-English guide to understanding how CyberDef detects cyber threats in your network logs.

---

## 🔄 The Big Picture

When you upload a log file, CyberDef runs a **three-tier analysis pipeline**:

```
Log File  →  Parse & Normalize  →  Chunk  →  Tier 1   →  Tier 2   →  Tier 3   →  Report
(CSV)        (Understand each       (Group     (Rules)     (Patterns)  (AI)        (Results)
              log line)              by actor)
```

Think of it like airport security:
- **Tier 1** = Metal detector (fast, catches known weapons)
- **Tier 2** = Behavioral profiling (connects the dots across travelers)
- **Tier 3** = Expert interrogation (AI deep-dives into suspicious cases)

---

## 📑 Step 1: Parsing & Normalization

**What happens:** Each line of your log file is read and converted into a standard format.

**Example:** A raw log line like:
```
Mar 01 10:15:23 webserver apache: 192.168.1.50 - - "GET /admin/../../../etc/passwd HTTP/1.1" 403 287
```
Gets parsed into structured fields:
| Field | Value |
|-------|-------|
| Timestamp | 2026-03-01 10:15:23 |
| Source IP | 192.168.1.50 |
| Method | GET |
| URL | /admin/../../../etc/passwd |
| Status Code | 403 (Forbidden) |

---

## 📦 Step 2: Chunking — Grouping Events Into "Behavioral Stories"

This is where CyberDef gets smart. Instead of looking at each log line individually (which gives no context), it **groups related events into chunks** — like assembling puzzle pieces into a picture.

### How Chunks Are Created

The system groups events using **three strategies simultaneously** in a single pass:

#### Strategy 1: Group by Source IP (Who is doing this?)
All events from the same attacker IP are grouped together within a **15-minute window**.

```
IP 192.168.1.50 — 15 min window:
  ├── 10:00:01  GET /login          → 200
  ├── 10:00:03  POST /login         → 401 (failed login)
  ├── 10:00:04  POST /login         → 401 (failed again)
  ├── 10:00:05  POST /login         → 200 (success!)
  ├── 10:02:00  GET /admin/users    → 200
  └── 10:05:00  GET /admin/export   → 200
```
> 💡 **This chunk tells a story:** Someone brute-forced a password, got in, then went straight to admin pages. That's a classic attack sequence!

#### Strategy 2: Group by Destination Host (What's being targeted?)
All events hitting the same target server are grouped within a **30-minute window**.
> Useful for detecting: "Multiple different IPs all scanning the same server" (distributed attack).

#### Strategy 3: Group by User (Which account is acting?)
All events tied to the same username are grouped within a **2-hour window**.
> Useful for detecting: "One user account being used from multiple IPs" (compromised credentials).

### What's Inside Each Chunk?

Each chunk contains a rich **behavioral profile**:

| Metric | What it means |
|--------|---------------|
| **Total Events** | How many actions this actor performed |
| **Failure Rate** | % of requests that failed (high = probing/scanning) |
| **Events per Minute** | How fast they're going (high = automated tool) |
| **Unique Targets** | How many different pages/hosts they hit |
| **Temporal Pattern** | Steady? Bursty? Escalating? |
| **Action Distribution** | Mix of GETs, POSTs, DELETEs |
| **Port Categories** | SSH, HTTP, RDP, etc. |

---

## 🔍 Step 3: Filtering — Which Chunks Are Suspicious?

Not every chunk is interesting. Normal users generate chunks too. The system filters to find the suspicious ones based on:

| Filter | Threshold | Why |
|--------|-----------|-----|
| Minimum events | ≥ 10 | Ignore tiny, insignificant activity |
| Failure rate | ≥ 30% | Normal users rarely fail this much |
| Unique targets | ≥ 3 | Scanning hits many different targets |

**Example:** A chunk with 200 events, 75% failure rate, hitting 15 targets → 🚨 **Very suspicious!**

---

## ⚡ Tier 1: Deterministic Rules (Instant)

**Speed:** Processes 200,000 events in ~4 seconds.

The system runs **60 pre-built detection rules** against every single event. These are pattern-matching rules — like a dictionary of known attack signatures.

### What it detects (examples):
| Threat | What the rule looks for |
|--------|------------------------|
| SQL Injection | `' OR 1=1`, `UNION SELECT`, `DROP TABLE` in URLs |
| Path Traversal | `../../etc/passwd`, `..\\windows\\` patterns |
| Command Injection | `; cat /etc/shadow`, `| whoami` in parameters |
| XSS | `<script>alert()`, `javascript:` in inputs |
| Brute Force | Same IP, many failed logins in short time |
| Scanner Detection | Known scanner user-agents (Nikto, sqlmap, Nmap) |

**Result:** A list of threats with severity (Critical/High/Medium/Low) and confidence scores.

---

## 🔗 Tier 2: Cross-Batch Correlation (Connects the Dots)

**Speed:** Near-instant (works on aggregated data).

Tier 1 looks at individual events. Tier 2 looks at **patterns across the entire day** — connecting activity across multiple 15-minute batches.

### What it detects:
| Pattern | What it means |
|---------|---------------|
| **Kill Chain Progression** | Same attacker moved from reconnaissance → exploitation → data access |
| **Multi-Vector Attacker** | Same IP using multiple attack types (SQL injection + path traversal + XSS) |
| **Distributed Recon** | Multiple IPs scanning targets in a coordinated way |
| **Rate Acceleration** | An attacker is speeding up — escalating their attack |
| **Off-Hours Anomaly** | Suspicious activity outside normal business hours |
| **Data Exfiltration** | Large outbound data transfers to suspicious destinations |

---

## 🤖 Tier 3: AI Agent Analysis (Deep Investigation)

**Speed:** ~12 seconds per chunk, 5 chunks in parallel → ~4 minutes total for the top 20 chunks.

This is where the real intelligence happens. Only the **most suspicious chunks** get sent to AI — the system picks the top 20 highest-risk chunks using a **risk scoring** system.

### Risk Scoring (How chunks are prioritized):
| Factor | Score Contribution |
|--------|--------------------|
| High event rate (automation) | Up to 2.0 points |
| High failure rate (probing) | Up to 3.0 points |
| Many unique targets (scanning) | Up to 2.0 points |
| Escalating pattern | +2.0 points |
| Bursty pattern | +1.0 points |
| High volume | Up to 1.0 points |

> 💡 IPs already fully explained by Tier 1 get their score **halved** (deprioritized, not skipped) — if there's room, they still get AI review.

### The Four AI Agents

Each suspicious chunk is analyzed by **four specialized AI agents** in sequence:

```
Chunk → 🧠 Agent 1 → 🎯 Agent 2 → 🗺️ Agent 3 → 📋 Agent 4
        Behavioral    Threat       MITRE         Triage &
        Interpretation Intent      Mapping       Narrative
```

#### 🧠 Agent 1: Behavioral Interpretation
> "Is this behavior suspicious?"

Reads the chunk's behavioral profile and interprets what the activity means.
- **Output:** Suspicious/Normal + Confidence + Reasoning

#### 🎯 Agent 2: Threat Intent
> "What is the attacker trying to achieve?"

Infers the attacker's goal and maps it to the Cyber Kill Chain.
- **Output:** Suspected intent + Kill chain stage (Reconnaissance → Exploitation → Exfiltration)

#### 🗺️ Agent 3: MITRE ATT&CK Mapping
> "Which known attack technique is this?"

Maps the behavior to the industry-standard MITRE ATT&CK framework.
- **Output:** Technique ID (e.g., T1110 = Brute Force) + Justification

#### 📋 Agent 4: Triage & Narrative
> "How urgent is this and what should we do?"

Assigns a priority level and writes a human-readable narrative.
- **Output:** Priority (Critical/High/Medium/Low) + Recommended action + Executive summary

---

## 📊 What You Get at the End

After all three tiers complete, CyberDef produces:

1. **Incidents** — Actionable alerts in the Incidents view, each with:
   - Title, severity, source IPs, evidence
   - Which tier (Rule / Correlation / AI) created it

2. **Human-Readable Report** — A detailed Markdown file saved to the `reports/` folder containing:
   - Executive summary with severity counts
   - Per-threat breakdown with evidence and recommendations
   - MITRE ATT&CK mapping table
   - Overall recommendations

3. **Dashboard Metrics** — Visual overview of threat landscape

4. **Day-Level Rollups** — Long-horizon patterns detected across all files analyzed today

---

## 🕐 Performance at Scale

| Stage | 1,000 events | 200,000 events |
|-------|-------------|----------------|
| Parse & Normalize | ~0.1s | ~4s |
| Chunking | ~0.01s | ~2s |
| Tier 1 (60 Rules) | ~0.2s | ~4s |
| Tier 2 (Correlation) | ~0.01s | ~0.1s |
| Tier 3 (AI, top 20 chunks) | ~2 min | ~3-4 min |
| **Total** | **~2 min** | **~3.5-4 min** |

---

*Document generated for CyberDef v1.0 — AI-Powered Network Threat Analysis Platform*
