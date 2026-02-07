# Ensuring Complete Investigation Execution

## Problem Statement

In multi-tier agent investigations, it's critical to ensure **all steps are executed correctly** and **no key actions are missed**. The original investigation of the impossible travel alert demonstrated this failure:

### What Went Wrong
- ✅ Extracted IOCs
- ✅ Enriched with threat intelligence
- ✅ Manually analyzed Splunk data
- ❌ **FAILED to create Finding objects from Splunk analysis**
- ❌ **Only passed threat intel findings to Reporter**
- ❌ **Reporter made wrong conclusion due to incomplete data**

**Result**: Report showed "SUSPICIOUS" instead of "FALSE POSITIVE" because it lacked critical context about shared infrastructure.

---

## Multi-Layered Solution

### **Layer 1: Investigation Protocol with Validation Gates**

**File**: `agents/investigation_protocol.py`

The `InvestigationProtocol` class enforces complete execution through:

#### **1. Explicit Step Definitions**
```python
InvestigationStep(
    id="tier2_analyze_splunk_results",
    name="Analyze Splunk Results & Create Findings",
    tier=2,
    agent="SplunkInvestigator",
    description="Convert Splunk query results into Finding objects",
    depends_on=["tier2_execute_splunk_queries"],
    validates=lambda ctx: (
        ctx.get("splunk_findings") is not None and
        len(ctx.get("splunk_findings", [])) > 0
    ),
    critical=True  # Investigation cannot proceed if this fails
)
```

#### **2. Dependency Management**
Each step explicitly declares what must complete before it can start:
- Tier 1 parsing depends on Tier 0 acquisition
- Tier 2 Splunk analysis depends on query execution
- Tier 3 reporting depends on ALL Tier 2 investigations

#### **3. Validation Gates**
Every step has a `validates` function that checks the context:
- Did IOC extraction actually find IOCs?
- Are Splunk findings stored in the context?
- Does the final report have a risk assessment?

#### **4. Critical vs. Optional Steps**
- **Critical steps** (marked `critical=True`): Investigation **stops** if validation fails
- **Optional steps**: Logged as warnings but don't block progression
- **Conditional steps**: Only executed if conditions are met (e.g., device fingerprint for ATO alerts)

#### **5. State Tracking**
Each step tracks:
- `PENDING` → `IN_PROGRESS` → `COMPLETED` or `FAILED`
- Timestamps for start/completion
- Error messages if validation fails

---

### **Layer 2: Protocol-Enforced Investigation Executor**

**File**: `investigate_with_protocol.py`

This demonstrates the protocol in action:

```python
# Step 1: Mark step as started
protocol.mark_step_started("tier2_analyze_splunk_results")

# Step 2: Do the work (execute Splunk queries, create findings)
splunk_findings = []
for result in query_results:
    finding = orchestrator.create_splunk_finding(
        query=result["query"],
        description=result["description"],
        result=result["data"],
        ioc_value=result.get("ioc_value")
    )
    splunk_findings.append(finding)

# Step 3: Validate and complete
try:
    protocol.mark_step_completed("tier2_analyze_splunk_results", {
        "splunk_findings": splunk_findings
    })
except ValueError as e:
    # BLOCKED: Cannot proceed without Splunk findings
    print(f"CRITICAL FAILURE: {e}")
    sys.exit(1)
```

#### **What Happens on Validation Failure**

```
================================================================================
🔍 CRITICAL VALIDATION GATE
================================================================================

⚠️  The protocol REQUIRES creating Finding objects from Splunk results.

❌ VALIDATION FAILED: Step 'Analyze Splunk Results & Create Findings' validation failed
   Investigation BLOCKED - cannot proceed to reporting without Splunk findings!

CRITICAL STEP FAILED: Analyze Splunk Results & Create Findings
```

---

### **Layer 3: Visual Progress Tracking**

The protocol provides real-time status visualization:

```
📊 Investigation Status
┌───────────────────────────────────────────────────────────────┐
│ Investigation Progress: 7/10 steps completed (70%)            │
└───────────────────────────────────────────────────────────────┘

Investigation Steps
┏━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━┓
┃ Tier ┃ Step                                     ┃ Agent             ┃ Status     ┃
┡━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━┩
│ T0   │ Acquire Alert Signal *                   │ SignalAcquisit... │ ✅ completed│
│ T1   │ Parse Alert & Extract IOCs *             │ Orchestrator      │ ✅ completed│
│ T1   │ Prepare Splunk Investigation Queries *   │ Orchestrator      │ ✅ completed│
│ T2   │ Execute Splunk Queries via MCP *         │ Claude (MCP)      │ 🔄 in_prog...│
│ T2   │ Analyze Splunk Results & Create Findin...│ SplunkInvestig... │ ⏳ pending │
│ T2   │ Device Fingerprint Analysis (ATO alerts) │ SplunkInvestig... │ ⏳ pending │
│ T2   │ Enrich IOCs with Threat Intelligence     │ ThreatIntelEnr... │ ⏳ pending │
│ T3   │ Consolidate All Findings *               │ Reporter          │ ⏳ pending │
│ T3   │ Generate Investigation Report *          │ Reporter          │ ⏳ pending │
└──────┴──────────────────────────────────────────┴───────────────────┴────────────┘

* = Critical step (investigation cannot proceed if failed)
```

---

## Complete Investigation Steps Defined

| Tier | Step | Agent | Critical | Validation |
|------|------|-------|----------|------------|
| **T0** | Acquire Alert Signal | SignalAcquisitionAgent | ✅ | `alert_data` exists |
| **T1** | Parse Alert & Extract IOCs | Orchestrator | ✅ | `alert` and `iocs` exist, IOCs > 0 |
| **T1** | Prepare Splunk Queries | Orchestrator | ✅ | `splunk_queries` exist, count > 0 |
| **T2** | Execute Splunk Queries | Claude (MCP) | ✅ | `splunk_query_results` exists |
| **T2** | **Analyze Splunk Results → Findings** | SplunkInvestigator | ✅ | **`splunk_findings` exist, count > 0** |
| **T2** | Device Fingerprint (conditional) | SplunkInvestigator | ❌ | Required if ATO alert |
| **T2** | Threat Intel Enrichment | ThreatIntelEnricher | ❌ | `threat_intel_findings` exists |
| **T3** | Consolidate Findings | Reporter | ✅ | All findings merged |
| **T3** | Generate Report | Reporter | ✅ | `final_report` with risk assessment |

**Key Insight**: The bolded step ("Analyze Splunk Results → Findings") is where the original investigation failed. The protocol makes this **critical and validates it**.

---

## How This Prevents the Original Mistake

### **Before (No Protocol)**
```python
# Execute Splunk queries manually
splunk_results = mcp__splunk__run_splunk_query(...)

# Manually analyze in my head
print("IP has 16K events from multiple users, must be VPN")

# Pass only threat intel findings to Reporter
findings = threat_intel_findings  # Missing Splunk findings!

# Reporter makes wrong conclusion
reporter.print_report(alert, iocs, findings)
# Result: "SUSPICIOUS" due to missing context
```

### **After (With Protocol)**
```python
# Protocol enforces step completion
protocol.mark_step_started("tier2_analyze_splunk_results")

# Must create Finding objects
splunk_findings = []
for result in splunk_results:
    finding = Finding(
        source=FindingSource.SPLUNK,
        title="IP 4.158.108.65: Shared infrastructure detected",
        description="16,358 events from dozens of users indicates VPN gateway",
        risk_level=RiskLevel.INFO,  # Lowers overall risk
        confidence=0.95
    )
    splunk_findings.append(finding)

# Validation ensures findings were created
protocol.mark_step_completed("tier2_analyze_splunk_results", {
    "splunk_findings": splunk_findings
})
# ✅ If no findings → CRITICAL FAILURE, investigation stops

# Reporter gets complete picture
all_findings = splunk_findings + threat_intel_findings
reporter.print_report(alert, iocs, all_findings)
# Result: "BENIGN / FALSE POSITIVE" with full context
```

---

## Usage

### **Run with Protocol Enforcement**

```bash
# Investigate DataDog alert with protocol
python investigate_with_protocol.py \
    --datadog-id "AwAAAZw0OXNE_fLK0Q..."

# Investigate alert from file
python investigate_with_protocol.py \
    --file alerts/impossible_travel.json
```

### **Integration with Existing Code**

```python
from agents.investigation_protocol import InvestigationProtocol

protocol = InvestigationProtocol()

# Start investigation
protocol.mark_step_started("tier0_acquisition")
alert_data = acquire_alert()
protocol.mark_step_completed("tier0_acquisition", {"alert_data": alert_data})

# Continue through all steps...
# Protocol will block if any critical step fails validation

# Check completion
if protocol.is_complete():
    print("Investigation complete and validated!")
else:
    print("ERROR: Investigation incomplete!")
    protocol.print_status()
```

---

## Benefits

### **1. Prevents Incomplete Investigations**
- Every critical step must complete and validate
- Missing steps are immediately caught
- No "forgetting" to create Finding objects

### **2. Clear Dependencies**
- Each step knows what must complete before it runs
- Automatic dependency resolution
- No running steps out of order

### **3. Graceful Degradation**
- Non-critical steps can fail without blocking
- Conditional steps only run when needed
- Clear distinction between "must have" and "nice to have"

### **4. Audit Trail**
- Complete history of what executed when
- Failure reasons captured
- Easy to debug incomplete investigations

### **5. Visual Progress**
- Real-time status tracking
- Emoji indicators for quick scanning
- Rich formatted progress tables

---

## Future Enhancements

### **1. Automated Step Execution**
Currently Claude (the AI) must execute steps manually. Could automate:
- Automatic MCP query execution
- Automatic finding creation from results
- Full hands-off investigation

### **2. Task Tool Integration**
Integrate with Claude Code's TaskCreate/TaskUpdate:
```python
protocol.integrate_with_task_system()
# Creates tasks for each investigation step
# Updates task status as steps complete
```

### **3. Investigation Templates**
Define different protocols for different alert types:
- `ImpossibleTravelProtocol`
- `MalwareDetectionProtocol`
- `DataExfiltrationProtocol`

### **4. Quality Gates**
Add minimum quality thresholds:
- "Must have at least 3 Splunk findings"
- "Device fingerprint analysis must have 90%+ confidence"
- "At least 2 threat intel sources must respond"

### **5. Parallel Execution**
Allow independent steps to run concurrently:
- Threat intel and Splunk can run in parallel
- Multiple Splunk queries execute simultaneously

---

## Conclusion

The `InvestigationProtocol` ensures **complete, correct, and validated** investigation execution by:

1. ✅ **Explicit step definitions** with clear requirements
2. ✅ **Dependency management** ensuring correct sequencing
3. ✅ **Validation gates** catching missing work
4. ✅ **Critical vs. optional** step classification
5. ✅ **Visual progress tracking** for transparency

This architectural pattern prevents the exact mistake made in the original investigation: skipping the critical step of converting Splunk analysis into Finding objects, which led to an incomplete and incorrect report.

**The protocol makes incomplete investigations impossible.**
