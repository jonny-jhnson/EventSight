# EventSight

A Claude-powered Windows Event Log analyzer that learns from security relevant feedback. EventSight leverages Claude and its inherent security knowledge to identify suspicious activity, with a feedback loop that makes it smarter over time for your specific environment.

EventSight uses **vector-based semantic search** for RAG (Retrieval-Augmented Generation) combined with In-Context Learning to drive finding confidence. Analyst feedback is stored locally, embedded for semantic similarity search, and injected into prompts to guide Claude's analysis.

## Features

- **Claude-Powered Analysis**: Leverages Claude's security knowledge to identify threats like process injection, credential theft, lateral movement, and more
- **Continuous Monitoring**: Watch EVTX files or live Windows channels (Security, Application, Sysmon) for new events in real-time
- **Dual-Path Learning Retrieval**: O(1) Event ID cache lookup with vector search fallback for optimal performance
- **Semantic Search RAG**: Uses sentence-transformers for semantic similarity - "credential dumping" matches "LSASS access" even without shared keywords
- **Event Persistence**: All parsed events stored in SQLite for later querying and cross-analysis correlation
- **Correlation Rules**: Define custom event correlation rules to detect attack patterns across related events
- **Multi-File Analysis**: Analyze multiple EVTX files together for cross-file correlation
- **Smart Filtering**: Claude-powered filtering identifies security-relevant Event IDs before analysis
- **HTML Reports**: Generate professional HTML reports with chronological timelines
- **Token Tracking**: Monitor API token usage at each analysis step

## Installation

### Prerequisites

- Windows OS (Required - uses wevtutil.exe for EVTX parsing)
- Python 3.10+
- [uv](https://docs.astral.sh/uv/) package manager
- Anthropic API key
- **Microsoft Visual C++ Redistributable** (Required for PyTorch/ML features)
  - Download: https://aka.ms/vs/17/release/vc_redist.x64.exe
  - This is required for the semantic search functionality (sentence-transformers/PyTorch)

### Setup with uv 

```powershell
# Install uv if you don't have it
pip install uv

# Navigate to project directory
cd C:\path\to\EventSight

# Create virtual environment and install dependencies
uv venv
uv pip install -e .

# Set your API key
$env:ANTHROPIC_API_KEY="your-key-here"

# Run EventSight
uv run eventsight
```

## Usage

### Interactive CLI Mode

```
uv run eventsight
```

This launches the interactive terminal:

```
  EVENTSIGHT SECURITY ANALYSIS

eventsight> help

Available Commands:
  evaluate <file> [--all]    Analyze an EVTX file for suspicious activity
  feedback <id> <verdict>    Provide feedback on a finding
  learnings                  List all stored learnings
  correlation                Manage correlation rules
  report                     Generate HTML report
  export                     Export analysis as markdown
  search <query>             Search past learnings
  stats                      Show learning statistics
  clear-events [--all]       Clear stored events from database
  clear                      Clear screen
  help                       Show this help
  exit                       Exit EventSight
```

### Analyzing EVTX Files

```cmd
# Interactive mode - will prompt for filtering options
eventsight> evaluate C:\Windows\System32\winevt\Logs\Security.evtx --all

# Filter options presented:
# 1) Smart filter (AI selects relevant Event IDs)
# 2) Specific Event IDs (e.g., 4624,4688,4689)
# 3) Load from CSV filter file
# 4) No filter (analyze all events)
```

### Multi-File Analysis

Analyze multiple EVTX files together for cross-file correlation:

```cmd
eventsight> evaluate Security.evtx Sysmon.evtx PowerShell.evtx --all
```

Note: Multi-file analysis requires explicit filtering (`--event-ids` or filter file) to manage API usage.

### Direct Commands

```cmd
# Analyze a file directly
uv run eventsight evaluate Security.evtx

# Analyze with specific Event IDs
uv run eventsight evaluate Security.evtx --all --event-ids "4624,4688,4689"

# Analyze with a filter file
uv run eventsight evaluate Security.evtx --all --filter-file my-filters.csv

# Disable all filtering
uv run eventsight evaluate Security.evtx --all --no-filter
```

### Continuous Analysis Mode

Monitor EVTX files or live Windows event channels for new events in real-time:

```cmd
# Monitor a live Windows channel (no admin required for most channels)
uv run eventsight evaluate Security --continuous --filter-file events.csv
uv run eventsight evaluate Application --continuous --event-ids 1000,1001

# Monitor an EVTX file
uv run eventsight evaluate Security.evtx --continuous --filter-file events.csv

# With custom check interval (every 15 seconds)
uv run eventsight evaluate Security --continuous --filter-file events.csv --interval 15

# With event IDs instead of filter file
uv run eventsight evaluate Security --continuous --event-ids 4624,4688,5145

# With custom batch size
uv run eventsight evaluate Security.evtx --continuous --filter-file events.csv --batch-size 50
```

**Input Types:**
- **Channel names**: `Security`, `Application`, `Microsoft-Windows-Sysmon/Operational` - monitors live Windows event channels
- **EVTX files**: `Security.evtx`, `C:\Logs\exported.evtx` - monitors exported log files

**How Continuous Mode Works:**

1. **Start from now**: Skips historical events, only analyzes events occurring after analysis starts
2. **Monitor loop**: Checks for new events at the specified interval (default: 60s)
3. **Incremental analysis**: Only new events (by timestamp) are analyzed
4. **Streaming output**: Findings are printed immediately as detected
5. **Live HTML report**: Auto-generates `eventsight_report.html` with 30-second auto-refresh
6. **Graceful shutdown**: Press `Ctrl+C` to stop and see a summary

**Live HTML Report:**

Continuous mode automatically generates a live-updating HTML report at `eventsight_report.html` in your current directory:
- **Auto-refresh**: Page refreshes every 30 seconds to show new findings
- **Live badge**: Pulsing green "LIVE" indicator shows monitoring is active
- **Statistics dashboard**: Events analyzed, total findings, iterations, severity breakdown
- **Finding details**: Severity, confidence, MITRE ATT&CK technique, recommendations
- **Dark theme**: Professional navy gradient design

Open the report in your browser while monitoring to see findings appear in real-time.

**Output Format:**
```
[10:30:00] Continuous analysis started
           File: Security
           Filter: 34 Event IDs
           Interval: 60s
           Learnings loaded: 20
           Report: C:\path\to\eventsight_report.html
           Mode: Watching for new events only (skipping historical)

[10:30:35] Analyzing 12 new events...
  [HIGH] Suspicious PowerShell Execution (T1059.001) - 85%
         User: DOMAIN\admin, Process: powershell.exe
  [MEDIUM] Network Logon from Unusual Source (T1078) - 72%
         User: DOMAIN\svc_account, Source: 10.0.0.50

[10:30:35] Analyzing 12 new events...
           No findings above threshold

[10:31:05] No new events, waiting...

^C
[10:31:20] Stopped
           Total: 12 events analyzed, 2 findings, 80.0s runtime
```

**Performance Optimizations:**
- Filters by Event ID during parsing (not after) - skips non-matching events entirely
- Pre-loads learnings and correlation rules once at startup
- Adaptive rate limiting: smaller batches get shorter delays
- Streams findings immediately instead of accumulating

**Requirements:**
- Single file/channel only (no multi-file in continuous mode)
- Must specify `--filter-file` or `--event-ids` (required for efficiency)

### Filter Files

Create a CSV file to define which Event IDs to analyze:

```csv
EventType,EventCode,Reason
Security,4624,Logon events for lateral movement detection
Security,4688,Process creation for execution tracking
Sysmon,1,Process creation with command line
Sysmon,10,Process access for injection detection
```

**Provider-aware filtering**: When you specify a provider/channel in the EventType column, EventSight will only match events from that specific source. This is useful when the same Event ID exists in multiple logs.

Supported provider formats:
- **Short aliases**: `Sysmon`, `Security`, `PowerShell`, `Defender`, `AppLocker`, etc.
- **Provider names**: `Microsoft-Windows-Sysmon`, `Microsoft-Windows-Security-Auditing`
- **Full channel names**: `Microsoft-Windows-Sysmon/Operational`

If you omit the EventType column or leave it blank, the Event ID will match from any provider.

## Correlation Rules

Define rules to correlate related events and detect attack patterns:

```cmd
eventsight> correlation add
```

Example: Correlate network logons (4624) with subsequent process creation (4688):

- **Source Event ID**: 4624 (Logon)
- **Source Condition**: LogonType = 3 (Network)
- **Target Event ID**: 4688 (Process Creation)
- **Source Field**: TargetLogonId
- **Target Field**: SubjectLogonId
- **Security Context**: Network logon followed by process execution may indicate lateral movement

Manage rules:
```cmd
eventsight> correlation list    # View all rules
eventsight> correlation delete <rule-id>
```

## Reports

### Console Output

Findings are displayed with:
- Severity badges (Critical, High, Medium - Low/Info hidden by default)
- MITRE ATT&CK technique and tactic mapping
- Security context (process, user, IPs, etc.)
- Matched correlation rules
- Recommendations

### Chronological Summary

Analysis includes a timeline of activity:
```
Detected 2 critical, 1 high severity finding(s).

Timeline of Activity:
[14:23:45] [C] Suspicious Process Injection (T1055) [Matched: Network Logon to Execution]
    → User: CORP\admin | Process: rundll32.exe (PID 4532) | Source: WORKSTATION1 (192.168.1.50)
[14:23:52] [H] LSASS Memory Access (T1003.001)
    → User: NT AUTHORITY\SYSTEM | Process: mimikatz.exe (PID 4588)
[14:24:01] [M] Scheduled Task Creation (T1053.005)
    → User: CORP\admin | Process: schtasks.exe (PID 4601)
```

### HTML Reports

Generate a professional HTML report:
```cmd
eventsight> report
```

Opens `report.html` in your browser with:
- Summary statistics and severity breakdown
- Chronological activity timeline
- Detailed findings with security context
- Matched correlation rules

### Markdown Export

```cmd
eventsight> export findings.md
```

## Feedback & Learning

Provide feedback on findings to improve future analyses:

```cmd
eventsight> feedback <finding-id> <verdict> "<explanation>"
```

Verdicts:

| Verdict | When to Use | Example |
|---------|-------------|---------|
| `false_positive` | AI flagged something benign as suspicious | "This is MsSense doing normal monitoring" |
| `true_positive` | AI correctly identified malicious activity | "Confirmed Mimikatz credential dump" |
| `benign` | Activity is suspicious-looking but approved | "This is our red team's authorized testing tool" |
| `needs_context` | Can't determine without more information | "Need to check with user if they ran this" |

Example:
```cmd
eventsight> feedback finding_20241209_001 false_positive "This is MsSense doing normal monitoring"
```

The system extracts reusable insights from your feedback and applies them to future analyses.

### Managing Learnings

View all stored learnings:
```cmd
eventsight> learnings
```

Edit a learning's insight text:
```cmd
eventsight> edit learning_20241209_143052_a1b2c3d4
```

Delete a learning:
```cmd
eventsight> delete learning_20241209_143052_a1b2c3d4
```

Search learnings by keyword:
```cmd
eventsight> search mssense
```

## How It Works

### Architecture

EventSight consists of two components that share a common data layer:

| Component | Purpose | Interface |
|-----------|---------|-----------|
| **EventSight CLI** | Interactive analysis & reporting | `uv run eventsight` |
| **EventSight-MCP** | Claude Code integration | MCP stdio server |

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                              USER INTERFACES                                     │
├────────────────────────────────────┬────────────────────────────────────────────┤
│          EventSight CLI              │           EventSight-MCP                      │
│         (Interactive)              │         (Claude Code)                       │
│                                    │                                             │
│  • evaluate <file>                 │  MCP Server (stdio) - 16 Tools:             │
│  • feedback <id> <verdict>         │  • evaluate_evtx                            │
│  • learnings / correlation         │  • feedback (agentic RAG)                   │
│  • report / export                 │  • list/search/edit learnings              │
│  • --continuous mode               │  • correlation rules                        │
│                                    │  • search_events                            │
└──────────────┬─────────────────────┴──────────────┬──────────────────────────────┘
               │                                    │
               └───────────────┬────────────────────┘
                               ▼
┌────────────────────────────────────────────────────────────────────────────────┐
│                           CORE ANALYSIS ENGINE                                  │
│                                                                                 │
│  ┌─────────────────────┐              ┌─────────────────────┐                  │
│  │   SecurityAgent     │              │   AgenticRAG        │                  │
│  │                     │              │   (MCP only)        │                  │
│  │ • EVTX parsing      │              │                     │                  │
│  │ • Batch analysis    │              │ • Natural language  │                  │
│  │ • Smart filtering   │              │   feedback          │                  │
│  │ • Deduplication     │              │ • Autonomous tool   │                  │
│  │ • Continuous mode   │              │   selection         │                  │
│  └──────────┬──────────┘              └──────────┬──────────┘                  │
│             └───────────────┬────────────────────┘                             │
│                             ▼                                                   │
│  ┌──────────────────────────────────────────────────────────────────────────┐  │
│  │                    CLAUDE API (claude-sonnet-4-20250514)                  │  │
│  │                                                                           │  │
│  │   System Prompt = ANALYSIS_PROMPT + Learnings (ICL) + Correlation Rules   │  │
│  │                              ↓                                            │  │
│  │                    JSON Response: Findings                                │  │
│  └──────────────────────────────────────────────────────────────────────────┘  │
└────────────────────────────────────────────────────────────────────────────────┘
                               │
                               ▼
┌────────────────────────────────────────────────────────────────────────────────┐
│                              RAG SYSTEM                                         │
│                                                                                 │
│   ┌────────────────────────────────────────────────────────────────────────┐   │
│   │                         RETRIEVAL                                       │   │
│   │                                                                         │   │
│   │   FAST PATH (O(1))                      FALLBACK (O(n))                 │   │
│   │   ┌──────────────────┐    ──miss──▶    ┌──────────────────┐            │   │
│   │   │ Event ID Cache   │                 │ Vector Search    │            │   │
│   │   │ {4624: [L1,L5],  │                 │ sentence-        │            │   │
│   │   │  4688: [L2], ..} │                 │ transformers     │            │   │
│   │   └──────────────────┘                 └──────────────────┘            │   │
│   │                        ↓                                                │   │
│   │              Top 10 Relevant Learnings                                  │   │
│   └────────────────────────────────────────────────────────────────────────┘   │
│                                                                                 │
│   ┌────────────────────────────────────────────────────────────────────────┐   │
│   │   AUGMENTATION: Inject learnings into system prompt                     │   │
│   │   ICL: Claude adapts behavior based on injected insights                │   │
│   └────────────────────────────────────────────────────────────────────────┘   │
└────────────────────────────────────────────────────────────────────────────────┘
                               │
                               ▼
┌────────────────────────────────────────────────────────────────────────────────┐
│                         SHARED DATA LAYER                                       │
│                       data/learnings/                                           │
│                                                                                 │
│   ┌─────────────────────────────────────────────────────────────────────────┐  │
│   │                      learnings.db (SQLite)                               │  │
│   │  ┌─────────────────┐  ┌─────────────────┐  ┌───────────────────────┐    │  │
│   │  │   learnings     │  │correlation_rules│  │  analysis_history     │    │  │
│   │  │ • insight       │  │ • source_event  │  │  • findings_json      │    │  │
│   │  │ • keywords      │  │ • target_event  │  │  • learnings_applied  │    │  │
│   │  │ • event_ids     │  │ • field mapping │  │                       │    │  │
│   │  └─────────────────┘  └─────────────────┘  └───────────────────────┘    │  │
│   └─────────────────────────────────────────────────────────────────────────┘  │
│                                                                                 │
│   ┌──────────────────────────┐    ┌──────────────────────────────────────┐     │
│   │  events.db (SQLite)      │    │  embeddings.npy (NumPy)              │     │
│   │  • All parsed events     │    │  • Vector embeddings for             │     │
│   │  • Indexed by Event ID,  │    │    semantic similarity search        │     │
│   │    timestamp, provider   │    │  • 384-dim float arrays              │     │
│   └──────────────────────────┘    └──────────────────────────────────────┘     │
└────────────────────────────────────────────────────────────────────────────────┘
                               │
                               ▼
┌────────────────────────────────────────────────────────────────────────────────┐
│                            INPUT: EVTX FILES                                    │
│                                                                                 │
│   parser.py → wevtutil.exe → XML → WindowsEvent objects                        │
│                                                                                 │
│   • Security.evtx    (4624, 4688, 4662, ...)                                   │
│   • Sysmon.evtx      (1, 3, 7, 8, 10, 11, ...)                                 │
│   • PowerShell.evtx  (4103, 4104, ...)                                         │
└────────────────────────────────────────────────────────────────────────────────┘
```

### Feedback Loop (Learning Cycle)

```
                              ┌──────────────────────┐
                              │   1. ANALYSIS        │
                              │   EVTX → Findings    │
                              └──────────┬───────────┘
                                         │
                                         ▼
┌──────────────────────┐      ┌──────────────────────┐
│   4. RETRIEVAL       │      │   2. REVIEW          │
│   Next analysis      │◀─────│   Analyst reviews    │
│   retrieves learning │      │   findings           │
└──────────────────────┘      └──────────┬───────────┘
         ▲                               │
         │                               ▼
         │                    ┌──────────────────────┐
         │                    │   3. FEEDBACK        │
         └────────────────────│   "False positive,   │
                              │    this is MsSense"  │
                              └──────────┬───────────┘
                                         │
                                         ▼
                              ┌──────────────────────┐
                              │   Claude extracts    │
                              │   reusable insight   │
                              │   + Event IDs        │
                              │   + Keywords         │
                              │         ↓            │
                              │   Stored in DB +     │
                              │   Vector embeddings  │
                              └──────────────────────┘
```

### Analysis Flow

1. **Parse**: EVTX file(s) parsed into structured events
2. **Store**: All parsed events saved to `events.db` for later querying
3. **Filter**: Smart filtering identifies security-relevant Event IDs (or use explicit filters)
4. **Batch**: Large files split into batches (default: 25 events per batch)
5. **Retrieve**: Dual-path learning retrieval (Event ID cache first, then vector search fallback)
6. **Analyze**: Claude analyzes events with context from learnings (ICL)
7. **Correlate**: Events matched against correlation rules
8. **Deduplicate**: Findings across batches are deduplicated
9. **Report**: Findings presented with timeline, context, and recommendations

### Semantic Search RAG

EventSight uses **sentence-transformers** (`all-MiniLM-L6-v2`) for semantic similarity search instead of simple keyword matching:

```
Query: "mimikatz credential theft"
Results:
  "LSASS memory access credential dumping" → 0.348 (match!)
  "Normal user login activity"             → 0.239
  "PowerShell encoded command"             → 0.055
```

Benefits over keyword matching:
- Finds conceptually related learnings even without shared words
- "Credential dumping" matches learnings about "LSASS access"
- Understands security domain relationships

### Dual-Path Learning Retrieval

EventSight uses a two-tier retrieval system for optimal performance:

1. **Fast Path (O(1))**: Event ID-based cache lookup
2. **Fallback Path**: Vector-based semantic search when no Event ID matches

```
Events to analyze
       │
       ▼
Extract Event IDs: {4624, 4688, 4769, ...}
       │
       ▼
┌─────────────────────────────────────────┐
│ FAST PATH: Event ID Cache (O(1))        │
│                                          │
│ _event_id_cache = {                      │
│   4624: ["learning_001", "learning_005"],│
│   4688: ["learning_002"],                │
│   ...                                    │
│ }                                        │
└─────────────────────────────────────────┘
       │
       ├── Matches found? ──▶ Return learnings
       │
       └── No matches? ─────▼
                             │
┌─────────────────────────────────────────┐
│ FALLBACK: Vector Semantic Search (O(n)) │
│                                          │
│ Query embedding vs stored embeddings    │
│ Returns top matches by cosine similarity│
└─────────────────────────────────────────┘
```

### RAG + In-Context Learning

EventSight combines two techniques instead of fine-tuning:

- **RAG (Retrieval-Augmented Generation)**: Retrieves relevant learnings based on Event IDs (fast) or semantic similarity (fallback)
- **ICL (In-Context Learning)**: Retrieved insights are injected into the prompt as examples that guide Claude's analysis

Benefits:
- No model modification - learnings are stored locally, not baked into weights
- Fully auditable - view, edit, and delete any learning
- Portable - copy the database to transfer learnings between systems
- Fast retrieval via Event ID indexing

```
Events ──▶ Event ID Cache ──▶ Retrieved Learnings
              (O(1))              │
                │                  │
                └── (fallback) ───▶ Vector Search (O(n))
                                      │
                                      ▼
               System Prompt + Insights ──▶ Claude Analysis
                               (ICL)
```

**Flow:**
1. **Feedback**: Analyst marks a finding with verdict and explanation
2. **Extract**: Claude extracts a reusable insight from the feedback
3. **Index**: Event IDs from related events automatically stored with learning
4. **Embed**: Insight embedded and stored with vector representation
5. **Retrieve**: Fast Event ID lookup first, then vector search fallback (RAG)
6. **Inject**: Top matching insights appended to the system prompt (ICL)

## Project Structure

```
eventsight/
├── src/
│   └── eventsight/
│       ├── __init__.py
│       ├── __main__.py      # CLI entry point
│       ├── cli.py           # Interactive terminal & HTML reports
│       ├── agent.py         # Core agent logic + batch processing
│       ├── parser.py        # EVTX parsing (wevtutil.exe)
│       ├── learnings.py     # Learning storage + vector search
│       ├── events_store.py  # Event storage (separate SQLite DB)
│       ├── prompts.py       # System prompts & JSON schemas
│       └── models.py        # Data models (Finding, Learning, CorrelationRule)
├── data/
│   ├── learnings/
│   │   ├── learnings.db     # Learnings, correlation rules, analysis history
│   │   ├── events.db        # All parsed events indexed for querying
│   │   ├── embeddings.npy   # Vector embeddings for semantic search
│   │   └── event_embeddings.npy  # Event embeddings
│   ├── FilterRules/         # Example CSV filter files
│   └── ReportExamples/      # Example HTML reports
├── pyproject.toml           # Project config (uv/pip compatible)
├── uv.lock                  # Locked dependencies
└── README.md
```

## Configuration

Configuration is available through `AgentConfig` in `models.py`:

```python
model: str = "claude-sonnet-4-20250514"  # Claude model to use
max_events_per_batch: int = 25           # Default events (limited mode)
batch_size: int = 25                     # Events per batch (API limit friendly)
confidence_threshold: Severity = Severity.MEDIUM  # Minimum severity to display
min_confidence_score: float = 0.65       # Filter findings below 65% confidence
database_path: str = "./data/learnings/learnings.db"
```

## Why 65% Confidence Threshold?

EventSight filters out findings below 65% confidence by default. This isn't arbitrary—it reflects how security operations actually work in the real world.

### The Signal-to-Noise Problem

AI models analyzing security logs will find *something* suspicious in almost any dataset. Windows generates millions of events daily, and many legitimate system behaviors technically match attack patterns:

- `svchost.exe` creating threads in user processes (normal Windows IPC)
- `explorer.exe` making network connections (shell integration, thumbnails, OneDrive)
- `lsass.exe` being accessed by security tools (EDR doing its job)
- PowerShell loading .NET assemblies (standard scripting behavior)

Without confidence filtering, analysts get buried in noise. A 40% confidence finding that says "explorer.exe made a network connection" wastes investigation time and erodes trust in the tool.

### The 65% Standard

The 65% threshold means:
- **0.65-1.0**: Strong indicators with corroborating evidence → Surface to analyst
- **0.5-0.65**: Suspicious but ambiguous → Log for correlation, don't alert
- **Below 0.5**: Weak signals, likely benign → Filter out entirely

This mirrors industry practice. Most EDR platforms, SIEM rules, and threat detection systems use similar thresholds. An alert that fires constantly gets disabled; an alert that fires accurately gets investigated.

### Adjusting the Threshold

If you want more aggressive detection (at the cost of more noise):

```python
# In models.py or via config
min_confidence_score: float = 0.5  # Lower threshold, more findings
```

For high-security environments with dedicated analyst capacity, lowering to 0.5 may be appropriate. For most use cases, 65% provides the right balance of coverage and actionability.


## Token Usage

When the project runs it will show the token usage like so:
```
Analyzing batch 1/3...
  Tokens: 2,450 in / 1,230 out
Analyzing batch 2/3...
  Tokens: 2,380 in / 1,150 out
Analyzing batch 3/3...
  Tokens: 2,290 in / 980 out
Total tokens used: 7,120 input, 3,360 output
```

## License

MIT License
