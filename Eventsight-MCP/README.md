# EventSight-MCP

MCP (Model Context Protocol) server for EventSight that provides Claude Code integration for Windows Event Log analysis with **Agentic RAG**.

## Overview

EventSight-MCP extends the core EventSight project by providing an MCP server interface that can be used directly within Claude Code. The key differentiator is the use of **Agentic RAG** (Retrieval-Augmented Generation) for processing analyst feedback and improving the shared learnings database.

## Agentic RAG vs Standard RAG

### Standard RAG (used in Eventsight)
- Direct vector similarity search to retrieve relevant learnings
- Fast O(1) lookup by Event ID
- Retrieval is deterministic based on query embeddings

### Agentic RAG (used in Eventsight-MCP)
- LLM-driven tool selection for intelligent retrieval and feedback processing
- The agent autonomously decides which tools to use based on the task:
  - `search_learnings` - Semantic search through existing learnings
  - `search_stored_events` - Find specific events in analyzed logs
  - `create_learning` - Generate new learnings from analyst feedback
  - `mark_finding` - Classify findings as true/false positives
- Better at understanding nuanced analyst feedback and creating high-quality learnings

## How It Improves Eventsight

When you provide feedback through the MCP server (e.g., "Finding #2 is a false positive because that's our EDR agent"), the Agentic RAG:

1. **Understands context** - Parses natural language to understand what you mean
2. **Searches intelligently** - Looks for similar existing learnings to avoid duplicates
3. **Creates better learnings** - Generates insights that generalize well to future analyses
4. **Updates the shared database** - Both Eventsight and Eventsight-MCP share the same `learnings.db`

This means learnings created through the MCP's agentic interface benefit the standalone Eventsight CLI tool as well.

## Shared Resources

EventSight-MCP shares the following with the main Eventsight project:
- `Eventsight/data/learnings/learnings.db` - Analyst learnings and correlation rules
- `Eventsight/data/learnings/events.db` - Stored events from analyses

## Installation

### Prerequisites

- Windows OS (uses wevtutil.exe for EVTX parsing)
- Python 3.10+
- Anthropic API key
- uv package manager (recommended)

### Setup

```bash
cd Eventsight-MCP
uv sync

# Set your API key
$env:ANTHROPIC_API_KEY="your-key-here"
```

## Usage with Claude Code

The MCP server is configured in `.mcp.json`:

```json
{
  "mcpServers": {
    "eventsight": {
      "type": "stdio",
      "command": "uv",
      "args": ["run", "eventsight-mcp"]
    }
  }
}
```

Run Claude Code from the `Eventsight-MCP` directory to automatically start the MCP server.

### Available Tools (16 Total)

#### Analysis Tools
| Tool | Description |
|------|-------------|
| `evaluate_evtx` | Analyze EVTX files for security threats |

#### Feedback & Agentic RAG Tools
| Tool | Description |
|------|-------------|
| `feedback` | Process analyst feedback using Agentic RAG (autonomous tool selection) |
| `add_feedback` | Provide verdict on a specific finding with manual Event ID specification |

#### Learning Management Tools
| Tool | Description |
|------|-------------|
| `list_learnings` | View all stored learnings |
| `search_learnings` | Search learnings by keyword or semantic similarity |
| `edit_learning` | Edit a learning's insight text or Event IDs |
| `delete_learning` | Delete a learning |

#### Event Search Tools
| Tool | Description |
|------|-------------|
| `search_stored_events` | Semantic search across analyzed events (LSASS access, PowerShell, etc.) |
| `get_event_details` | Get full details of a specific event by database ID |

#### Correlation Rules Tools
| Tool | Description |
|------|-------------|
| `list_correlation_rules` | View all correlation rules |
| `add_correlation_rule` | Create new correlation rules to detect attack patterns |
| `delete_correlation_rule` | Delete a correlation rule |

#### Statistics & Maintenance Tools
| Tool | Description |
|------|-------------|
| `get_stats` | Get EventSight statistics (learnings count, analyses, events) |
| `clear_events` | Clear stored events from database |

#### Export/Import Tools
| Tool | Description |
|------|-------------|
| `export_learnings_package` | Export learnings to a portable ZIP file for sharing |
| `import_learnings_package` | Import learnings from another instance (merge or replace) |

## Usage Examples

### Analyzing EVTX Files
```
Use evaluate_evtx to analyze Security.evtx for security threats
```

### Providing Feedback with Agentic RAG
The `feedback` tool uses an autonomous agent that can understand natural language:
```
Use feedback with "Finding #2 is a false positive - that's our EDR agent MsSense doing normal monitoring"
```

The agent will:
1. Parse your natural language instruction
2. Identify the finding you're referring to
3. Create a learning with the appropriate verdict and insight
4. Store it in the shared database for future analyses

### Searching Events
```
Use search_stored_events to find "LSASS memory access" events
Use search_stored_events to find "encoded PowerShell execution"
```

### Sharing Learnings
```
# Export learnings to share with another team
Use export_learnings_package with output_path="team_learnings.zip"

# Import learnings from another EventSight instance
Use import_learnings_package with package_path="shared_learnings.zip" and merge=true
```

## Architecture

```
Eventsight-MCP/
├── src/eventsight_mcp/
│   ├── server.py        # MCP server entry point (16 tools defined here)
│   ├── agent.py         # Security analysis agent (SecurityAgent class)
│   ├── agentic_rag.py   # Agentic RAG implementation
│   ├── learnings.py     # Learnings store with vector search + export/import
│   ├── events_store.py  # SQLite event storage
│   ├── evtx_parser.py   # EVTX file parser (uses wevtutil.exe)
│   ├── models.py        # Pydantic models (Finding, Learning, etc.)
│   └── prompts.py       # System prompts & JSON schemas
├── .mcp.json            # MCP server configuration
├── pyproject.toml       # Package dependencies
└── uv.lock              # Locked dependencies
```

## License

MIT
