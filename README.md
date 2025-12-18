# EventSight

AI-powered Windows Event Log analyzer that learns from analyst feedback.

## Project Structure

This repository contains two related projects:

```
EventSight/
├── Eventsight/          # Standalone CLI tool
│   └── data/learnings/  # Shared learnings database
└── Eventsight-MCP/      # MCP server for Claude Code integration
    └── .mcp.json      # MCP configuration
```

### Why Two Projects?

| | Eventsight | Eventsight-MCP |
|---|----------|--------------|
| **Interface** | Command-line (CLI) | MCP Server (Claude Code) |
| **RAG Type** | Standard RAG | Agentic RAG |
| **Use Case** | Direct analysis & reporting | Interactive analysis with Claude |
| **Feedback** | Manual commands | Natural language via Claude |

### Shared Resources

Both projects share the same learnings database, meaning:
- Learnings created in either project benefit both
- Correlation rules are shared
- Analysis improvements compound over time

The shared data lives in `Eventsight/data/learnings/`:
- `learnings.db` - Analyst learnings, correlation rules, and analysis history
- `events.db` - Stored events from analyses (indexed by Event ID, timestamp, provider)
- `embeddings.npy` - 384-dimensional vector embeddings for semantic search
- `event_embeddings.npy` - Event embeddings for semantic event search

## Eventsight (CLI)

The standalone command-line tool for Windows Event Log analysis.

**Features:**
- Parse and analyze EVTX files
- Batch processing with streaming output
- Continuous monitoring mode with live HTML report (auto-refreshing dashboard)
- Standard RAG for fast, deterministic learning retrieval
- Interactive feedback mode
- HTML/Markdown report generation

**Quick Start:**
```bash
cd Eventsight
uv sync
uv run eventsight evaluate Security.evtx --event-ids 4624,4688
```

See [Eventsight/README.md](Eventsight/README.md) for full documentation.

## Eventsight-MCP (Claude Code Integration)

MCP server that brings EventSight capabilities into Claude Code with Agentic RAG.

**Features:**
- All EventSight analysis capabilities via 16 MCP tools
- Agentic RAG for intelligent feedback processing
- Natural language interaction ("Finding #2 is our EDR, mark as benign")
- Semantic event search
- Export/import learnings for sharing between instances

**Quick Start:**
```bash
# From the Eventsight-MCP directory with Claude Code
cd Eventsight-MCP

# Then use tools like:
# - evaluate_evtx to analyze EVTX files
# - feedback to process analyst input using Agentic RAG
# - search_stored_events to find specific activity
# - export_learnings_package to share learnings
```

See [Eventsight-MCP/README.md](Eventsight-MCP/README.md) for full documentation.

## RAG Approaches

### Standard RAG (Eventsight)
Direct vector similarity search for learning retrieval:
1. Query → Embedding → Similarity Search → Top-K Results
2. Fast O(1) lookup by Event ID when available
3. Deterministic, efficient for batch processing

### Agentic RAG (Eventsight-MCP)
LLM-driven tool selection for intelligent processing:
1. Query → LLM analyzes intent → Selects appropriate tools
2. Can search events, create learnings, mark findings autonomously
3. Better at understanding nuanced natural language feedback
4. Creates higher-quality, generalizable learnings

## License

MIT
