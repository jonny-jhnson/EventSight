"""EventSight MCP Server - Windows Event Log Analysis via MCP."""

import atexit
import json
import os
import signal
import sys
from pathlib import Path
from typing import Optional

from mcp.server.fastmcp import FastMCP

from .agent import SecurityAgent
from .models import Verdict, Severity, AgentConfig


# Global agent instance (initialized lazily)
_agent: Optional[SecurityAgent] = None

# Flag to track if shutdown is in progress
_shutting_down = False


def shutdown_handler(signum=None, frame=None):
    """Handle graceful shutdown on Ctrl+C or termination signals."""
    global _shutting_down, _agent

    if _shutting_down:
        # Already shutting down, force exit on second signal
        print("\nForce exit requested.", file=sys.stderr)
        sys.exit(1)

    _shutting_down = True
    print("\nShutdown requested - stopping background processes...", file=sys.stderr)

    if _agent is not None:
        try:
            # Cancel any running batch operations
            _agent.cancel()
            # Clean up resources
            _agent.close()
        except Exception as e:
            print(f"Error during cleanup: {e}", file=sys.stderr)

    sys.exit(0)


def cleanup_on_exit():
    """Cleanup handler for normal exit."""
    global _agent
    if _agent is not None:
        try:
            _agent.close()
        except Exception:
            pass


def get_agent() -> SecurityAgent:
    """Get or create the SecurityAgent instance."""
    global _agent
    if _agent is None:
        # Set up database path - share learnings with Eventsight project
        db_path = os.environ.get(
            "EVENTSIGHT_DB_PATH",
            str(Path(__file__).parent.parent.parent.parent / "Eventsight" / "data" / "learnings" / "learnings.db")
        )
        config = AgentConfig(database_path=db_path)
        _agent = SecurityAgent(config=config)
    return _agent


# Create the MCP server
mcp = FastMCP("EventSight")


# ==================== Analysis Tools ====================

@mcp.tool()
def evaluate_evtx(
    file_path: str,
    event_ids: Optional[str] = None,
    batch_size: int = 25,
    analyze_all: bool = True
) -> dict:
    """
    Analyze a Windows EVTX file for security threats.

    Args:
        file_path: Path to the EVTX file to analyze
        event_ids: Optional comma-separated Event IDs to filter (e.g., "4624,4688,5145")
        batch_size: Number of events per batch (default: 25)
        analyze_all: Whether to analyze all events or just first batch

    Returns:
        Analysis results including findings, summary, and statistics
    """
    agent = get_agent()

    # Parse event IDs if provided
    filter_event_ids = None
    if event_ids:
        filter_event_ids = [int(eid.strip()) for eid in event_ids.split(",")]

    # Run analysis
    result = agent.evaluate_evtx(
        file_path,
        batch_size=batch_size,
        filter_event_ids=filter_event_ids,
        parse_all=analyze_all
    )

    # Convert findings to serializable format
    findings_list = []
    for f in result.findings:
        finding_dict = {
            "id": f.id,
            "severity": f.severity.value,
            "title": f.title,
            "description": f.description,
            "technique": f.technique,
            "tactic": f.tactic,
            "confidence": f.confidence,
            "recommendation": f.recommendation,
            "instance_count": f.instance_count
        }
        if f.security_context:
            finding_dict["security_context"] = {
                "user": f"{f.security_context.user_domain}\\{f.security_context.user_name}" if f.security_context.user_name else None,
                "source_ip": f.security_context.source_ip,
                "process": f.security_context.process_name,
                "file": f.security_context.target_filename
            }
        findings_list.append(finding_dict)

    return {
        "analysis_id": result.id,
        "file": result.file_path,
        "total_events": result.total_events,
        "events_analyzed": result.events_analyzed,
        "findings_count": len(result.findings),
        "findings": findings_list,
        "summary": result.summary
    }


# ==================== Feedback Tools ====================

@mcp.tool()
def add_feedback(
    finding_id: str,
    verdict: str,
    explanation: str,
    event_ids: Optional[str] = None
) -> dict:
    """
    Provide feedback on a finding to create a learning.

    Args:
        finding_id: ID of the finding to provide feedback on
        verdict: One of: false_positive, true_positive, benign, needs_context
        explanation: Your explanation of why this verdict applies
        event_ids: Optional comma-separated Event IDs for this learning (e.g., "5145,4663")

    Returns:
        The created learning with insight and keywords
    """
    agent = get_agent()

    # Parse verdict
    try:
        verdict_enum = Verdict(verdict)
    except ValueError:
        return {"error": f"Invalid verdict: {verdict}. Use: false_positive, true_positive, benign, needs_context"}

    # Parse event IDs if provided
    event_ids_list = None
    if event_ids:
        event_ids_list = [int(eid.strip()) for eid in event_ids.split(",")]

    learning = agent.add_feedback(finding_id, verdict_enum, explanation, event_ids_list)

    return {
        "learning_id": learning.id,
        "insight": learning.insight,
        "keywords": learning.keywords[:10],
        "event_ids": learning.event_ids,
        "verdict": learning.type.value
    }


# ==================== Learning Management Tools ====================

@mcp.tool()
def list_learnings(limit: int = 50) -> dict:
    """
    List all stored learnings.

    Args:
        limit: Maximum number of learnings to return

    Returns:
        List of learnings with their insights and event IDs
    """
    agent = get_agent()

    learnings = agent.get_learnings(limit=limit)

    return {
        "count": len(learnings),
        "learnings": [
            {
                "id": l.id,
                "insight": l.insight[:200] + "..." if len(l.insight) > 200 else l.insight,
                "event_ids": l.event_ids,
                "verdict": l.type.value if l.type else None,
                "keywords": l.keywords[:5]
            }
            for l in learnings
        ]
    }


@mcp.tool()
def search_learnings(query: str, limit: int = 10) -> dict:
    """
    Search learnings by keyword or semantic similarity.

    Args:
        query: Search query (keywords or description)
        limit: Maximum results to return

    Returns:
        Matching learnings
    """
    agent = get_agent()

    learnings = agent.search_learnings(query, limit=limit)

    return {
        "query": query,
        "count": len(learnings),
        "results": [
            {
                "id": l.id,
                "insight": l.insight,
                "event_ids": l.event_ids,
                "keywords": l.keywords[:5]
            }
            for l in learnings
        ]
    }


@mcp.tool()
def edit_learning(
    learning_id: str,
    new_insight: Optional[str] = None,
    event_ids: Optional[str] = None
) -> dict:
    """
    Edit a learning's insight text or Event IDs.

    Args:
        learning_id: ID of the learning to edit
        new_insight: New insight text (optional)
        event_ids: New Event IDs as comma-separated string (optional)

    Returns:
        Success status and updated learning
    """
    agent = get_agent()

    if new_insight:
        success = agent.update_learning(learning_id, new_insight)
        if not success:
            return {"error": f"Failed to update insight for {learning_id}"}

    if event_ids:
        event_ids_list = [int(eid.strip()) for eid in event_ids.split(",")]
        success = agent.update_learning_event_ids(learning_id, event_ids_list)
        if not success:
            return {"error": f"Failed to update Event IDs for {learning_id}"}

    # Get updated learning
    learning = agent.get_learning(learning_id)
    if not learning:
        return {"error": f"Learning not found: {learning_id}"}

    return {
        "success": True,
        "learning": {
            "id": learning.id,
            "insight": learning.insight,
            "event_ids": learning.event_ids
        }
    }


@mcp.tool()
def delete_learning(learning_id: str) -> dict:
    """
    Delete a learning.

    Args:
        learning_id: ID of the learning to delete

    Returns:
        Success status
    """
    agent = get_agent()

    success = agent.delete_learning(learning_id)
    return {
        "success": success,
        "deleted_id": learning_id if success else None,
        "error": None if success else f"Learning not found: {learning_id}"
    }


# ==================== Correlation Rules Tools ====================

@mcp.tool()
def list_correlation_rules() -> dict:
    """
    List all correlation rules.

    Returns:
        List of correlation rules with their configurations
    """
    agent = get_agent()

    rules = agent.get_correlation_rules()

    return {
        "count": len(rules),
        "rules": [
            {
                "id": r.id,
                "name": r.name,
                "source_event_id": r.source_event_id,
                "target_event_id": r.target_event_id,
                "source_field": r.source_field,
                "target_field": r.target_field,
                "security_context": r.security_context
            }
            for r in rules
        ]
    }


@mcp.tool()
def add_correlation_rule(
    name: str,
    source_event_id: int,
    target_event_id: int,
    source_field: str,
    target_field: str,
    security_context: str,
    source_condition: Optional[str] = None,
    time_window_seconds: int = 300
) -> dict:
    """
    Add a new correlation rule to detect attack patterns.

    Args:
        name: Name of the correlation rule
        source_event_id: Event ID that starts the correlation
        target_event_id: Event ID that completes the correlation
        source_field: Field in source event to match
        target_field: Field in target event to match
        security_context: Description of what this correlation indicates
        source_condition: Optional condition for source event (e.g., "LogonType=3")
        time_window_seconds: Time window for correlation (default: 300)

    Returns:
        The created correlation rule
    """
    agent = get_agent()

    rule = agent.add_correlation_rule(
        name=name,
        source_event_id=source_event_id,
        target_event_id=target_event_id,
        source_field=source_field,
        target_field=target_field,
        security_context=security_context,
        source_condition=source_condition,
        time_window_seconds=time_window_seconds
    )

    return {
        "success": True,
        "rule": {
            "id": rule.id,
            "name": rule.name,
            "pattern": f"Event {rule.source_event_id} -> Event {rule.target_event_id} via {source_field}"
        }
    }


@mcp.tool()
def delete_correlation_rule(rule_id: str) -> dict:
    """
    Delete a correlation rule.

    Args:
        rule_id: ID of the rule to delete

    Returns:
        Success status
    """
    agent = get_agent()

    success = agent.delete_correlation_rule(rule_id)
    return {
        "success": success,
        "deleted_id": rule_id if success else None
    }


# ==================== Agentic RAG Tools ====================

@mcp.tool()
def search_stored_events(
    query: str,
    event_ids: Optional[str] = None,
    limit: int = 20
) -> dict:
    """
    Semantically search stored events using natural language.

    Use this to find specific events based on activity descriptions:
    - "LSASS memory access"
    - "PsExec lateral movement"
    - "encoded PowerShell execution"
    - "network logons from external IPs"

    Args:
        query: Natural language description of events to find
        event_ids: Optional comma-separated Event IDs to filter (e.g., "4624,4688")
        limit: Maximum results to return

    Returns:
        Matching events with similarity scores and details
    """
    agent = get_agent()

    # Parse event IDs if provided
    event_ids_list = None
    if event_ids:
        event_ids_list = [int(eid.strip()) for eid in event_ids.split(",")]

    # Use SQL-based search with field_contains derived from query
    field_contains = {}

    # Simple keyword extraction for common patterns
    query_lower = query.lower()
    if "lsass" in query_lower:
        field_contains["TargetImage"] = "lsass"
    if "powershell" in query_lower:
        field_contains["CommandLine"] = "powershell"
    if "encoded" in query_lower or "-enc" in query_lower:
        field_contains["CommandLine"] = "-enc"
    if "psexec" in query_lower:
        field_contains["ServiceName"] = "PSEXESVC"
    if "mimikatz" in query_lower:
        field_contains["SourceImage"] = "mimikatz"

    events = agent.events_store.search_events(
        event_ids=event_ids_list,
        field_contains=field_contains if field_contains else None,
        limit=limit
    )

    return {
        "query": query,
        "count": len(events),
        "events": [
            {
                "db_id": e["id"],
                "event_id": e["event_id"],
                "timestamp": e["timestamp"],
                "provider": e["provider"],
                "event_data": e["event_data"]
            }
            for e in events
        ]
    }


@mcp.tool()
def feedback(instruction: str) -> dict:
    """
    Process analyst feedback using Agentic RAG.

    This is an autonomous agent that can:
    - Mark findings as false positives/true positives and create learnings
    - Search stored events to find things the initial analysis missed
    - Create learnings from discovered patterns

    Examples:
        "Finding #2 is legitimate, that's our monitoring agent"
        "You missed the PsExec lateral movement - find it and create a learning"
        "Look for LSASS access events and tell me what you find"
        "Search for encoded PowerShell and create a learning if suspicious"

    Args:
        instruction: Natural language instruction describing what to do

    Returns:
        Agent response with actions taken and any created learnings
    """
    agent = get_agent()

    result = agent.process_feedback(instruction)

    return {
        "success": result.get("success", False),
        "response": result.get("response", ""),
        "iterations": result.get("iterations", 0),
        "created_learnings": result.get("created_learnings", []),
        "marked_findings": result.get("marked_findings", []),
        "tool_calls": len(result.get("tool_calls", [])),
        "error": result.get("error")
    }


@mcp.tool()
def get_event_details(event_db_id: int) -> dict:
    """
    Get full details of a specific event by its database ID.

    Use after search_stored_events to get complete event information.

    Args:
        event_db_id: The database ID of the event (from search results)

    Returns:
        Full event details including all event_data fields
    """
    agent = get_agent()

    event = agent.events_store.get_event_by_db_id(event_db_id)

    if not event:
        return {"error": f"Event not found with db_id: {event_db_id}"}

    return {
        "db_id": event["id"],
        "event_id": event["event_id"],
        "timestamp": event["timestamp"],
        "provider": event["provider"],
        "channel": event["channel"],
        "computer": event["computer"],
        "user_sid": event["user_sid"],
        "process_id": event["process_id"],
        "analysis_id": event["analysis_id"],
        "event_data": event["event_data"]
    }


# ==================== Statistics Tools ====================

@mcp.tool()
def get_stats() -> dict:
    """
    Get EventSight statistics including learnings count, analyses, and event counts.

    Returns:
        Statistics about the EventSight instance
    """
    agent = get_agent()

    stats = agent.get_stats()
    return stats


@mcp.tool()
def clear_events(clear_all: bool = False) -> dict:
    """
    Clear stored events from the database.

    Args:
        clear_all: If True, clears ALL events. If False, clears only current analysis.

    Returns:
        Number of events cleared
    """
    agent = get_agent()

    if clear_all:
        count = agent.clear_events()
    else:
        count = agent.clear_events(current_only=True)

    return {
        "cleared": count,
        "scope": "all" if clear_all else "current_analysis"
    }


# ==================== Export/Import Tools ====================

@mcp.tool()
def export_learnings_package(output_path: str, include_embeddings: bool = True) -> dict:
    """
    Export learnings database to a portable ZIP package.

    Creates a self-contained package that can be imported into another
    EventSight instance or a different project that doesn't use Agentic RAG.

    Args:
        output_path: Path for the output ZIP file (e.g., "my_learnings.zip")
        include_embeddings: Whether to include vector embeddings (larger but faster import)

    Returns:
        Export metadata including counts and file size
    """
    from .learnings import export_learnings

    agent = get_agent()
    db_path = agent.config.database_path

    try:
        result = export_learnings(db_path, output_path, include_embeddings)
        return result
    except Exception as e:
        return {"error": str(e)}


@mcp.tool()
def import_learnings_package(package_path: str, merge: bool = True) -> dict:
    """
    Import learnings from an exported package.

    Args:
        package_path: Path to the exported ZIP file
        merge: If True, merge with existing learnings (skip duplicates).
               If False, replace all learnings.

    Returns:
        Import metadata including counts
    """
    from .learnings import import_learnings

    agent = get_agent()
    target_dir = str(Path(agent.config.database_path).parent)

    try:
        result = import_learnings(package_path, target_dir, merge)

        # Rebuild in-memory caches after import
        agent.learnings_store._build_event_id_cache()
        if agent.learnings_store.use_vectors and agent.learnings_store.vector_store:
            agent.learnings_store._ensure_embeddings()

        return result
    except Exception as e:
        return {"error": str(e)}


# ==================== Entry Point ====================

def main():
    """Run the MCP server."""
    # Register signal handlers for graceful shutdown
    signal.signal(signal.SIGINT, shutdown_handler)
    signal.signal(signal.SIGTERM, shutdown_handler)

    # Register cleanup on normal exit
    atexit.register(cleanup_on_exit)

    try:
        mcp.run(transport="stdio")
    except KeyboardInterrupt:
        shutdown_handler()
    finally:
        cleanup_on_exit()


if __name__ == "__main__":
    main()
