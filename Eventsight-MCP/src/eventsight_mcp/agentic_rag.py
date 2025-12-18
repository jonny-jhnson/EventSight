"""Agentic RAG - Autonomous reasoning and retrieval for security analysis feedback."""

import json
import os
import uuid
from datetime import datetime
from typing import Optional, Any

import anthropic

from .models import Learning, Verdict, Finding, WindowsEvent
from .learnings import LearningsStore, extract_keywords


# Tool definitions for the agent - SQL-based search (fast, no embeddings)
AGENTIC_TOOLS = [
    {
        "name": "search_events",
        "description": """Search stored events using structured SQL queries.

You must translate natural language into structured search parameters:

Examples:
- "LSASS memory access" → event_ids=[10], field_contains={"TargetImage": "lsass"}
- "encoded PowerShell" → field_contains={"CommandLine": "-enc"}
- "PsExec lateral movement" → event_ids=[7045], field_contains={"ServiceName": "PSEXESVC"}
- "network logons" → event_ids=[4624], field_contains={"LogonType": "3"}
- "credential dumping" → event_ids=[10], field_contains={"TargetImage": "lsass", "GrantedAccess": "0x1010"}
- "service installations" → event_ids=[7045]
- "process creation with cmd" → event_ids=[1, 4688], field_contains={"CommandLine": "cmd"}

Think about what Event IDs and field values would indicate the activity.""",
        "input_schema": {
            "type": "object",
            "properties": {
                "event_ids": {
                    "type": "array",
                    "items": {"type": "integer"},
                    "description": "Event IDs to filter by (e.g., [10] for Sysmon ProcessAccess, [4624] for logon)"
                },
                "field_contains": {
                    "type": "object",
                    "additionalProperties": {"type": "string"},
                    "description": "Field names and substrings to search for in event_data, e.g., {\"CommandLine\": \"powershell\", \"Image\": \"lsass\"}"
                },
                "provider": {
                    "type": "string",
                    "description": "Optional: Filter by provider name (e.g., 'Sysmon', 'Security')"
                },
                "limit": {
                    "type": "integer",
                    "description": "Maximum events to return (default: 50)",
                    "default": 50
                }
            },
            "required": []
        }
    },
    {
        "name": "get_event_summary",
        "description": """Get a summary of what events are stored and available to search.

Returns Event ID counts, providers, and time range. Use this first to understand
what's available before searching.""",
        "input_schema": {
            "type": "object",
            "properties": {},
            "required": []
        }
    },
    {
        "name": "get_event_details",
        "description": """Get full details of a specific event by its database ID.

Use this after search_events to get complete information about an event,
including all event_data fields that might not be shown in search results.""",
        "input_schema": {
            "type": "object",
            "properties": {
                "event_db_id": {
                    "type": "integer",
                    "description": "The database ID of the event (from search results)"
                }
            },
            "required": ["event_db_id"]
        }
    },
    {
        "name": "search_learnings",
        "description": """Search existing learnings for relevant past insights.

Use this to check if we already have knowledge about a pattern or activity type.""",
        "input_schema": {
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "Description of what to search for"
                },
                "limit": {
                    "type": "integer",
                    "description": "Maximum results (default: 10)",
                    "default": 10
                }
            },
            "required": ["query"]
        }
    },
    {
        "name": "create_learning",
        "description": """Create a new learning from discovered events or analyst feedback.

Use this when:
- You've found events that represent a pattern worth remembering
- The analyst has confirmed an activity is benign/malicious
- You want to improve future analysis based on what was found""",
        "input_schema": {
            "type": "object",
            "properties": {
                "verdict": {
                    "type": "string",
                    "enum": ["false_positive", "true_positive", "benign", "needs_context", "missed_detection"],
                    "description": "Classification of what this learning represents"
                },
                "explanation": {
                    "type": "string",
                    "description": "Analyst explanation of why this classification applies"
                },
                "event_ids": {
                    "type": "array",
                    "items": {"type": "integer"},
                    "description": "Event IDs this learning applies to"
                },
                "related_event_db_ids": {
                    "type": "array",
                    "items": {"type": "integer"},
                    "description": "Optional: Specific event database IDs this learning was based on"
                },
                "finding_summary": {
                    "type": "string",
                    "description": "Optional: Summary of the finding or pattern this learning addresses"
                }
            },
            "required": ["verdict", "explanation", "event_ids"]
        }
    },
    {
        "name": "mark_finding",
        "description": """Mark a finding from the analysis with a verdict.

Use this when the analyst provides feedback on an existing finding.""",
        "input_schema": {
            "type": "object",
            "properties": {
                "finding_id": {
                    "type": "string",
                    "description": "ID of the finding to mark"
                },
                "verdict": {
                    "type": "string",
                    "enum": ["false_positive", "true_positive", "benign", "needs_context"],
                    "description": "The verdict for this finding"
                },
                "explanation": {
                    "type": "string",
                    "description": "Explanation for the verdict"
                }
            },
            "required": ["finding_id", "verdict", "explanation"]
        }
    },
    {
        "name": "get_analysis_summary",
        "description": """Get a summary of the current/recent analysis including findings.

Use this to understand what was already found before searching for missed events.""",
        "input_schema": {
            "type": "object",
            "properties": {},
            "required": []
        }
    }
]


AGENTIC_SYSTEM_PROMPT = """You are a security analyst assistant that helps process feedback on security log analysis.

## Your Role

After an EVTX file has been analyzed, the threat hunter will provide feedback. Your job is to:

1. **Process verdicts on existing findings** - When they say a finding is legitimate/false positive, mark it and create a learning
2. **Find missed detections** - When they say "you missed X", search the stored events to find it
3. **Create learnings** - Build reusable knowledge that improves future analyses

## Your Tools

- **get_event_summary**: See what events are available (Event ID counts, providers). USE THIS FIRST.
- **search_events**: SQL-based search. YOU must translate queries into Event IDs and field filters.
- **get_event_details**: Get full details of a specific event after finding it.
- **search_learnings**: Check if we already have relevant knowledge.
- **create_learning**: Save a new insight for future analyses.
- **mark_finding**: Apply a verdict to an existing finding.
- **get_analysis_summary**: Review what was already found.

## How to Search for Events

The search_events tool uses SQL, so you must translate natural language into structured queries:

| Looking for... | event_ids | field_contains |
|----------------|-----------|----------------|
| LSASS access | [10] | {"TargetImage": "lsass"} |
| Encoded PowerShell | [1, 4688] | {"CommandLine": "-enc"} |
| PsExec | [7045] | {"ServiceName": "PSEXESVC"} |
| Network logons | [4624] | {"LogonType": "3"} |
| Mimikatz | [10] | {"SourceImage": "mimikatz"} |
| Service install | [7045] | {} |
| Scheduled task | [4698] | {} |
| Registry run key | [13] | {"TargetObject": "Run"} |
| Remote thread | [8] | {} |
| DNS query | [22] | {} |
| File creation | [11] | {} |

## Event ID Reference

**Security Log:**
- 4624: Logon (check LogonType: 2=interactive, 3=network, 10=RDP)
- 4625: Failed logon
- 4648: Explicit credential logon
- 4672: Special privileges assigned
- 4688: Process creation
- 4698/4699/4700/4701/4702: Scheduled task operations
- 7045: Service installation

**Sysmon:**
- 1: Process creation (with CommandLine, ParentImage)
- 3: Network connection
- 7: Image loaded (DLL)
- 8: CreateRemoteThread
- 10: ProcessAccess (credential dumping)
- 11: FileCreate
- 13: RegistryEvent
- 22: DNSEvent

## How to Handle Feedback

### "Finding #X is legitimate / false positive / benign"
1. Use mark_finding to apply the verdict
2. A learning will be automatically created

### "You missed X activity" or "Find the X events"
1. First, use get_event_summary to see what's available
2. Think about what Event IDs and field values would indicate this activity
3. Use search_events with appropriate filters
4. If too broad, refine with more specific field_contains
5. When you find relevant events, present them to the analyst
6. If they confirm, create a learning for future detection

## Response Guidelines

- Be concise but thorough
- Always start with get_event_summary if you need to search
- Explain what you found and why it matters
- If you can't find something, explain what you searched for
- Always create learnings for confirmed patterns
- Reference specific Event IDs and fields when discussing findings"""


class AgenticRAG:
    """
    Agentic RAG orchestrator for autonomous security analysis feedback processing.

    Implements a tool-use loop where the agent can:
    - Search stored events using SQL queries
    - Search existing learnings
    - Create new learnings
    - Mark findings with verdicts
    - Reason about what to do next

    The agent continues until it decides it has addressed the feedback.
    """

    def __init__(self,
                 learnings_store: LearningsStore,
                 events_store: Any,  # EventsStore
                 current_analysis: Any = None,  # AnalysisResult
                 model: str = "claude-sonnet-4-20250514"):
        """
        Initialize the Agentic RAG orchestrator.

        Args:
            learnings_store: Store for learnings
            events_store: Store for events (SQLite)
            current_analysis: Current/recent analysis result for context
            model: Claude model to use
        """
        self.learnings_store = learnings_store
        self.events_store = events_store
        self.current_analysis = current_analysis
        self.model = model

        # Initialize Anthropic client
        api_key = os.environ.get("ANTHROPIC_API_KEY")
        if not api_key:
            raise ValueError("ANTHROPIC_API_KEY environment variable not set")
        self.client = anthropic.Anthropic(api_key=api_key)

        # Track tool calls for observability
        self._tool_calls: list[dict] = []
        self._total_input_tokens = 0
        self._total_output_tokens = 0

    def process_feedback(self, instruction: str, max_iterations: int = 10) -> dict:
        """
        Process analyst feedback using the agent loop.

        Args:
            instruction: The analyst's feedback/instruction
            max_iterations: Maximum tool-use iterations

        Returns:
            Result dict with response, actions taken, and any created learnings
        """
        self._tool_calls = []
        self._total_input_tokens = 0
        self._total_output_tokens = 0

        messages = [{"role": "user", "content": instruction}]
        created_learnings = []
        marked_findings = []

        for iteration in range(max_iterations):
            # Call Claude with tools
            response = self.client.messages.create(
                model=self.model,
                max_tokens=4096,
                system=AGENTIC_SYSTEM_PROMPT,
                tools=AGENTIC_TOOLS,
                messages=messages
            )

            self._total_input_tokens += response.usage.input_tokens
            self._total_output_tokens += response.usage.output_tokens

            # Check if agent is done (no tool use)
            if response.stop_reason == "end_turn":
                # Extract final text response
                final_text = ""
                for block in response.content:
                    if hasattr(block, 'text'):
                        final_text = block.text
                        break

                return {
                    "success": True,
                    "response": final_text,
                    "iterations": iteration + 1,
                    "tool_calls": self._tool_calls,
                    "created_learnings": created_learnings,
                    "marked_findings": marked_findings,
                    "tokens": {
                        "input": self._total_input_tokens,
                        "output": self._total_output_tokens
                    }
                }

            # Process tool calls
            tool_results = []
            for block in response.content:
                if block.type == "tool_use":
                    tool_name = block.name
                    tool_input = block.input

                    # Log the tool call
                    self._tool_calls.append({
                        "iteration": iteration,
                        "tool": tool_name,
                        "input": tool_input
                    })

                    # Execute the tool
                    result = self._execute_tool(tool_name, tool_input)

                    # Track created learnings and marked findings
                    if tool_name == "create_learning" and result.get("success"):
                        created_learnings.append(result.get("learning_id"))
                    elif tool_name == "mark_finding" and result.get("success"):
                        marked_findings.append(result.get("finding_id"))
                        if result.get("learning_id"):
                            created_learnings.append(result.get("learning_id"))

                    tool_results.append({
                        "type": "tool_result",
                        "tool_use_id": block.id,
                        "content": json.dumps(result, default=str)
                    })

            # Add assistant response and tool results to messages
            messages.append({"role": "assistant", "content": response.content})
            messages.append({"role": "user", "content": tool_results})

        # Max iterations reached
        return {
            "success": False,
            "error": "Max iterations reached",
            "iterations": max_iterations,
            "tool_calls": self._tool_calls,
            "created_learnings": created_learnings,
            "marked_findings": marked_findings,
            "tokens": {
                "input": self._total_input_tokens,
                "output": self._total_output_tokens
            }
        }

    def _execute_tool(self, tool_name: str, tool_input: dict) -> dict:
        """Execute a tool and return the result."""
        try:
            if tool_name == "search_events":
                return self._search_events(
                    event_ids=tool_input.get("event_ids"),
                    field_contains=tool_input.get("field_contains"),
                    provider=tool_input.get("provider"),
                    limit=tool_input.get("limit", 50)
                )
            elif tool_name == "get_event_summary":
                return self._get_event_summary()
            elif tool_name == "get_event_details":
                return self._get_event_details(tool_input["event_db_id"])
            elif tool_name == "search_learnings":
                return self._search_learnings(
                    query=tool_input["query"],
                    limit=tool_input.get("limit", 10)
                )
            elif tool_name == "create_learning":
                return self._create_learning(
                    verdict=tool_input["verdict"],
                    explanation=tool_input["explanation"],
                    event_ids=tool_input["event_ids"],
                    related_event_db_ids=tool_input.get("related_event_db_ids"),
                    finding_summary=tool_input.get("finding_summary", "")
                )
            elif tool_name == "mark_finding":
                return self._mark_finding(
                    finding_id=tool_input["finding_id"],
                    verdict=tool_input["verdict"],
                    explanation=tool_input["explanation"]
                )
            elif tool_name == "get_analysis_summary":
                return self._get_analysis_summary()
            else:
                return {"error": f"Unknown tool: {tool_name}"}
        except Exception as e:
            return {"error": str(e)}

    def _search_events(self,
                       event_ids: Optional[list[int]] = None,
                       field_contains: Optional[dict[str, str]] = None,
                       provider: Optional[str] = None,
                       limit: int = 50) -> dict:
        """Search stored events using SQL queries."""
        events = self.events_store.search_events(
            event_ids=event_ids,
            field_contains=field_contains,
            provider=provider,
            limit=limit
        )

        if not events:
            return {
                "count": 0,
                "events": [],
                "message": "No matching events found. Try different Event IDs or field filters.",
                "search_params": {
                    "event_ids": event_ids,
                    "field_contains": field_contains,
                    "provider": provider
                }
            }

        # Format events for display
        events_list = []
        for e in events:
            event_dict = {
                "db_id": e["id"],
                "event_id": e["event_id"],
                "timestamp": e["timestamp"],
                "provider": e["provider"],
                "channel": e["channel"],
                "event_data": e["event_data"]
            }
            events_list.append(event_dict)

        return {
            "count": len(events_list),
            "events": events_list,
            "search_params": {
                "event_ids": event_ids,
                "field_contains": field_contains,
                "provider": provider
            }
        }

    def _get_event_summary(self) -> dict:
        """Get summary of stored events."""
        return self.events_store.get_event_summary()

    def _get_event_details(self, event_db_id: int) -> dict:
        """Get full details of a specific event."""
        event = self.events_store.get_event_by_db_id(event_db_id)

        if not event:
            return {"error": f"Event not found with db_id: {event_db_id}"}

        return {
            "db_id": event_db_id,
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

    def _search_learnings(self, query: str, limit: int = 10) -> dict:
        """Search existing learnings."""
        learnings = self.learnings_store.search_learnings(query, limit=limit)

        return {
            "count": len(learnings),
            "query": query,
            "learnings": [
                {
                    "id": l.id,
                    "insight": l.insight,
                    "verdict": l.type.value,
                    "event_ids": l.event_ids,
                    "keywords": l.keywords[:10],
                    "times_applied": l.times_applied
                }
                for l in learnings
            ]
        }

    def _create_learning(self, verdict: str, explanation: str, event_ids: list[int],
                         related_event_db_ids: Optional[list[int]] = None,
                         finding_summary: str = "") -> dict:
        """Create a new learning."""
        try:
            verdict_enum = Verdict(verdict)
        except ValueError:
            return {"error": f"Invalid verdict: {verdict}"}

        # Generate insight using Claude
        insight = self._extract_insight(finding_summary, verdict_enum, explanation)

        # Extract keywords
        keywords = extract_keywords(f"{explanation} {finding_summary} {insight}")

        # Create the learning
        learning = Learning(
            id=f"learning_{datetime.now().strftime('%Y%m%d%H%M%S')}_{uuid.uuid4().hex[:8]}",
            type=verdict_enum,
            original_finding_id=None,
            original_finding_summary=finding_summary,
            analyst_explanation=explanation,
            insight=insight,
            keywords=keywords,
            event_ids=event_ids
        )

        # Store it
        self.learnings_store.add_learning(learning)

        return {
            "success": True,
            "learning_id": learning.id,
            "insight": insight,
            "event_ids": event_ids,
            "message": f"Created learning for Event IDs {event_ids}"
        }

    def _extract_insight(self, finding_summary: str, verdict: Verdict, explanation: str) -> str:
        """Use Claude to extract a reusable insight."""
        from .prompts import LEARNING_EXTRACTION_PROMPT

        response = self.client.messages.create(
            model=self.model,
            max_tokens=500,
            system=LEARNING_EXTRACTION_PROMPT,
            messages=[{
                "role": "user",
                "content": f"""Extract a reusable insight from this analyst feedback.

Finding/Context: {finding_summary or 'Not specified'}
Analyst verdict: {verdict.value}
Analyst explanation: {explanation}

Write a 1-3 sentence insight that can help with future analyses. Be specific about what to look for or ignore."""
            }]
        )

        self._total_input_tokens += response.usage.input_tokens
        self._total_output_tokens += response.usage.output_tokens

        return response.content[0].text.strip()

    def _mark_finding(self, finding_id: str, verdict: str, explanation: str) -> dict:
        """Mark a finding with a verdict and create a learning."""
        if not self.current_analysis:
            return {"error": "No current analysis available. Run evaluate_evtx first."}

        # Find the finding
        finding = None
        for f in self.current_analysis.findings:
            if f.id == finding_id:
                finding = f
                break

        if not finding:
            return {"error": f"Finding not found: {finding_id}"}

        try:
            verdict_enum = Verdict(verdict)
        except ValueError:
            return {"error": f"Invalid verdict: {verdict}"}

        # Extract Event IDs from the finding
        event_ids = []
        for related_event in finding.related_events:
            eid = related_event.get('event_id')
            if eid and eid not in event_ids:
                event_ids.append(eid)

        finding_summary = f"{finding.title}: {finding.description[:200]}"

        # Create learning
        result = self._create_learning(
            verdict=verdict,
            explanation=explanation,
            event_ids=event_ids,
            finding_summary=finding_summary
        )

        if result.get("success"):
            # Mark the finding
            finding.feedback_received = True
            finding.analyst_verdict = verdict_enum

            return {
                "success": True,
                "finding_id": finding_id,
                "verdict": verdict,
                "learning_id": result.get("learning_id"),
                "message": f"Marked finding as {verdict} and created learning"
            }
        else:
            return result

    def _get_analysis_summary(self) -> dict:
        """Get summary of current analysis."""
        if not self.current_analysis:
            return {"error": "No current analysis available"}

        findings_summary = []
        for f in self.current_analysis.findings:
            findings_summary.append({
                "id": f.id,
                "severity": f.severity.value,
                "title": f.title,
                "technique": f.technique,
                "confidence": f.confidence,
                "instance_count": f.instance_count,
                "feedback_received": f.feedback_received
            })

        return {
            "analysis_id": self.current_analysis.id,
            "file": self.current_analysis.file_path,
            "total_events": self.current_analysis.total_events,
            "events_analyzed": self.current_analysis.events_analyzed,
            "findings_count": len(self.current_analysis.findings),
            "findings": findings_summary,
            "summary": self.current_analysis.summary
        }
