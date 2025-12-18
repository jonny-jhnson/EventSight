"""Interactive CLI for the EVTX Security Agent."""

import csv
import os
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.markdown import Markdown
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich import box

from prompt_toolkit import PromptSession
from prompt_toolkit.history import FileHistory
from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
from prompt_toolkit.completion import WordCompleter

from .agent import SecurityAgent, CancelledException
from .models import Verdict, Severity


# Configure console for Windows compatibility - avoid Unicode spinners/braille
# Use safe_box to avoid box-drawing character issues
import sys

# Reconfigure stdout to use UTF-8 if possible
if hasattr(sys.stdout, 'reconfigure'):
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass

console = Console(force_terminal=True, legacy_windows=False, safe_box=True)


def print_banner():
    """Print the welcome banner."""
    banner = """
╔══════════════════════════════════════════════════════════════════╗
║                      EventSight v1.0                             ║
║          Claude-Powered Windows Event Log Analysis               ║
║             By Jonathan Johnson (@JonnyJohnson_)                 ║
║                                                                  ║
║  Type 'help' for available commands                              ║
╚══════════════════════════════════════════════════════════════════╝
    """
    console.print(banner, style="bold cyan")


def parse_filter_file(file_path: str) -> tuple[list[int], dict[int, dict], list[tuple[str, int]]]:
    """
    Parse a CSV filter file containing Event IDs to filter to.

    Supported formats:
        With header: EventType,EventCode,Reason
        Without header: Auto-detects which column contains numeric Event IDs

    The EventType/Provider column is optional. If provided, filtering will match
    events by both provider AND Event ID. Supported provider formats:
        - Full channel name: "Microsoft-Windows-Sysmon/Operational"
        - Provider name: "Microsoft-Windows-Sysmon"
        - Short alias: "Sysmon", "Security", "PowerShell"

    Returns:
        Tuple of:
            - list of event IDs (for backwards compatibility)
            - dict mapping event ID to metadata (for display)
            - list of (provider, event_id) tuples for provider-aware filtering
    """
    event_ids = []
    event_metadata = {}
    provider_filters: list[tuple[str, int]] = []  # (provider, event_id) pairs

    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(f"Filter file not found: {file_path}")

    with open(path, 'r', newline='', encoding='utf-8') as f:
        reader = csv.reader(f)
        rows = list(reader)

    if not rows:
        return event_ids, event_metadata, provider_filters

    first_row = rows[0]
    header_lower = [h.lower().strip() for h in first_row]

    # Check if this is a header row by looking for known column names
    has_header = any(h in header_lower for h in (
        'eventcode', 'event_code', 'eventid', 'event_id', 'code', 'id'
    ))

    code_col = None
    type_col = None
    reason_col = None
    data_start = 0

    if has_header:
        # Find column indices from header
        for i, h in enumerate(header_lower):
            if h in ('eventcode', 'event_code', 'eventid', 'event_id', 'code', 'id'):
                code_col = i
            elif h in ('eventtype', 'event_type', 'type', 'provider', 'channel', 'source'):
                type_col = i
            elif h in ('reason', 'reason_for_collection', 'description'):
                reason_col = i
        data_start = 1  # Skip header row
    else:
        # No header - auto-detect which column has numeric Event IDs
        # Try each column and find the one that parses as integers
        for col_idx in range(len(first_row)):
            try:
                int(first_row[col_idx].strip())
                code_col = col_idx
                break
            except ValueError:
                continue

        if code_col is None:
            raise ValueError("Could not find a column with numeric Event IDs")

        # Assign type and reason columns based on position relative to code_col
        if code_col == 0:
            type_col = None
            reason_col = 1 if len(first_row) > 1 else None
        elif code_col == 1:
            type_col = 0
            reason_col = 2 if len(first_row) > 2 else None
        else:
            type_col = 0
            reason_col = code_col + 1 if len(first_row) > code_col + 1 else None

        data_start = 0  # No header, start from first row

    # Read data rows
    for row in rows[data_start:]:
        if not row or len(row) <= code_col or not row[code_col].strip():
            continue

        try:
            event_id = int(row[code_col].strip())
            event_ids.append(event_id)

            metadata = {}
            provider = None
            if type_col is not None and len(row) > type_col:
                provider = row[type_col].strip()
                metadata['type'] = provider
            if reason_col is not None and len(row) > reason_col:
                metadata['reason'] = row[reason_col].strip()

            # Store provider filter if provider is specified
            if provider:
                provider_filters.append((provider, event_id))

            # Use (provider, event_id) as key if provider specified, else just event_id
            if provider:
                event_metadata[(provider, event_id)] = metadata
            else:
                event_metadata[event_id] = metadata
        except ValueError:
            # Skip rows with invalid event IDs
            continue

    return event_ids, event_metadata, provider_filters


def prompt_filter_choice(console: Console, require_explicit: bool = False) -> tuple[str, Optional[str], Optional[list[int]]]:
    """
    Prompt the user to choose a filtering method.

    Args:
        console: Rich console for output
        require_explicit: If True, only allow manual or file-based filtering (for multi-file analysis)

    Returns:
        Tuple of (choice: str, filter_file_path: Optional[str], event_ids: Optional[list[int]])
        choice is one of: 'smart', 'manual', 'file', 'none'
    """
    console.print("\n[bold cyan]How would you like to filter events?[/bold cyan]")
    if not require_explicit:
        console.print("  [1] Smart filter - Let AI identify security-relevant Event IDs")
    else:
        console.print("  [dim][1] Smart filter - Not available for multi-file analysis[/dim]")
    console.print("  [2] Manual Event IDs - Enter specific Event IDs to analyze")
    console.print("  [3] Load from file - Use a CSV filter file")
    if not require_explicit:
        console.print("  [4] No filter - Analyze all events (may hit rate limits)")
    else:
        console.print("  [dim][4] No filter - Not available for multi-file analysis[/dim]")

    while True:
        try:
            default = "2" if require_explicit else "1"
            choice_input = input(f"\nEnter choice [1-4] (default: {default}): ").strip() or default
            choice_num = int(choice_input)

            if choice_num == 1:
                if require_explicit:
                    console.print("[red]Smart filter is not available for multi-file analysis. Choose option 2 or 3.[/red]")
                    continue
                return ('smart', None, None)

            elif choice_num == 2:
                console.print("\n[dim]Enter Event ID(s) - single ID or comma-separated (e.g., 82 or 1,4688,4624):[/dim]")
                ids_input = input("> ").strip()
                try:
                    event_ids = [int(x.strip()) for x in ids_input.split(',') if x.strip()]
                    if not event_ids:
                        console.print("[red]No valid Event IDs entered. Try again.[/red]")
                        continue
                    return ('manual', None, event_ids)
                except ValueError as e:
                    console.print(f"[red]Invalid format: {e}. Enter numbers only (e.g., 82 or 1,4688,4624).[/red]")
                    continue

            elif choice_num == 3:
                console.print("\n[dim]Enter path to CSV filter file:[/dim]")
                file_path = input("> ").strip().strip('"').strip("'")
                if not Path(file_path).exists():
                    console.print(f"[red]File not found: {file_path}[/red]")
                    continue
                return ('file', file_path, None)

            elif choice_num == 4:
                if require_explicit:
                    console.print("[red]'No filter' is not available for multi-file analysis. Choose option 2 or 3.[/red]")
                    continue
                return ('none', None, None)

            else:
                console.print("[red]Invalid choice. Enter 1, 2, 3, or 4.[/red]")

        except ValueError:
            console.print("[red]Invalid input. Enter a number 1-4.[/red]")


def print_help():
    """Print help information."""
    help_table = Table(title="Available Commands", box=box.ROUNDED)
    help_table.add_column("Command", style="cyan", no_wrap=True)
    help_table.add_column("Description", style="white")
    help_table.add_column("Example", style="dim")

    commands = [
        ("evaluate <file> [options]", "Analyze EVTX file. Options: --batch N, --filter-file FILE, --event-ids IDS, --show-tokens", "evaluate Security.evtx"),
        ("feedback <id> <verdict> <expl> [--event-ids]", "Provide feedback on a finding", 'feedback finding_001 false_positive "EDR" --event-ids 5145'),
        ("correlation add", "Add a new correlation rule (interactive)", "correlation add"),
        ("correlations", "List all correlation rules", "correlations"),
        ("learnings", "List all stored learnings", "learnings"),
        ("search <query>", "Search past learnings", "search MDE injection"),
        ("stats", "Show agent statistics", "stats"),
        ("findings", "Show findings from last analysis", "findings"),
        ("report [file]", "Generate HTML report and open in browser", "report"),
        ("export <file>", "Export last analysis to markdown file", "export report.md"),
        ("edit <id> [--event-ids]", "Edit a learning's insight or Event IDs", "edit learning_001 --event-ids 5145,4663"),
        ("delete <id>", "Delete a learning or correlation rule", "delete learning_20240115_001"),
        ("clear-events [--all]", "Clear stored events from DB", "clear-events --all"),
        ("clear", "Clear the screen", "clear"),
        ("help", "Show this help message", "help"),
        ("exit", "Exit the agent", "exit"),
    ]
    
    for cmd, desc, example in commands:
        help_table.add_row(cmd, desc, example)
    
    console.print(help_table)
    
    console.print("\n[bold]Verdict Options:[/bold]")
    verdicts_table = Table(box=box.SIMPLE)
    verdicts_table.add_column("Verdict", style="yellow")
    verdicts_table.add_column("Use When")
    
    verdicts_table.add_row("false_positive", "The finding is not actually malicious")
    verdicts_table.add_row("true_positive", "The finding is confirmed malicious")
    verdicts_table.add_row("benign", "The activity is expected/normal")
    verdicts_table.add_row("needs_context", "More information is needed")
    
    console.print(verdicts_table)


def format_severity(severity: Severity) -> str:
    """Format severity with color."""
    colors = {
        Severity.CRITICAL: "red bold",
        Severity.HIGH: "red",
        Severity.MEDIUM: "yellow",
        Severity.LOW: "blue",
        Severity.INFO: "dim",
    }
    return f"[{colors.get(severity, 'white')}]{severity.value.upper()}[/]"


def _get_file_display_name(file_path: str) -> str:
    """Extract just the filename(s) from a path string for display.

    Handles both single paths and semicolon-separated multiple paths.
    """
    if ";" in file_path:
        # Multiple files - extract each filename
        paths = [p.strip() for p in file_path.split(";")]
        names = [Path(p).name for p in paths if p]
        return "; ".join(names)
    else:
        return Path(file_path).name


def _get_severity_icon(severity: Severity) -> str:
    """Get icon for severity level."""
    icons = {
        Severity.CRITICAL: "!!!",
        Severity.HIGH: "!!",
        Severity.MEDIUM: "!",
        Severity.LOW: "~",
        Severity.INFO: "i",
    }
    return icons.get(severity, "?")


def display_findings(agent: SecurityAgent):
    """Display findings from the current analysis."""
    if not agent.current_analysis:
        console.print("[yellow]No analysis results available. Run 'evaluate' first.[/yellow]")
        return

    analysis = agent.current_analysis

    # Header
    console.print()
    console.print("[bold white on blue]  EVENTSIGHT SECURITY ANALYSIS  [/bold white on blue]")
    console.print()

    # Summary table
    summary_table = Table(box=None, show_header=False, padding=(0, 2))
    summary_table.add_column("Label", style="dim")
    summary_table.add_column("Value")
    summary_table.add_row("File", f"[white]{_get_file_display_name(analysis.file_path)}[/white]")
    summary_table.add_row("Analyzed", f"[white]{analysis.analyzed_at.strftime('%Y-%m-%d %H:%M:%S')}[/white]")
    summary_table.add_row("Events", f"[white]{analysis.events_analyzed:,}[/white] [dim]of {analysis.total_events:,} total[/dim]")
    console.print(summary_table)
    console.print()

    # Filter to only show Critical, High, Medium findings
    display_findings_list = [
        f for f in analysis.findings
        if f.severity in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM)
    ]
    hidden_count = len(analysis.findings) - len(display_findings_list)

    # Severity breakdown bar
    if analysis.findings:
        console.print("[bold]Findings Overview[/bold]")
        console.print()

        # Create visual severity bar
        bar_parts = []
        if analysis.critical_count:
            bar_parts.append(f"[white on red] {analysis.critical_count} CRITICAL [/white on red]")
        if analysis.high_count:
            bar_parts.append(f"[white on dark_red] {analysis.high_count} HIGH [/white on dark_red]")
        if analysis.medium_count:
            bar_parts.append(f"[black on yellow] {analysis.medium_count} MEDIUM [/black on yellow]")

        if bar_parts:
            console.print("  " + " ".join(bar_parts))
        if hidden_count > 0:
            console.print(f"  [dim]({hidden_count} low/info findings hidden)[/dim]")
        console.print()

    # Summary text
    if analysis.summary:
        console.print(f"[dim]{analysis.summary}[/dim]")
        console.print()

    if not display_findings_list:
        if hidden_count > 0:
            console.print(f"[green]No critical/high/medium findings. {hidden_count} low-priority findings hidden.[/green]")
        else:
            console.print("[bold green]No suspicious activity detected.[/bold green]")
        return

    # Findings
    console.print("[bold]Detailed Findings[/bold]")
    console.print()

    for i, finding in enumerate(display_findings_list):
        severity_styles = {
            Severity.CRITICAL: ("red bold", "white on red"),
            Severity.HIGH: ("red", "white on dark_red"),
            Severity.MEDIUM: ("yellow", "black on yellow"),
            Severity.LOW: ("blue", "white on blue"),
            Severity.INFO: ("dim", "white on grey37"),
        }
        text_style, badge_style = severity_styles.get(finding.severity, ("white", "white on grey37"))

        # Get timestamp from related events
        timestamp_str = ""
        if finding.related_events:
            ts = finding.related_events[0].get("timestamp", "")
            if ts:
                try:
                    from datetime import datetime as dt
                    parsed = dt.fromisoformat(ts.replace("Z", "+00:00"))
                    timestamp_str = parsed.strftime("%Y-%m-%d %H:%M:%S")
                except Exception:
                    timestamp_str = ts[:19] if len(ts) >= 19 else ts

        # Finding header with severity badge, instance count, and timestamp
        severity_badge = f"[{badge_style}] {finding.severity.value.upper()} [/{badge_style}]"
        instance_count = finding.instance_count
        instance_badge = f" [magenta]({instance_count} occurrences)[/magenta]" if instance_count > 1 else ""

        if timestamp_str:
            console.print(f"  {severity_badge} [bold]{finding.title}[/bold]{instance_badge}  [dim]{timestamp_str}[/dim]")
        else:
            console.print(f"  {severity_badge} [bold]{finding.title}[/bold]{instance_badge}")

        # Metadata line
        meta_parts = [f"[dim]ID: {finding.id}[/dim]"]
        if finding.technique:
            meta_parts.append(f"[cyan]{finding.technique}[/cyan]")
        if finding.tactic:
            meta_parts.append(f"[dim]{finding.tactic}[/dim]")
        meta_parts.append(f"[dim]Confidence: {finding.confidence:.0%}[/dim]")
        console.print(f"  {' | '.join(meta_parts)}")
        console.print()

        # Description in a subtle box
        desc_lines = finding.description.split('\n')
        for line in desc_lines:
            console.print(f"    {line}")
        console.print()

        # Related events
        related_event_ids = sorted(set(
            e.get('event_id') for e in finding.related_events if e.get('event_id')
        ))
        if related_event_ids:
            event_tags = " ".join(f"[dim on grey15] {eid} [/dim on grey15]" for eid in related_event_ids)
            console.print(f"    [dim]Event IDs:[/dim] {event_tags}")
            console.print()

        # Recommendation
        console.print(f"    [green]>[/green] [italic]{finding.recommendation}[/italic]")

        # Security context in compact grid
        if finding.security_context:
            sc = finding.security_context
            context_items = []

            if sc.process_name:
                context_items.append(("Process", sc.process_name + (f" (PID {sc.process_id})" if sc.process_id else "")))
            if sc.process_command_line:
                cmd = sc.process_command_line[:60] + "..." if len(sc.process_command_line) > 60 else sc.process_command_line
                context_items.append(("Command", cmd))
            if sc.parent_process_name:
                context_items.append(("Parent", sc.parent_process_name + (f" (PID {sc.parent_process_id})" if sc.parent_process_id else "")))
            if sc.user_name:
                user = f"{sc.user_domain}\\{sc.user_name}" if sc.user_domain else sc.user_name
                context_items.append(("User", user))
            if sc.logon_type:
                logon_types = {2: "Interactive", 3: "Network", 4: "Batch", 5: "Service", 7: "Unlock", 10: "RemoteInteractive"}
                context_items.append(("Logon Type", f"{sc.logon_type} ({logon_types.get(sc.logon_type, 'Other')})"))
            if sc.source_ip:
                src = sc.source_ip + (f":{sc.source_port}" if sc.source_port else "")
                context_items.append(("Source IP", src))
            if sc.target_filename:
                context_items.append(("File", sc.target_filename))
            if sc.registry_key:
                context_items.append(("Registry", sc.registry_key))
            if sc.service_name:
                context_items.append(("Service", sc.service_name))
            if sc.assembly_name:
                context_items.append(("Assembly", sc.assembly_name))

            if context_items:
                console.print()
                console.print("    [dim]Context:[/dim]")
                for label, value in context_items:
                    console.print(f"      [cyan]{label}:[/cyan] {value}")

        # Matched correlation rules
        if finding.matched_correlations:
            console.print()
            console.print("    [dim]Matched Correlation Rules:[/dim]")
            for mc in finding.matched_correlations:
                rule_info = f"[magenta]{mc.rule_name}[/magenta]"
                if mc.source_field == mc.target_field:
                    field_info = f"Event {mc.source_event_id} → {mc.target_event_id} via {mc.source_field}"
                else:
                    field_info = f"Event {mc.source_event_id} → {mc.target_event_id} via {mc.source_field}→{mc.target_field}"
                if mc.matched_value:
                    field_info += f" = '{mc.matched_value}'"
                console.print(f"      {rule_info}: [dim]{field_info}[/dim]")

        # Multiple instances (merged findings)
        if finding.instances and len(finding.instances) > 1:
            console.print()
            console.print(f"    [bold magenta]Occurrences ({len(finding.instances)} total):[/bold magenta]")
            for idx, instance in enumerate(finding.instances[:10], 1):  # Show first 10
                ts_str = instance.timestamp.strftime("%Y-%m-%d %H:%M:%S")
                detail = instance.instance_detail or "No details"
                # Truncate long details
                if len(detail) > 80:
                    detail = detail[:77] + "..."
                console.print(f"      [dim]{idx}.[/dim] [{ts_str}] {detail}")
            if len(finding.instances) > 10:
                console.print(f"      [dim]... and {len(finding.instances) - 10} more occurrences[/dim]")

        # Separator
        if i < len(display_findings_list) - 1:
            console.print()
            console.print("  [dim]" + "─" * 68 + "[/dim]")
            console.print()

    console.print()
    console.print("[dim]Use 'report' to generate an HTML report, or 'export <file>' for markdown.[/dim]")


def display_learnings(agent: SecurityAgent):
    """Display all stored learnings."""
    learnings = agent.get_learnings(limit=20)

    if not learnings:
        console.print("[yellow]No learnings stored yet. Provide feedback on findings to build knowledge.[/yellow]")
        return

    table = Table(title=f"Stored Learnings ({len(learnings)} shown)", box=box.ROUNDED)
    table.add_column("ID", style="cyan", no_wrap=True)
    table.add_column("Type", style="yellow", max_width=15)
    table.add_column("Event IDs", style="magenta", max_width=15)
    table.add_column("Insight", style="white")
    table.add_column("Applied", justify="right", style="green")

    for learning in learnings:
        event_ids_str = ",".join(str(eid) for eid in learning.event_ids) if learning.event_ids else "-"
        table.add_row(
            learning.id,
            learning.type.value,
            event_ids_str,
            learning.insight,
            str(learning.times_applied)
        )

    console.print(table)


def display_correlation_rules(agent: SecurityAgent):
    """Display all stored correlation rules."""
    rules = agent.get_correlation_rules(limit=20)

    if not rules:
        console.print("[yellow]No correlation rules defined yet. Use 'correlation add' to create one.[/yellow]")
        return

    table = Table(title=f"Correlation Rules ({len(rules)} shown)", box=box.ROUNDED)
    table.add_column("ID", style="cyan", no_wrap=True)
    table.add_column("Name", style="white", max_width=30)
    table.add_column("Pattern", style="yellow", max_width=35)
    table.add_column("Severity", style="red", max_width=10)
    table.add_column("Applied", justify="right", style="green")

    for rule in rules:
        # Build pattern description using the model's formatter
        conditions = ""
        if rule.source_conditions:
            conds = ", ".join(
                rule._format_condition(k, v)
                for k, v in rule.source_conditions.items()
            )
            conditions = f" ({conds})"

        # Format field correlation
        if rule.source_field == rule.target_field:
            field_str = rule.source_field
        else:
            field_str = f"{rule.source_field}->{rule.target_field}"

        pattern = f"{rule.source_event_id}{conditions} -> {rule.target_event_id} via {field_str}"

        # Truncate pattern if too long
        if len(pattern) > 35:
            pattern = pattern[:32] + "..."

        table.add_row(
            rule.id[:25],
            rule.name[:30] if len(rule.name) > 30 else rule.name,
            pattern,
            rule.severity_hint.value.upper(),
            str(rule.times_applied)
        )

    console.print(table)

    # Show one detailed example if there are rules
    if rules:
        console.print("\n[dim]Use 'delete <rule_id>' to remove a rule[/dim]")


def parse_conditions(conditions_str: str) -> dict:
    """
    Parse condition string into structured format.

    Supports:
        field=value              -> {"field": "value"} (equals)
        field contains value     -> {"field": {"op": "contains", "value": "value"}}
        field starts_with value  -> {"field": {"op": "starts_with", "value": "value"}}
        field ends_with value    -> {"field": {"op": "ends_with", "value": "value"}}
        field != value           -> {"field": {"op": "not_equals", "value": "value"}}
        field not_contains value -> {"field": {"op": "not_contains", "value": "value"}}
    """
    conditions = {}
    if not conditions_str.strip():
        return conditions

    # Split by comma, but be careful with values that might contain commas
    parts = [p.strip() for p in conditions_str.split(',')]

    for part in parts:
        if not part:
            continue

        # Check for operators (order matters - check longer patterns first)
        if ' not_contains ' in part.lower():
            idx = part.lower().index(' not_contains ')
            field = part[:idx].strip()
            value = part[idx + 14:].strip()
            conditions[field] = {"op": "not_contains", "value": value}
        elif ' contains ' in part.lower():
            idx = part.lower().index(' contains ')
            field = part[:idx].strip()
            value = part[idx + 10:].strip()
            conditions[field] = {"op": "contains", "value": value}
        elif ' starts_with ' in part.lower():
            idx = part.lower().index(' starts_with ')
            field = part[:idx].strip()
            value = part[idx + 13:].strip()
            conditions[field] = {"op": "starts_with", "value": value}
        elif ' ends_with ' in part.lower():
            idx = part.lower().index(' ends_with ')
            field = part[:idx].strip()
            value = part[idx + 11:].strip()
            conditions[field] = {"op": "ends_with", "value": value}
        elif '!=' in part:
            field, value = part.split('!=', 1)
            conditions[field.strip()] = {"op": "not_equals", "value": value.strip()}
        elif '=' in part:
            field, value = part.split('=', 1)
            conditions[field.strip()] = value.strip()
        else:
            raise ValueError(f"Invalid condition format: {part}")

    return conditions


def prompt_correlation_rule(console: Console) -> dict:
    """Interactive prompt to create a correlation rule."""
    console.print("\n[bold cyan]Create a Correlation Rule[/bold cyan]")
    console.print("[dim]Define how two event types should be correlated for security analysis[/dim]\n")

    # Source event
    console.print("[bold]Source Event (the event that starts the correlation):[/bold]")
    source_event_id = input("  Event ID (e.g., 4624): ").strip()
    try:
        source_event_id = int(source_event_id)
    except ValueError:
        raise ValueError(f"Invalid Event ID: {source_event_id}")

    console.print("  [dim]Optional: Add conditions for the source event[/dim]")
    console.print("  [dim]Formats: field=value, field contains value, field starts_with value[/dim]")
    console.print("  [dim]Example: LogonType=3, FullyQualifiedAssemblyName contains Rubeus[/dim]")
    source_conditions_str = input("  Conditions (comma-separated, or blank): ").strip()
    source_conditions = parse_conditions(source_conditions_str)

    # Target event
    console.print("\n[bold]Target Event (the event to correlate to):[/bold]")
    target_event_id = input("  Event ID (e.g., 4688): ").strip()
    try:
        target_event_id = int(target_event_id)
    except ValueError:
        raise ValueError(f"Invalid Event ID: {target_event_id}")

    console.print("  [dim]Optional: Add conditions for the target event[/dim]")
    console.print("  [dim]Formats: field=value, field contains value, field starts_with value[/dim]")
    target_conditions_str = input("  Conditions (comma-separated, or blank): ").strip()
    target_conditions = parse_conditions(target_conditions_str)

    # Correlation fields
    console.print("\n[bold]Correlation Fields:[/bold]")
    console.print("  [dim]The fields that link these events together.[/dim]")
    console.print("  [dim]These can be different field names (e.g., TargetLogonId -> SubjectLogonId)[/dim]")
    console.print("  [dim]Examples: TargetLogonId/SubjectLogonId, NewProcessId/ProcessId[/dim]")

    source_field = input("  Source event field (e.g., TargetLogonId): ").strip()
    if not source_field:
        raise ValueError("Source field is required")

    target_field_input = input(f"  Target event field (default: {source_field}): ").strip()
    target_field = target_field_input if target_field_input else source_field

    # Metadata
    console.print("\n[bold]Rule Metadata:[/bold]")
    name = input("  Rule name (e.g., 'Network Logon to Process Execution'): ").strip()
    if not name:
        name = f"Event {source_event_id} to {target_event_id} correlation"

    field_desc = source_field if source_field == target_field else f"{source_field} -> {target_field}"
    description = input("  Description (what this correlation represents): ").strip()
    if not description:
        description = f"Correlates Event {source_event_id} to Event {target_event_id} via {field_desc}"

    console.print("\n[bold]Security Context:[/bold]")
    console.print("  [dim]Explain why this correlation is security-relevant[/dim]")
    security_context = input("  Security context: ").strip()
    if not security_context:
        security_context = "This correlation may indicate suspicious activity"

    # Severity
    console.print("\n[bold]Severity Hint:[/bold]")
    console.print("  [1] Critical  [2] High  [3] Medium  [4] Low  [5] Info")
    severity_choice = input("  Choice [1-5] (default: 3): ").strip() or "3"
    severity_map = {"1": "critical", "2": "high", "3": "medium", "4": "low", "5": "info"}
    severity = Severity(severity_map.get(severity_choice, "medium"))

    # MITRE ATT&CK
    console.print("\n[bold]MITRE ATT&CK (optional):[/bold]")
    technique = input("  Technique ID (e.g., T1021): ").strip() or None
    tactic = input("  Tactic (e.g., Lateral Movement): ").strip() or None

    return {
        "source_event_id": source_event_id,
        "source_conditions": source_conditions,
        "target_event_id": target_event_id,
        "target_conditions": target_conditions,
        "source_field": source_field,
        "target_field": target_field,
        "name": name,
        "description": description,
        "security_context": security_context,
        "severity_hint": severity,
        "technique": technique,
        "tactic": tactic
    }


def display_stats(agent: SecurityAgent):
    """Display agent statistics."""
    stats = agent.get_stats()

    stored_events = stats.get('total_stored_events', 0)
    stored_events_str = f"{stored_events:,}" if stored_events > 0 else "None"
    using_vectors = stats.get('using_vectors', False)
    search_mode = "Vector (semantic)" if using_vectors else "Keyword"

    stats_text = f"""
## Agent Statistics

**Model:** {stats['model']}
**Total Learnings:** {stats['total_learnings']}
**Total Correlation Rules:** {stats.get('total_correlation_rules', 0)}
**Stored Events:** {stored_events_str}
**Search Mode:** {search_mode}
**Current Analysis:** {stats['current_analysis'] or 'None'}

### Learnings by Type
"""

    for type_name, count in stats.get('by_type', {}).items():
        stats_text += f"- {type_name}: {count}\n"

    if stats.get('most_applied'):
        stats_text += "\n### Most Applied Learnings\n"
        for insight, count in stats['most_applied']:
            stats_text += f"- ({count}x) {insight}...\n"

    console.print(Panel(Markdown(stats_text), title="Statistics", border_style="blue"))


def run_interactive(agent: SecurityAgent):
    """Run the interactive CLI loop."""
    print_banner()
    
    # Set up command completion
    commands = ['evaluate', 'feedback', 'correlation', 'correlations', 'learnings',
                'search', 'stats', 'findings', 'report', 'export', 'delete',
                'clear-events', 'clear', 'help', 'exit']
    completer = WordCompleter(commands, ignore_case=True)
    
    # Set up history
    history_file = Path.home() / ".eventsight_history"
    session = PromptSession(
        history=FileHistory(str(history_file)),
        auto_suggest=AutoSuggestFromHistory(),
        completer=completer
    )
    
    while True:
        try:
            # Get input
            user_input = session.prompt("agent> ").strip()
            
            if not user_input:
                continue
            
            # Parse command
            parts = user_input.split(maxsplit=1)
            command = parts[0].lower()
            args = parts[1] if len(parts) > 1 else ""
            
            # Handle commands
            if command == "exit" or command == "quit":
                console.print("[cyan]Goodbye![/cyan]")
                break
            
            elif command == "help":
                print_help()
            
            elif command == "clear":
                os.system('cls' if os.name == 'nt' else 'clear')
                print_banner()
            
            elif command == "evaluate":
                if not args:
                    console.print("[red]Usage: evaluate <file_path> [--batch N] [--show-tokens][/red]")
                    continue

                args_clean = args

                # Check for --batch N flag
                batch_size = None
                batch_match = re.search(r'--batch\s+(\d+)', args_clean)
                if batch_match:
                    batch_size = int(batch_match.group(1))
                    args_clean = re.sub(r'--batch\s+\d+', '', args_clean)

                # Check for --filter-file flag
                filter_file = None
                filter_file_match = re.search(r'--filter-file\s+("[^"]+"|\'[^\']+\'|\S+)', args_clean)
                if filter_file_match:
                    filter_file = filter_file_match.group(1).strip('"').strip("'")
                    args_clean = re.sub(r'--filter-file\s+("[^"]+"|\'[^\']+\'|\S+)', '', args_clean)

                # Check for --event-ids flag
                event_ids_arg = None
                event_ids_match = re.search(r'--event-ids\s+(\S+)', args_clean)
                if event_ids_match:
                    event_ids_arg = event_ids_match.group(1)
                    args_clean = re.sub(r'--event-ids\s+\S+', '', args_clean)

                # Check for --continuous flag
                continuous_mode = '--continuous' in args_clean
                args_clean = args_clean.replace('--continuous', '')

                # Check for --interval flag
                interval = 60  # default
                interval_match = re.search(r'--interval\s+(\d+)', args_clean)
                if interval_match:
                    interval = int(interval_match.group(1))
                    args_clean = re.sub(r'--interval\s+\d+', '', args_clean)

                # Check for --show-tokens flag
                show_tokens = '--show-tokens' in args_clean
                args_clean = args_clean.replace('--show-tokens', '')

                # Parse file paths - support multiple files separated by spaces
                # Handle quoted paths with spaces
                file_paths_str = args_clean.strip()
                file_paths = []

                # Parse quoted and unquoted paths
                # Use shlex with posix=False to preserve backslashes on Windows
                import shlex
                try:
                    lexer = shlex.shlex(file_paths_str, posix=False)
                    lexer.whitespace_split = True
                    lexer.whitespace = ' \t'
                    path_parts = list(lexer)
                except ValueError:
                    path_parts = file_paths_str.split()

                for part in path_parts:
                    # Remove surrounding quotes if present
                    part = part.strip().strip('"').strip("'")
                    if not part:
                        continue
                    if Path(part).exists():
                        file_paths.append(part)
                    elif continuous_mode:
                        # In continuous mode, allow channel names that don't exist as files
                        file_paths.append(part)
                    else:
                        console.print(f"[red]File not found: {part}[/red]")

                if not file_paths:
                    console.print("[red]No valid files or channels provided.[/red]")
                    continue

                is_multi_file = len(file_paths) > 1

                # Continuous mode validation
                if continuous_mode:
                    if is_multi_file:
                        console.print("[red]Error: Continuous mode only supports a single file or channel.[/red]")
                        continue
                    if not filter_file and not event_ids_arg:
                        console.print("[red]Error: Continuous mode requires --filter-file or --event-ids.[/red]")
                        console.print("[dim]Example: evaluate Security --continuous --filter-file events.csv[/dim]")
                        continue

                file_path = file_paths if is_multi_file else file_paths[0]

                if is_multi_file:
                    console.print(f"[cyan]Analyzing {len(file_paths)} files together for cross-file correlation...[/cyan]")
                    for fp in file_paths:
                        console.print(f"  [dim]- {fp}[/dim]")

                if batch_size:
                    console.print(f"[cyan]Using batch size of {batch_size} events[/cyan]")

                # Determine filtering method
                smart_filter = True if not is_multi_file else False
                filter_relevant = True
                filter_event_ids = None
                filter_metadata = None
                provider_filters = None

                # If explicit flags provided, use them
                if filter_file:
                    try:
                        filter_event_ids, filter_metadata, provider_filters = parse_filter_file(filter_file)
                        smart_filter = False
                        if provider_filters:
                            console.print(f"[cyan]Loaded {len(provider_filters)} provider-specific Event IDs from filter file[/cyan]")
                        else:
                            console.print(f"[cyan]Loaded {len(filter_event_ids)} Event IDs from filter file[/cyan]")
                    except Exception as e:
                        console.print(f"[red]Error loading filter file: {e}[/red]")
                        continue
                elif event_ids_arg:
                    try:
                        filter_event_ids = [int(x.strip()) for x in event_ids_arg.split(',') if x.strip()]
                        if not filter_event_ids:
                            console.print("[red]No valid Event IDs provided.[/red]")
                            continue
                        smart_filter = False
                        console.print(f"[cyan]Filtering to Event IDs: {filter_event_ids}[/cyan]")
                    except ValueError as e:
                        console.print(f"[red]Invalid event IDs format: {e}. Use numbers only (e.g., --event-ids 82 or --event-ids 1,4688,4624).[/red]")
                        continue
                else:
                    # For multi-file analysis, require explicit filtering
                    if is_multi_file:
                        console.print("[yellow]Multi-file analysis requires explicit Event ID filtering.[/yellow]")
                        console.print("[dim]Use --event-ids or --filter-file, or enter Event IDs manually.[/dim]")

                    # Prompt user for filter choice
                    try:
                        choice, filter_path, manual_ids = prompt_filter_choice(console, require_explicit=is_multi_file)

                        if choice == 'smart':
                            if is_multi_file:
                                console.print("[red]Smart filtering is not available for multi-file analysis.[/red]")
                                continue
                            smart_filter = True
                        elif choice == 'manual':
                            filter_event_ids = manual_ids
                            smart_filter = False
                            console.print(f"[cyan]Filtering to Event IDs: {filter_event_ids}[/cyan]")
                        elif choice == 'file':
                            filter_event_ids, filter_metadata, provider_filters = parse_filter_file(filter_path)
                            smart_filter = False
                            if provider_filters:
                                console.print(f"[cyan]Loaded {len(provider_filters)} provider-specific Event IDs from filter file[/cyan]")
                            else:
                                console.print(f"[cyan]Loaded {len(filter_event_ids)} Event IDs from filter file[/cyan]")
                            if filter_metadata:
                                # Show what we loaded
                                shown = 0
                                for key, meta in list(filter_metadata.items())[:5]:
                                    reason = meta.get('reason', '')[:50]
                                    if isinstance(key, tuple):
                                        provider, eid = key
                                        label = f"{provider} Event {eid}"
                                    else:
                                        label = f"Event {key}"
                                    console.print(f"  [dim]{label}: {reason}...[/dim]" if len(reason) == 50 else f"  [dim]{label}: {reason}[/dim]")
                                    shown += 1
                                if len(filter_metadata) > 5:
                                    console.print(f"  [dim]... and {len(filter_metadata) - 5} more[/dim]")
                        elif choice == 'none':
                            if is_multi_file:
                                console.print("[red]'No filter' is not available for multi-file analysis. Please specify Event IDs.[/red]")
                                continue
                            smart_filter = False
                            filter_relevant = False
                    except KeyboardInterrupt:
                        console.print("\n[yellow]Cancelled.[/yellow]")
                        continue

                # Handle continuous mode
                if continuous_mode:
                    # Build filter set
                    if filter_event_ids:
                        filter_set = set(filter_event_ids)
                    else:
                        filter_set = set()

                    effective_batch_size = batch_size if batch_size else 50

                    # Default report path for continuous mode (absolute path)
                    report_path = str(Path.cwd() / "eventsight_report.html")

                    console.print(f"[cyan]Starting continuous analysis...[/cyan]")
                    console.print(f"[dim]Press Ctrl+C to stop[/dim]")
                    try:
                        agent.analyze_continuous(
                            file_path=file_path,
                            filter_event_ids=filter_set,
                            interval=interval,
                            batch_size=effective_batch_size,
                            report_path=report_path
                        )
                    except KeyboardInterrupt:
                        # User pressed Ctrl+C - cancel the agent
                        agent.cancel()
                        console.print("\n[yellow]Stopped continuous analysis.[/yellow]")
                    except CancelledException:
                        console.print("\n[yellow]Continuous analysis cancelled.[/yellow]")
                    continue

                # Standard one-shot analysis
                with Progress(
                    SpinnerColumn(),
                    TextColumn("[progress.description]{task.description}"),
                    console=console
                ) as progress:
                    progress.add_task("Analyzing events...", total=None)
                    try:
                        result = agent.evaluate_evtx(
                            file_path,
                            batch_size=batch_size,
                            smart_filter=smart_filter,
                            filter_relevant=filter_relevant,
                            filter_event_ids=filter_event_ids,
                            filter_metadata=filter_metadata,
                            provider_filters=provider_filters,
                            show_tokens=show_tokens
                        )
                        display_findings(agent)
                    except KeyboardInterrupt:
                        # User pressed Ctrl+C - cancel the agent and stop gracefully
                        agent.cancel()
                        console.print("\n[yellow]Analysis cancelled by user.[/yellow]")
                    except CancelledException:
                        # Analysis was cancelled via the cancel() method
                        console.print("\n[yellow]Analysis cancelled.[/yellow]")
                    except Exception as e:
                        console.print(f"[red]Error: {e}[/red]")
            
            elif command == "findings":
                display_findings(agent)
            
            elif command == "feedback":
                # Parse: feedback <finding_id> <verdict> <explanation> [--event-ids 5145,4663]
                # Check for --event-ids flag first
                event_ids_override = None
                if "--event-ids" in args:
                    # Extract --event-ids value
                    match = re.search(r'--event-ids\s+([0-9,]+)', args)
                    if match:
                        try:
                            event_ids_override = [int(eid.strip()) for eid in match.group(1).split(",") if eid.strip()]
                        except ValueError:
                            console.print("[red]Invalid Event IDs format. Use: --event-ids 5145,4663[/red]")
                            continue
                    # Remove --event-ids from args for further parsing
                    args = re.sub(r'--event-ids\s+[0-9,]+', '', args).strip()

                feedback_parts = args.split(maxsplit=2)
                if len(feedback_parts) < 3:
                    console.print("[red]Usage: feedback <finding_id> <verdict> <explanation> [--event-ids 5145,4663][/red]")
                    console.print("[dim]Verdicts: false_positive, true_positive, benign, needs_context[/dim]")
                    continue

                finding_id = feedback_parts[0]
                verdict_str = feedback_parts[1]
                explanation = feedback_parts[2].strip('"').strip("'")

                try:
                    verdict = Verdict(verdict_str)
                except ValueError:
                    console.print(f"[red]Invalid verdict: {verdict_str}[/red]")
                    console.print("[dim]Valid options: false_positive, true_positive, benign, needs_context[/dim]")
                    continue

                with Progress(
                    SpinnerColumn(),
                    TextColumn("[progress.description]{task.description}"),
                    console=console
                ) as progress:
                    progress.add_task("Learning from feedback...", total=None)
                    try:
                        learning = agent.add_feedback(finding_id, verdict, explanation, event_ids_override)
                    except KeyboardInterrupt:
                        agent.cancel()
                        console.print("\n[yellow]Feedback cancelled by user.[/yellow]")
                        continue
                    except CancelledException:
                        console.print("\n[yellow]Feedback cancelled.[/yellow]")
                        continue

                # Show Event IDs in the output
                event_ids_str = ", ".join(str(eid) for eid in learning.event_ids) if learning.event_ids else "(none - will use vector search)"
                console.print(Panel(
                    f"[green]Learning recorded![/green]\n\n**Insight:** {learning.insight}\n\n**Keywords:** {', '.join(learning.keywords[:10])}\n\n**Event IDs:** {event_ids_str}",
                    title="New Learning",
                    border_style="green"
                ))
            
            elif command == "learnings":
                display_learnings(agent)

            elif command == "correlations":
                display_correlation_rules(agent)

            elif command == "correlation":
                if args.strip().lower() == "add":
                    try:
                        rule_data = prompt_correlation_rule(console)
                        rule = agent.add_correlation_rule(**rule_data)
                        field_str = rule.source_field if rule.source_field == rule.target_field else f"{rule.source_field} -> {rule.target_field}"
                        console.print(Panel(
                            f"[green]Correlation rule created![/green]\n\n"
                            f"**ID:** {rule.id}\n"
                            f"**Name:** {rule.name}\n"
                            f"**Pattern:** Event {rule.source_event_id} -> Event {rule.target_event_id} via {field_str}\n"
                            f"**Context:** {rule.security_context}",
                            title="New Correlation Rule",
                            border_style="green"
                        ))
                    except ValueError as e:
                        console.print(f"[red]Error: {e}[/red]")
                    except KeyboardInterrupt:
                        console.print("\n[yellow]Cancelled.[/yellow]")
                else:
                    console.print("[red]Usage: correlation add[/red]")
                    console.print("[dim]Use 'correlations' to list existing rules[/dim]")

            elif command == "search":
                if not args:
                    console.print("[red]Usage: search <query>[/red]")
                    continue
                
                results = agent.search_learnings(args)
                
                if not results:
                    console.print("[yellow]No matching learnings found.[/yellow]")
                    continue
                
                table = Table(title=f"Search Results for '{args}'", box=box.ROUNDED)
                table.add_column("ID", style="cyan")
                table.add_column("Insight", style="white")
                
                for learning in results[:10]:
                    table.add_row(learning.id, learning.insight)
                
                console.print(table)
            
            elif command == "stats":
                display_stats(agent)
            
            elif command == "delete":
                if not args:
                    console.print("[red]Usage: delete <id>[/red]")
                    console.print("[dim]Works for both learning IDs and correlation rule IDs[/dim]")
                    continue

                item_id = args.strip()
                # Try to delete as correlation rule first (if ID starts with corr_)
                if item_id.startswith("corr_"):
                    if agent.delete_correlation_rule(item_id):
                        console.print(f"[green]Deleted correlation rule: {item_id}[/green]")
                    else:
                        console.print(f"[red]Correlation rule not found: {item_id}[/red]")
                # Try to delete as learning
                elif agent.delete_learning(item_id):
                    console.print(f"[green]Deleted learning: {item_id}[/green]")
                # Try correlation rule as fallback
                elif agent.delete_correlation_rule(item_id):
                    console.print(f"[green]Deleted correlation rule: {item_id}[/green]")
                else:
                    console.print(f"[red]Item not found: {item_id}[/red]")

            elif command == "edit":
                if not args:
                    console.print("[red]Usage: edit <learning_id> [--event-ids 5145,4663][/red]")
                    continue

                # Parse args for --event-ids flag
                parts = args.split()
                learning_id = parts[0]
                event_ids_arg = None

                # Check for --event-ids flag
                for i, part in enumerate(parts):
                    if part == "--event-ids" and i + 1 < len(parts):
                        event_ids_arg = parts[i + 1]
                        break

                learning = agent.get_learning(learning_id)

                if not learning:
                    console.print(f"[red]Learning not found: {learning_id}[/red]")
                    continue

                # If --event-ids provided, just update Event IDs
                if event_ids_arg:
                    try:
                        # Parse and validate Event IDs
                        new_event_ids = [int(eid.strip()) for eid in event_ids_arg.split(",") if eid.strip()]
                        if agent.update_learning_event_ids(learning_id, new_event_ids):
                            console.print(f"[green]Updated Event IDs for {learning_id}: {new_event_ids}[/green]")
                        else:
                            console.print(f"[red]Failed to update Event IDs.[/red]")
                    except ValueError:
                        console.print("[red]Invalid Event IDs. Use comma-separated numbers: --event-ids 5145,4663[/red]")
                    continue

                # Show current learning details
                console.print(f"\n[bold]Current insight:[/bold]")
                console.print(f"  {learning.insight}")
                event_ids_str = ",".join(str(eid) for eid in learning.event_ids) if learning.event_ids else "(none)"
                console.print(f"\n[bold]Current Event IDs:[/bold] {event_ids_str}")
                console.print()

                # Prompt for what to edit
                console.print("[cyan]What would you like to edit?[/cyan]")
                console.print("  1) Insight text")
                console.print("  2) Event IDs")
                console.print("  3) Cancel")

                try:
                    choice = input("> ").strip()

                    if choice == "1":
                        console.print("[cyan]Enter new insight:[/cyan]")
                        new_insight = input("> ")
                        if not new_insight.strip():
                            console.print("[yellow]Edit cancelled.[/yellow]")
                            continue
                        if agent.update_learning(learning_id, new_insight.strip()):
                            console.print(f"[green]Updated insight for: {learning_id}[/green]")
                        else:
                            console.print(f"[red]Failed to update learning.[/red]")

                    elif choice == "2":
                        console.print("[cyan]Enter Event IDs (comma-separated, e.g., 5145,4663):[/cyan]")
                        event_ids_input = input("> ")
                        if not event_ids_input.strip():
                            console.print("[yellow]Edit cancelled.[/yellow]")
                            continue
                        try:
                            new_event_ids = [int(eid.strip()) for eid in event_ids_input.split(",") if eid.strip()]
                            if agent.update_learning_event_ids(learning_id, new_event_ids):
                                console.print(f"[green]Updated Event IDs for {learning_id}: {new_event_ids}[/green]")
                            else:
                                console.print(f"[red]Failed to update Event IDs.[/red]")
                        except ValueError:
                            console.print("[red]Invalid Event IDs. Use comma-separated numbers.[/red]")

                    else:
                        console.print("[yellow]Edit cancelled.[/yellow]")

                except KeyboardInterrupt:
                    console.print("\n[yellow]Edit cancelled.[/yellow]")
                    continue

            elif command == "clear-events":
                # Check for --all flag
                clear_all = "--all" in args

                if clear_all:
                    # Confirm before clearing all events
                    count = agent.get_events_count()
                    if count == 0:
                        console.print("[yellow]No stored events to clear.[/yellow]")
                        continue

                    console.print(f"[yellow]This will delete ALL {count:,} stored events from the database.[/yellow]")
                    confirm = input("Are you sure? (yes/no): ").strip().lower()

                    if confirm == "yes":
                        deleted = agent.clear_events()
                        console.print(f"[green]Cleared {deleted:,} events from database.[/green]")
                    else:
                        console.print("[dim]Cancelled.[/dim]")
                else:
                    # Clear events for current analysis only
                    if not agent.current_analysis:
                        console.print("[yellow]No current analysis. Use 'clear-events --all' to clear all stored events.[/yellow]")
                        continue

                    analysis_id = agent.current_analysis.id
                    count = agent.get_events_count(analysis_id)

                    if count == 0:
                        console.print(f"[yellow]No stored events for analysis {analysis_id}.[/yellow]")
                        continue

                    deleted = agent.clear_events(analysis_id)
                    console.print(f"[green]Cleared {deleted:,} events for analysis {analysis_id}.[/green]")

            elif command == "export":
                if not agent.current_analysis:
                    console.print("[yellow]No analysis to export. Run 'evaluate' first.[/yellow]")
                    continue

                filename = args.strip() or f"analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"

                export_analysis(agent.current_analysis, filename, agent.config.confidence_threshold)
                console.print(f"[green]Exported to {filename}[/green]")

            elif command == "report":
                if not agent.current_analysis:
                    console.print("[yellow]No analysis to report. Run 'evaluate' first.[/yellow]")
                    continue

                filename = args.strip() or f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
                if not filename.endswith('.html'):
                    filename += '.html'

                report_path = generate_html_report(agent.current_analysis, filename, agent.config.confidence_threshold)
                abs_path = os.path.abspath(report_path)

                console.print(f"[green]HTML report generated: {abs_path}[/green]")

                # Try to open in browser
                try:
                    import webbrowser
                    webbrowser.open(f'file://{abs_path}')
                    console.print("[dim]Opening in browser...[/dim]")
                except Exception:
                    console.print(f"[dim]Open the file in your browser to view the report.[/dim]")

            else:
                console.print(f"[red]Unknown command: {command}[/red]")
                console.print("[dim]Type 'help' for available commands[/dim]")
        
        except KeyboardInterrupt:
            console.print("\n[dim]Use 'exit' to quit[/dim]")
            continue
        except EOFError:
            break
        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")


def export_analysis(analysis, filename: str, confidence_threshold: Severity = Severity.MEDIUM):
    """Export analysis results to a markdown file.

    Args:
        analysis: The analysis result to export
        filename: Output filename
        confidence_threshold: Minimum severity to include (default: MEDIUM)
    """
    # Filter findings by confidence threshold
    display_findings = [
        f for f in analysis.findings
        if f.severity >= confidence_threshold
    ]
    hidden_count = len(analysis.findings) - len(display_findings)

    content = f"""# Security Analysis Report

**File:** {_get_file_display_name(analysis.file_path)}
**Analyzed:** {analysis.analyzed_at.strftime('%Y-%m-%d %H:%M:%S')}
**Analysis ID:** {analysis.id}

## Summary

- **Total Events:** {analysis.total_events:,}
- **Events Analyzed:** {analysis.events_analyzed:,}
- **Findings:** {len(display_findings)} (threshold: {confidence_threshold.value.upper()}+)
  - Critical: {analysis.critical_count}
  - High: {analysis.high_count}
  - Medium: {analysis.medium_count}
  - Low: {analysis.low_count}
  - Info: {analysis.info_count}
{f"  - *({hidden_count} below threshold hidden)*" if hidden_count > 0 else ""}

{analysis.summary}

## Findings

"""

    for finding in display_findings:
        # Extract unique Event IDs from related events
        related_event_ids = sorted(set(
            e.get('event_id') for e in finding.related_events if e.get('event_id')
        ))
        if related_event_ids:
            related_events_str = f"{len(finding.related_events)} events (Event IDs: {', '.join(str(eid) for eid in related_event_ids)})"
        else:
            related_events_str = f"{len(finding.related_events)} events"

        content += f"""
### [{finding.severity.value.upper()}] {finding.title}

**ID:** {finding.id}
**Confidence:** {finding.confidence:.0%}
**Technique:** {finding.technique or 'N/A'} ({finding.tactic or 'N/A'})
**Related Events:** {related_events_str}

{finding.description}

**Recommendation:** {finding.recommendation}
"""

        # Add security context if available
        if finding.security_context:
            sc = finding.security_context
            content += "\n#### Security Context\n\n"

            # Process info
            if sc.process_name or sc.process_id:
                proc_info = []
                if sc.process_name:
                    proc_info.append(f"**Name:** {sc.process_name}")
                if sc.process_id:
                    proc_info.append(f"**PID:** {sc.process_id}")
                content += f"**Process:** {' | '.join(proc_info)}\n"
            if sc.process_command_line:
                content += f"**Command Line:**\n```\n{sc.process_command_line}\n```\n"
            if sc.parent_process_name or sc.parent_process_id:
                parent_info = []
                if sc.parent_process_name:
                    parent_info.append(sc.parent_process_name)
                if sc.parent_process_id:
                    parent_info.append(f"PID: {sc.parent_process_id}")
                content += f"**Parent Process:** {' | '.join(parent_info)}\n"

            # User info
            if sc.user_name or sc.user_domain:
                user_info = f"{sc.user_domain}\\\\{sc.user_name}" if sc.user_domain else sc.user_name
                if sc.logon_type:
                    logon_types = {2: "Interactive", 3: "Network", 4: "Batch", 5: "Service", 7: "Unlock", 8: "NetworkCleartext", 9: "NewCredentials", 10: "RemoteInteractive", 11: "CachedInteractive"}
                    lt_name = logon_types.get(sc.logon_type, str(sc.logon_type))
                    user_info += f" (Logon Type {sc.logon_type}: {lt_name})"
                content += f"**User:** {user_info}\n"
            if sc.logon_id:
                content += f"**Logon ID:** `{sc.logon_id}`\n"
            if sc.user_sid:
                content += f"**User SID:** `{sc.user_sid}`\n"

            # Target user (for lateral movement / impersonation)
            if sc.target_user_name:
                target_user = f"{sc.target_user_domain}\\\\{sc.target_user_name}" if sc.target_user_domain else sc.target_user_name
                content += f"**Target User:** {target_user}\n"
            if sc.target_logon_id:
                content += f"**Target Logon ID:** `{sc.target_logon_id}`\n"

            # Network info
            if sc.source_ip or sc.source_hostname:
                src = sc.source_hostname or sc.source_ip
                if sc.source_ip and sc.source_hostname:
                    src = f"{sc.source_hostname} ({sc.source_ip})"
                if sc.source_port:
                    src += f":{sc.source_port}"
                content += f"**Source:** {src}\n"
            if sc.destination_ip:
                dst = sc.destination_ip
                if sc.destination_port:
                    dst += f":{sc.destination_port}"
                content += f"**Destination:** {dst}\n"

            # File/Registry
            if sc.target_filename:
                content += f"**File:** `{sc.target_filename}`\n"
            if sc.registry_key:
                content += f"**Registry Key:** `{sc.registry_key}`\n"
                if sc.registry_value:
                    content += f"**Registry Value:** `{sc.registry_value}`\n"

            # .NET/Assembly
            if sc.assembly_name:
                content += f"**Assembly:** `{sc.assembly_name}`\n"
            if sc.clr_version:
                content += f"**CLR Version:** {sc.clr_version}\n"

            # Service/Task
            if sc.service_name:
                content += f"**Service:** {sc.service_name}\n"
            if sc.task_name:
                content += f"**Scheduled Task:** {sc.task_name}\n"

            # Additional fields
            if sc.additional_fields:
                content += "\n**Additional Fields:**\n"
                for key, value in sc.additional_fields.items():
                    content += f"- **{key}:** {value}\n"

        # Add matched correlations if available
        if finding.matched_correlations:
            content += "\n#### Matched Correlation Rules\n\n"
            for mc in finding.matched_correlations:
                field_str = mc.source_field if mc.source_field == mc.target_field else f"{mc.source_field} -> {mc.target_field}"
                content += f"- **{mc.rule_name}**: Event {mc.source_event_id} → Event {mc.target_event_id} via `{field_str}`"
                if mc.matched_value:
                    content += f" (matched value: `{mc.matched_value}`)"
                content += "\n"

        content += "\n---\n"

    with open(filename, 'w', encoding='utf-8') as f:
        f.write(content)


def generate_html_report(analysis, filename: str = "report.html", confidence_threshold: Severity = Severity.MEDIUM) -> str:
    """Generate a beautiful HTML report for the analysis.

    Args:
        analysis: The analysis result to export
        filename: Output filename
        confidence_threshold: Minimum severity to include (default: MEDIUM)
    """
    import html as html_module

    def escape(text):
        """Escape HTML special characters."""
        if text is None:
            return ""
        return html_module.escape(str(text))

    # Severity colors
    severity_colors = {
        "critical": ("#dc2626", "#fef2f2", "#991b1b"),
        "high": ("#ea580c", "#fff7ed", "#c2410c"),
        "medium": ("#ca8a04", "#fefce8", "#a16207"),
        "low": ("#2563eb", "#eff6ff", "#1d4ed8"),
        "info": ("#6b7280", "#f9fafb", "#4b5563"),
    }

    html_content = f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>EventSight Security Report</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background: linear-gradient(135deg, #1e1b4b 0%, #312e81 50%, #1e1b4b 100%);
            min-height: 100vh;
            color: #1f2937;
            line-height: 1.6;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            padding: 2rem;
        }}
        header {{
            text-align: center;
            padding: 3rem 0;
            color: white;
        }}
        header h1 {{
            font-size: 2.5rem;
            font-weight: 700;
            margin-bottom: 0.5rem;
            text-shadow: 0 2px 4px rgba(0,0,0,0.3);
        }}
        header .subtitle {{
            font-size: 1.1rem;
            opacity: 0.9;
        }}
        .card {{
            background: white;
            border-radius: 16px;
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06);
            margin-bottom: 1.5rem;
            overflow: hidden;
        }}
        .card-header {{
            padding: 1.25rem 1.5rem;
            border-bottom: 1px solid #e5e7eb;
            background: #f9fafb;
        }}
        .card-header h2 {{
            font-size: 1.25rem;
            font-weight: 600;
            color: #111827;
        }}
        .card-body {{
            padding: 1.5rem;
        }}
        .summary-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
        }}
        .summary-item {{
            padding: 1rem;
            background: #f9fafb;
            border-radius: 8px;
        }}
        .summary-item .label {{
            font-size: 0.75rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            color: #6b7280;
            margin-bottom: 0.25rem;
        }}
        .summary-item .value {{
            font-size: 1.25rem;
            font-weight: 600;
            color: #111827;
        }}
        .severity-bar {{
            display: flex;
            gap: 0.5rem;
            flex-wrap: wrap;
            margin: 1rem 0;
        }}
        .severity-badge {{
            padding: 0.5rem 1rem;
            border-radius: 9999px;
            font-weight: 600;
            font-size: 0.875rem;
        }}
        .severity-critical {{ background: #fef2f2; color: #991b1b; border: 2px solid #fca5a5; }}
        .severity-high {{ background: #fff7ed; color: #c2410c; border: 2px solid #fdba74; }}
        .severity-medium {{ background: #fefce8; color: #a16207; border: 2px solid #fde047; }}
        .severity-low {{ background: #eff6ff; color: #1d4ed8; border: 2px solid #93c5fd; }}
        .severity-info {{ background: #f9fafb; color: #4b5563; border: 2px solid #d1d5db; }}
        .finding {{
            border: 1px solid #e5e7eb;
            border-radius: 12px;
            margin-bottom: 1rem;
            overflow: hidden;
        }}
        .finding-header {{
            padding: 1rem 1.25rem;
            display: flex;
            align-items: center;
            gap: 1rem;
            border-bottom: 1px solid #e5e7eb;
        }}
        .finding-severity {{
            padding: 0.25rem 0.75rem;
            border-radius: 6px;
            font-weight: 700;
            font-size: 0.75rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }}
        .finding-title {{
            font-size: 1.1rem;
            font-weight: 600;
            color: #111827;
            flex: 1;
        }}
        .instance-badge {{
            background: #e9d5ff;
            color: #7e22ce;
            padding: 0.25rem 0.5rem;
            border-radius: 9999px;
            font-size: 0.75rem;
            font-weight: 600;
            margin-left: 0.5rem;
        }}
        .occurrences-section {{
            margin-top: 1rem;
            padding-top: 1rem;
            border-top: 1px solid #e5e7eb;
        }}
        .occurrences-section h4 {{
            font-size: 0.875rem;
            font-weight: 600;
            color: #7e22ce;
            margin-bottom: 0.75rem;
        }}
        .occurrence-item {{
            display: flex;
            align-items: flex-start;
            gap: 0.75rem;
            padding: 0.5rem;
            background: #faf5ff;
            border-radius: 6px;
            margin-bottom: 0.5rem;
            font-size: 0.875rem;
        }}
        .occurrence-num {{
            color: #9333ea;
            font-weight: 600;
            min-width: 1.5rem;
        }}
        .occurrence-time {{
            color: #6b7280;
            font-family: monospace;
            font-size: 0.75rem;
            min-width: 140px;
        }}
        .occurrence-detail {{
            color: #374151;
            flex: 1;
            word-break: break-all;
        }}
        .finding-confidence {{
            font-size: 0.875rem;
            color: #6b7280;
        }}
        .finding-body {{
            padding: 1.25rem;
        }}
        .finding-description {{
            color: #374151;
            margin-bottom: 1rem;
        }}
        .finding-meta {{
            display: flex;
            flex-wrap: wrap;
            gap: 0.5rem;
            margin-bottom: 1rem;
        }}
        .meta-tag {{
            background: #f3f4f6;
            padding: 0.25rem 0.75rem;
            border-radius: 6px;
            font-size: 0.75rem;
            color: #4b5563;
        }}
        .meta-tag.technique {{
            background: #dbeafe;
            color: #1e40af;
        }}
        .meta-tag.tactic {{
            background: #e0e7ff;
            color: #3730a3;
        }}
        .recommendation {{
            background: #ecfdf5;
            border-left: 4px solid #10b981;
            padding: 0.75rem 1rem;
            border-radius: 0 8px 8px 0;
            color: #065f46;
            margin-top: 1rem;
        }}
        .recommendation::before {{
            content: "Recommendation: ";
            font-weight: 600;
        }}
        .context-section {{
            margin-top: 1rem;
            padding-top: 1rem;
            border-top: 1px solid #e5e7eb;
        }}
        .context-section h4 {{
            font-size: 0.875rem;
            font-weight: 600;
            color: #6b7280;
            margin-bottom: 0.75rem;
        }}
        .context-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 0.5rem;
        }}
        .context-item {{
            font-size: 0.875rem;
            padding: 0.5rem;
            background: #f9fafb;
            border-radius: 6px;
        }}
        .context-item .label {{
            color: #6b7280;
            font-weight: 500;
        }}
        .context-item .value {{
            color: #111827;
            word-break: break-all;
        }}
        .event-ids {{
            display: flex;
            flex-wrap: wrap;
            gap: 0.25rem;
            margin-top: 0.5rem;
        }}
        .event-id {{
            background: #1e1b4b;
            color: white;
            padding: 0.125rem 0.5rem;
            border-radius: 4px;
            font-size: 0.75rem;
            font-family: monospace;
        }}
        footer {{
            text-align: center;
            padding: 2rem;
            color: rgba(255,255,255,0.7);
            font-size: 0.875rem;
        }}
        .no-findings {{
            text-align: center;
            padding: 3rem;
            color: #059669;
        }}
        .no-findings svg {{
            width: 64px;
            height: 64px;
            margin-bottom: 1rem;
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>EventSight Security Report</h1>
            <p class="subtitle">Claude-Powered Windows Event Log Analysis</p>
        </header>

        <div class="card">
            <div class="card-header">
                <h2>Analysis Summary</h2>
            </div>
            <div class="card-body">
                <div class="summary-grid">
                    <div class="summary-item">
                        <div class="label">File Analyzed</div>
                        <div class="value" style="font-size: 0.9rem; word-break: break-all;">{escape(_get_file_display_name(analysis.file_path))}</div>
                    </div>
                    <div class="summary-item">
                        <div class="label">Analysis Date</div>
                        <div class="value">{analysis.analyzed_at.strftime('%Y-%m-%d %H:%M')}</div>
                    </div>
                    <div class="summary-item">
                        <div class="label">Events Analyzed</div>
                        <div class="value">{analysis.events_analyzed:,} <span style="font-size: 0.75rem; color: #6b7280;">of {analysis.total_events:,}</span></div>
                    </div>
                    <div class="summary-item">
                        <div class="label">Total Findings</div>
                        <div class="value">{len(analysis.findings)}</div>
                    </div>
                </div>

                <div class="severity-bar">
'''

    if analysis.critical_count:
        html_content += f'                    <span class="severity-badge severity-critical">{analysis.critical_count} Critical</span>\n'
    if analysis.high_count:
        html_content += f'                    <span class="severity-badge severity-high">{analysis.high_count} High</span>\n'
    if analysis.medium_count:
        html_content += f'                    <span class="severity-badge severity-medium">{analysis.medium_count} Medium</span>\n'

    # Filter findings by confidence threshold
    display_findings = [
        f for f in analysis.findings
        if f.severity >= confidence_threshold
    ]
    hidden_count = len(analysis.findings) - len(display_findings)

    if hidden_count > 0:
        html_content += f'                    <span style="color: #6b7280; font-size: 0.75rem; margin-left: 0.5rem;">({hidden_count} below {confidence_threshold.value.upper()} hidden)</span>\n'

    html_content += f'''                </div>
'''

    # Add summary with proper line break handling for the multi-line format
    if analysis.summary:
        summary_html = escape(analysis.summary).replace('\n', '<br>')
        html_content += f'''
                <div style="margin-top: 1rem; padding: 1rem; background: #f3f4f6; border-radius: 8px; font-family: monospace; font-size: 0.875rem; white-space: pre-wrap; line-height: 1.5;">
{summary_html}
                </div>
'''

    html_content += '''            </div>
        </div>

        <div class="card">
            <div class="card-header">
                <h2>Detailed Findings</h2>
            </div>
            <div class="card-body">
'''

    if not display_findings:
        if hidden_count > 0:
            html_content += f'''
                <div class="no-findings">
                    <svg fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"></path>
                    </svg>
                    <h3 style="font-size: 1.25rem; font-weight: 600;">No High-Priority Findings</h3>
                    <p style="color: #6b7280;">{hidden_count} low-priority findings were hidden from this report.</p>
                </div>
'''
        else:
            html_content += '''
                <div class="no-findings">
                    <svg fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"></path>
                    </svg>
                    <h3 style="font-size: 1.25rem; font-weight: 600;">No Suspicious Activity Detected</h3>
                    <p style="color: #6b7280;">The analyzed events did not reveal any security concerns.</p>
                </div>
'''
    else:
        for finding in display_findings:
            sev = finding.severity.value
            bg_color, light_bg, text_color = severity_colors.get(sev, severity_colors["info"])

            # Get timestamp from related events
            timestamp_str = ""
            if finding.related_events:
                ts = finding.related_events[0].get("timestamp", "")
                if ts:
                    try:
                        from datetime import datetime as dt
                        parsed = dt.fromisoformat(ts.replace("Z", "+00:00"))
                        timestamp_str = parsed.strftime("%Y-%m-%d %H:%M:%S")
                    except Exception:
                        timestamp_str = ts[:19] if len(ts) >= 19 else ts

            timestamp_html = f'<span style="color: #6b7280; font-size: 0.875rem; margin-left: auto;">{escape(timestamp_str)}</span>' if timestamp_str else ''

            # Instance count badge for merged findings
            instance_count = finding.instance_count
            instance_badge_html = f'<span class="instance-badge">{instance_count} occurrences</span>' if instance_count > 1 else ''

            html_content += f'''
                <div class="finding">
                    <div class="finding-header" style="background: {light_bg};">
                        <span class="finding-severity" style="background: {bg_color}; color: white;">{sev.upper()}</span>
                        <span class="finding-title">{escape(finding.title)}{instance_badge_html}</span>
                        {timestamp_html}
                        <span class="finding-confidence">{finding.confidence:.0%} confidence</span>
                    </div>
                    <div class="finding-body">
                        <p class="finding-description">{escape(finding.description)}</p>
                        <div class="finding-meta">
                            <span class="meta-tag">ID: {escape(finding.id)}</span>
'''
            if finding.technique:
                html_content += f'                            <span class="meta-tag technique">{escape(finding.technique)}</span>\n'
            if finding.tactic:
                html_content += f'                            <span class="meta-tag tactic">{escape(finding.tactic)}</span>\n'

            # Event IDs
            related_event_ids = sorted(set(
                e.get('event_id') for e in finding.related_events if e.get('event_id')
            ))
            if related_event_ids:
                html_content += '                        </div>\n                        <div class="event-ids">\n'
                for eid in related_event_ids:
                    html_content += f'                            <span class="event-id">Event {eid}</span>\n'
                html_content += '                        </div>\n'
            else:
                html_content += '                        </div>\n'

            # Recommendation
            if finding.recommendation:
                html_content += f'                        <div class="recommendation">{escape(finding.recommendation)}</div>\n'

            # Security context
            if finding.security_context:
                sc = finding.security_context
                context_items = []

                if sc.process_name:
                    context_items.append(("Process", sc.process_name + (f" (PID {sc.process_id})" if sc.process_id else "")))
                if sc.process_command_line:
                    cmd = sc.process_command_line[:100] + "..." if len(sc.process_command_line) > 100 else sc.process_command_line
                    context_items.append(("Command Line", cmd))
                if sc.parent_process_name:
                    context_items.append(("Parent Process", sc.parent_process_name))
                if sc.user_name:
                    user = f"{sc.user_domain}\\{sc.user_name}" if sc.user_domain else sc.user_name
                    context_items.append(("User", user))
                if sc.logon_type:
                    logon_types = {2: "Interactive", 3: "Network", 4: "Batch", 5: "Service", 7: "Unlock", 10: "RemoteInteractive"}
                    context_items.append(("Logon Type", f"{sc.logon_type} ({logon_types.get(sc.logon_type, 'Other')})"))
                if sc.source_ip:
                    context_items.append(("Source IP", sc.source_ip + (f":{sc.source_port}" if sc.source_port else "")))
                if sc.target_filename:
                    context_items.append(("File", sc.target_filename))
                if sc.registry_key:
                    context_items.append(("Registry", sc.registry_key))
                if sc.service_name:
                    context_items.append(("Service", sc.service_name))
                if sc.assembly_name:
                    context_items.append(("Assembly", sc.assembly_name))

                if context_items:
                    html_content += '''                        <div class="context-section">
                            <h4>Security Context</h4>
                            <div class="context-grid">
'''
                    for label, value in context_items:
                        html_content += f'                                <div class="context-item"><span class="label">{escape(label)}:</span> <span class="value">{escape(value)}</span></div>\n'
                    html_content += '                            </div>\n                        </div>\n'

            # Matched correlation rules
            if finding.matched_correlations:
                html_content += '''                        <div class="context-section">
                            <h4>Matched Correlation Rules</h4>
                            <div style="display: flex; flex-direction: column; gap: 0.5rem;">
'''
                for mc in finding.matched_correlations:
                    if mc.source_field == mc.target_field:
                        field_info = f"Event {mc.source_event_id} → {mc.target_event_id} via {mc.source_field}"
                    else:
                        field_info = f"Event {mc.source_event_id} → {mc.target_event_id} via {mc.source_field}→{mc.target_field}"
                    if mc.matched_value:
                        field_info += f" = '{mc.matched_value}'"
                    html_content += f'''                                <div style="padding: 0.5rem; background: #faf5ff; border-left: 3px solid #9333ea; border-radius: 0 6px 6px 0;">
                                    <span style="font-weight: 600; color: #7e22ce;">{escape(mc.rule_name)}</span>
                                    <span style="color: #6b7280; font-size: 0.875rem; margin-left: 0.5rem;">{escape(field_info)}</span>
                                </div>
'''
                html_content += '                            </div>\n                        </div>\n'

            # Multiple instances (merged findings)
            if finding.instances and len(finding.instances) > 1:
                html_content += '''                        <div class="occurrences-section">
                            <h4>Individual Occurrences</h4>
'''
                for idx, instance in enumerate(finding.instances[:15], 1):  # Show first 15
                    ts_str = instance.timestamp.strftime("%Y-%m-%d %H:%M:%S")
                    detail = escape(instance.instance_detail or "No details")
                    # Truncate long details
                    if len(detail) > 100:
                        detail = detail[:97] + "..."
                    html_content += f'''                            <div class="occurrence-item">
                                <span class="occurrence-num">{idx}.</span>
                                <span class="occurrence-time">{ts_str}</span>
                                <span class="occurrence-detail">{detail}</span>
                            </div>
'''
                if len(finding.instances) > 15:
                    html_content += f'''                            <div style="text-align: center; color: #6b7280; font-size: 0.875rem; margin-top: 0.5rem;">
                                ... and {len(finding.instances) - 15} more occurrences
                            </div>
'''
                html_content += '                        </div>\n'

            html_content += '                    </div>\n                </div>\n'

    html_content += f'''            </div>
        </div>

        <footer>
            <p>Generated by EventSight | Analysis ID: {escape(analysis.id)}</p>
            <p>Report generated on {datetime.now().strftime('%Y-%m-%d at %H:%M:%S')}</p>
        </footer>
    </div>
</body>
</html>
'''

    with open(filename, 'w', encoding='utf-8') as f:
        f.write(html_content)

    return filename


def generate_continuous_html_report(
    findings: list,
    filename: str,
    file_path: str,
    start_time: datetime,
    total_events: int,
    iteration_count: int,
    min_confidence: float = 0.65
) -> str:
    """Generate a live-updating HTML report for continuous mode.

    Args:
        findings: List of Finding objects detected so far
        filename: Output filename
        file_path: Path to the monitored file/channel
        start_time: When continuous monitoring started
        total_events: Total events analyzed so far
        iteration_count: Number of analysis iterations
        min_confidence: Minimum confidence threshold used
    """
    import html as html_module

    def escape(text):
        """Escape HTML special characters."""
        if text is None:
            return ""
        return html_module.escape(str(text))

    runtime = (datetime.now() - start_time).total_seconds()
    runtime_str = f"{int(runtime // 3600)}h {int((runtime % 3600) // 60)}m {int(runtime % 60)}s" if runtime >= 3600 else f"{int(runtime // 60)}m {int(runtime % 60)}s"

    # Count by severity
    critical_count = sum(1 for f in findings if f.severity.value == "critical")
    high_count = sum(1 for f in findings if f.severity.value == "high")
    medium_count = sum(1 for f in findings if f.severity.value == "medium")
    low_count = sum(1 for f in findings if f.severity.value == "low")

    # Severity colors
    severity_colors = {
        "critical": ("#dc2626", "#fef2f2", "#991b1b"),
        "high": ("#ea580c", "#fff7ed", "#c2410c"),
        "medium": ("#ca8a04", "#fefce8", "#a16207"),
        "low": ("#2563eb", "#eff6ff", "#1d4ed8"),
        "info": ("#6b7280", "#f9fafb", "#4b5563"),
    }

    html_content = f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="refresh" content="30">
    <title>EventSight Continuous Monitor</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background: linear-gradient(135deg, #0f172a 0%, #1e293b 50%, #0f172a 100%);
            min-height: 100vh;
            color: #1f2937;
            line-height: 1.6;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            padding: 2rem;
        }}
        header {{
            text-align: center;
            padding: 2rem 0;
            color: white;
        }}
        header h1 {{
            font-size: 2rem;
            font-weight: 700;
            margin-bottom: 0.5rem;
            text-shadow: 0 2px 4px rgba(0,0,0,0.3);
        }}
        .live-badge {{
            display: inline-block;
            background: #22c55e;
            color: white;
            padding: 0.25rem 0.75rem;
            border-radius: 9999px;
            font-size: 0.75rem;
            font-weight: 600;
            animation: pulse 2s infinite;
            margin-left: 0.5rem;
        }}
        @keyframes pulse {{
            0%, 100% {{ opacity: 1; }}
            50% {{ opacity: 0.7; }}
        }}
        .status-bar {{
            display: flex;
            justify-content: center;
            gap: 2rem;
            flex-wrap: wrap;
            margin-top: 1rem;
            color: rgba(255,255,255,0.8);
            font-size: 0.875rem;
        }}
        .status-item {{
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }}
        .card {{
            background: white;
            border-radius: 16px;
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06);
            margin-bottom: 1.5rem;
            overflow: hidden;
        }}
        .card-header {{
            padding: 1rem 1.5rem;
            border-bottom: 1px solid #e5e7eb;
            background: #f9fafb;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        .card-header h2 {{
            font-size: 1.125rem;
            font-weight: 600;
            color: #111827;
        }}
        .card-body {{
            padding: 1.5rem;
        }}
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 1rem;
        }}
        .stat-item {{
            text-align: center;
            padding: 1rem;
            background: #f9fafb;
            border-radius: 8px;
        }}
        .stat-value {{
            font-size: 1.5rem;
            font-weight: 700;
            color: #111827;
        }}
        .stat-label {{
            font-size: 0.75rem;
            color: #6b7280;
            text-transform: uppercase;
        }}
        .severity-badge {{
            display: inline-block;
            padding: 0.25rem 0.75rem;
            border-radius: 9999px;
            font-size: 0.75rem;
            font-weight: 600;
            color: white;
        }}
        .severity-critical {{ background: #dc2626; }}
        .severity-high {{ background: #ea580c; }}
        .severity-medium {{ background: #ca8a04; }}
        .severity-low {{ background: #2563eb; }}
        .severity-info {{ background: #6b7280; }}
        .finding {{
            border: 1px solid #e5e7eb;
            border-radius: 12px;
            margin-bottom: 1rem;
            overflow: hidden;
        }}
        .finding-header {{
            padding: 1rem;
            display: flex;
            align-items: center;
            gap: 0.75rem;
            flex-wrap: wrap;
        }}
        .finding-title {{
            font-weight: 600;
            color: #111827;
            flex: 1;
        }}
        .finding-time {{
            color: #6b7280;
            font-size: 0.875rem;
        }}
        .finding-confidence {{
            color: #6b7280;
            font-size: 0.75rem;
            background: #f3f4f6;
            padding: 0.25rem 0.5rem;
            border-radius: 4px;
        }}
        .finding-body {{
            padding: 1rem;
            background: white;
            border-top: 1px solid #e5e7eb;
        }}
        .finding-description {{
            color: #374151;
            margin-bottom: 1rem;
        }}
        .finding-meta {{
            display: flex;
            gap: 0.5rem;
            flex-wrap: wrap;
            margin-bottom: 0.75rem;
        }}
        .meta-tag {{
            font-size: 0.75rem;
            padding: 0.25rem 0.5rem;
            background: #f3f4f6;
            border-radius: 4px;
            color: #4b5563;
        }}
        .meta-tag.technique {{
            background: #dbeafe;
            color: #1e40af;
        }}
        .meta-tag.tactic {{
            background: #fae8ff;
            color: #86198f;
        }}
        .context-section {{
            margin-top: 1rem;
            padding: 1rem;
            background: #f9fafb;
            border-radius: 8px;
        }}
        .context-section h4 {{
            font-size: 0.75rem;
            text-transform: uppercase;
            color: #6b7280;
            margin-bottom: 0.5rem;
        }}
        .context-grid {{
            display: grid;
            gap: 0.25rem;
            font-size: 0.875rem;
        }}
        .context-item .label {{
            color: #6b7280;
        }}
        .context-item .value {{
            color: #111827;
            font-family: monospace;
        }}
        .recommendation {{
            margin-top: 1rem;
            padding: 0.75rem;
            background: #ecfdf5;
            border-left: 3px solid #10b981;
            border-radius: 0 6px 6px 0;
            font-size: 0.875rem;
            color: #065f46;
        }}
        .no-findings {{
            text-align: center;
            padding: 3rem;
            color: #6b7280;
        }}
        .no-findings svg {{
            width: 48px;
            height: 48px;
            margin-bottom: 1rem;
            color: #22c55e;
        }}
        footer {{
            text-align: center;
            padding: 2rem;
            color: rgba(255,255,255,0.6);
            font-size: 0.875rem;
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>EventSight Continuous Monitor <span class="live-badge">LIVE</span></h1>
            <div class="status-bar">
                <div class="status-item">Monitoring: {escape(file_path)}</div>
                <div class="status-item">Runtime: {runtime_str}</div>
                <div class="status-item">Confidence: &ge;{min_confidence:.0%}</div>
            </div>
        </header>

        <div class="card">
            <div class="card-header">
                <h2>Monitoring Statistics</h2>
                <span style="color: #6b7280; font-size: 0.875rem;">Last updated: {datetime.now().strftime('%H:%M:%S')}</span>
            </div>
            <div class="card-body">
                <div class="stats-grid">
                    <div class="stat-item">
                        <div class="stat-value">{total_events:,}</div>
                        <div class="stat-label">Events Analyzed</div>
                    </div>
                    <div class="stat-item">
                        <div class="stat-value">{len(findings)}</div>
                        <div class="stat-label">Total Findings</div>
                    </div>
                    <div class="stat-item">
                        <div class="stat-value">{iteration_count}</div>
                        <div class="stat-label">Iterations</div>
                    </div>
                    <div class="stat-item">
                        <div class="stat-value" style="color: #dc2626;">{critical_count}</div>
                        <div class="stat-label">Critical</div>
                    </div>
                    <div class="stat-item">
                        <div class="stat-value" style="color: #ea580c;">{high_count}</div>
                        <div class="stat-label">High</div>
                    </div>
                    <div class="stat-item">
                        <div class="stat-value" style="color: #ca8a04;">{medium_count}</div>
                        <div class="stat-label">Medium</div>
                    </div>
                </div>
            </div>
        </div>

        <div class="card">
            <div class="card-header">
                <h2>Findings</h2>
            </div>
            <div class="card-body">
'''

    if not findings:
        html_content += '''
                <div class="no-findings">
                    <svg fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"></path>
                    </svg>
                    <h3 style="font-size: 1.25rem; font-weight: 600;">No Findings Yet</h3>
                    <p>Monitoring for suspicious activity...</p>
                </div>
'''
    else:
        # Sort by timestamp descending (newest first)
        sorted_findings = sorted(findings, key=lambda f: f.timestamp, reverse=True)
        for finding in sorted_findings:
            sev = finding.severity.value
            bg_color, light_bg, text_color = severity_colors.get(sev, severity_colors["info"])
            timestamp_str = finding.timestamp.strftime("%Y-%m-%d %H:%M:%S")

            html_content += f'''
                <div class="finding">
                    <div class="finding-header" style="background: {light_bg};">
                        <span class="severity-badge severity-{sev}">{sev.upper()}</span>
                        <span class="finding-title">{escape(finding.title)}</span>
                        <span class="finding-time">{timestamp_str}</span>
                        <span class="finding-confidence">{finding.confidence:.0%}</span>
                    </div>
                    <div class="finding-body">
                        <p class="finding-description">{escape(finding.description)}</p>
                        <div class="finding-meta">
'''
            if finding.technique:
                html_content += f'                            <span class="meta-tag technique">{escape(finding.technique)}</span>\n'
            if finding.tactic:
                html_content += f'                            <span class="meta-tag tactic">{escape(finding.tactic)}</span>\n'
            html_content += '                        </div>\n'

            # Security context
            if finding.security_context:
                sc = finding.security_context
                context_items = []
                if sc.process_name:
                    context_items.append(("Process", sc.process_name + (f" (PID {sc.process_id})" if sc.process_id else "")))
                if sc.process_command_line:
                    cmd = sc.process_command_line[:150] + "..." if len(sc.process_command_line) > 150 else sc.process_command_line
                    context_items.append(("Command", cmd))
                if sc.parent_process_name:
                    context_items.append(("Parent", sc.parent_process_name))
                if sc.user_name:
                    user = f"{sc.user_domain}\\{sc.user_name}" if sc.user_domain else sc.user_name
                    context_items.append(("User", user))
                if sc.source_ip:
                    context_items.append(("Source IP", sc.source_ip))
                if sc.target_filename:
                    context_items.append(("File", sc.target_filename))

                if context_items:
                    html_content += '''                        <div class="context-section">
                            <h4>Security Context</h4>
                            <div class="context-grid">
'''
                    for label, value in context_items:
                        html_content += f'                                <div class="context-item"><span class="label">{escape(label)}:</span> <span class="value">{escape(value)}</span></div>\n'
                    html_content += '                            </div>\n                        </div>\n'

            # Recommendation
            if finding.recommendation:
                html_content += f'                        <div class="recommendation">{escape(finding.recommendation)}</div>\n'

            html_content += '                    </div>\n                </div>\n'

    html_content += f'''            </div>
        </div>

        <footer>
            <p>EventSight Continuous Monitor | Started: {start_time.strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p>Page auto-refreshes every 30 seconds</p>
        </footer>
    </div>
</body>
</html>
'''

    with open(filename, 'w', encoding='utf-8') as f:
        f.write(html_content)

    return filename


@click.group(invoke_without_command=True)
@click.pass_context
def cli(ctx):
    """EventSight - Claude-powered Windows Event Log analysis."""
    ctx.ensure_object(dict)
    
    if ctx.invoked_subcommand is None:
        # No subcommand, run interactive mode
        try:
            agent = SecurityAgent()
            ctx.obj['agent'] = agent
            run_interactive(agent)
        except ValueError as e:
            console.print(f"[red]Error: {e}[/red]")
            sys.exit(1)
        finally:
            if 'agent' in ctx.obj:
                ctx.obj['agent'].close()


@cli.command()
@click.argument('file_paths', nargs=-1, required=True)
@click.option('--max-events', type=int, default=None, help='Maximum events to analyze (overrides default)')
@click.option('--batch-size', type=int, default=None, help='Events per batch for large files (default: 25)')
@click.option('--no-smart-filter', is_flag=True, help='Disable AI-based smart filtering of Event IDs')
@click.option('--no-filter', is_flag=True, help='Disable all filtering - analyze all events')
@click.option('--event-ids', type=str, default=None, help='Comma-separated list of Event IDs to filter to (e.g., "1,4688,4624")')
@click.option('--filter-file', type=click.Path(exists=True), default=None, help='CSV file with Event IDs to filter (columns: EventType,EventCode,Reason)')
@click.option('--continuous', is_flag=True, help='Enable continuous monitoring mode - watches for new events')
@click.option('--interval', type=int, default=60, help='Seconds between checks in continuous mode (default: 60)')
@click.option('--min-confidence', type=float, default=None, help='Minimum confidence threshold (0.0-1.0, default: 0.7). Lower values show more findings.')
def evaluate(file_paths, max_events, batch_size, no_smart_filter, no_filter, event_ids, filter_file, continuous, interval, min_confidence):
    """Analyze EVTX file(s) or live Windows event channels.

    Pass one or more EVTX files to analyze. When multiple files are provided,
    events are merged together for cross-file correlation analysis.

    By default, smart filtering identifies security-relevant Event IDs to reduce API usage.

    You can specify exact Event IDs with --event-ids "1,4688,4624"

    Or load Event IDs from a CSV file with --filter-file filter.csv
    The CSV should have columns: EventType, EventCode, Reason (header optional)

    IMPORTANT: When analyzing multiple files, you MUST use --event-ids or --filter-file
    to specify which events to analyze (smart filtering is disabled for multi-file analysis).

    CONTINUOUS MODE: Use --continuous to monitor for new events.
    Supports both EVTX files and live channel names (e.g., "Application", "Security").
    Requires --filter-file or --event-ids to specify which events to analyze.
    Automatically generates a live-updating HTML report (eventsight_report.html).

    Examples:
      eventsight evaluate Security.evtx --continuous --event-ids 4624,4688
      eventsight evaluate Security.evtx --continuous --filter-file events.csv
      eventsight evaluate Application --continuous --event-ids 1000,1001
    """
    try:
        agent = SecurityAgent()
        file_paths = list(file_paths)
        is_multi_file = len(file_paths) > 1

        # Continuous mode validation
        if continuous:
            if is_multi_file:
                print("Error: Continuous mode only supports a single EVTX file or channel.")
                sys.exit(1)
            if not filter_file and not event_ids:
                print("Error: Continuous mode requires --filter-file or --event-ids to specify which events to analyze.")
                print("")
                print("Example:")
                print("  eventsight evaluate Security.evtx --continuous --filter-file events.csv")
                print("  eventsight evaluate Security.evtx --continuous --event-ids 4624,4688,4672")
                print("  eventsight evaluate Application --continuous --event-ids 1000,1001  # Live channel")
                sys.exit(1)
        else:
            # Non-continuous mode requires existing files
            for fp in file_paths:
                if not Path(fp).exists():
                    print(f"Error: File not found: {fp}")
                    sys.exit(1)

        # Parse filter file if provided
        filter_event_ids = None
        filter_metadata = None
        provider_filters = None

        if filter_file:
            try:
                filter_event_ids, filter_metadata, provider_filters = parse_filter_file(filter_file)
                if provider_filters:
                    print(f"Loaded {len(provider_filters)} provider-specific Event IDs from filter file: {filter_file}")
                else:
                    print(f"Loaded {len(filter_event_ids)} Event IDs from filter file: {filter_file}")
                # Show preview of loaded filters
                shown = 0
                for key, meta in list(filter_metadata.items())[:3]:
                    reason = meta.get('reason', '')[:60]
                    if isinstance(key, tuple):
                        provider, eid = key
                        print(f"  {provider} Event {eid}: {reason}")
                    else:
                        print(f"  Event {key}: {reason}")
                    shown += 1
                if len(filter_metadata) > 3:
                    print(f"  ... and {len(filter_metadata) - 3} more")
            except Exception as e:
                print(f"Error loading filter file: {e}")
                sys.exit(1)
        elif event_ids:
            # Parse event IDs if provided via command line
            try:
                filter_event_ids = [int(x.strip()) for x in event_ids.split(',')]
                print(f"Filtering to Event IDs: {filter_event_ids}")
            except ValueError:
                print(f"Error: Invalid event IDs format. Use comma-separated numbers (e.g., '1,4688,4624')")
                sys.exit(1)

        # Multi-file analysis requires explicit filtering
        if is_multi_file and not filter_event_ids:
            print("Error: When analyzing multiple EVTX files, you must specify which events to analyze.")
            print("Use --event-ids or --filter-file to specify the Event IDs to include.")
            print("")
            print("Examples:")
            print("  eventsight evaluate file1.evtx file2.evtx --event-ids 4624,4688,4672")
            print("  eventsight evaluate file1.evtx file2.evtx --filter-file my_filters.csv")
            sys.exit(1)

        if is_multi_file:
            print(f"Analyzing {len(file_paths)} EVTX files together for cross-file correlation...")
            for fp in file_paths:
                print(f"  - {fp}")

        # Determine filter settings
        smart_filter = not no_smart_filter if not is_multi_file else False
        filter_relevant = not no_filter
        if filter_event_ids:
            smart_filter = False  # Disable smart filter when explicit IDs provided
        if no_filter:
            smart_filter = False

        # Continuous mode - monitor for new events
        if continuous:
            filter_set = set(filter_event_ids) if filter_event_ids else set()
            effective_batch_size = batch_size if batch_size else 50

            # Apply custom confidence threshold if specified
            if min_confidence is not None:
                agent.config.min_confidence_score = min_confidence
                print(f"Using minimum confidence threshold: {min_confidence:.0%}")

            # Default report path for continuous mode (absolute path)
            report_path = str(Path.cwd() / "eventsight_report.html")

            agent.analyze_continuous(
                file_path=file_paths[0],
                filter_event_ids=filter_set,
                interval=interval,
                batch_size=effective_batch_size,
                report_path=report_path
            )
            agent.close()
            return

        # Standard one-shot analysis
        result = agent.evaluate_evtx(
            file_paths,
            max_events=max_events,
            batch_size=batch_size,
            smart_filter=smart_filter,
            filter_relevant=filter_relevant,
            filter_event_ids=filter_event_ids,
            filter_metadata=filter_metadata,
            provider_filters=provider_filters
        )

        display_findings(agent)
        agent.close()

    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


@cli.command()
@click.argument('finding_id')
@click.argument('verdict', type=click.Choice(['false_positive', 'true_positive', 'benign', 'needs_context']))
@click.argument('explanation')
def feedback(finding_id, verdict, explanation):
    """Provide feedback on a finding."""
    try:
        agent = SecurityAgent()
        learning = agent.add_feedback(finding_id, Verdict(verdict), explanation)
        
        console.print(Panel(
            f"[green]Learning recorded![/green]\n\n**Insight:** {learning.insight}",
            title="New Learning",
            border_style="green"
        ))
        
        agent.close()
        
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        sys.exit(1)


@cli.command()
def learnings():
    """List all stored learnings."""
    try:
        agent = SecurityAgent()
        display_learnings(agent)
        agent.close()
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        sys.exit(1)


if __name__ == "__main__":
    cli()
