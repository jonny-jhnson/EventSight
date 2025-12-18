"""Core security analysis agent using Claude."""

import json
import os
import re
import signal
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional, Callable

import anthropic


class CancelledException(Exception):
    """Raised when an analysis operation is cancelled."""
    pass

from .models import (
    AgentConfig, AnalysisResult, Finding, FindingInstance, Learning, Severity, Verdict, WindowsEvent,
    CorrelationRule, SecurityContext, MatchedCorrelation
)
from .parser import parse_evtx_file, events_to_summary, filter_security_relevant_events, parse_evtx_incremental


from .learnings import LearningsStore, extract_keywords
from .events_store import EventsStore
from .prompts import (
    ANALYSIS_SYSTEM_PROMPT, LEARNING_EXTRACTION_PROMPT,
    CORRELATION_CONTEXT_HEADER
)


@dataclass
class ContinuousState:
    """Tracks state for continuous analysis mode."""
    last_timestamp: Optional[datetime] = None
    total_events_analyzed: int = 0
    total_findings: int = 0
    iteration_count: int = 0
    start_time: datetime = field(default_factory=datetime.now)
    all_findings: list = field(default_factory=list)  # Track all findings for report


def _safe_int(value) -> Optional[int]:
    """Safely convert a value to int, handling hex strings and None."""
    if value is None:
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        value = value.strip()
        if not value:
            return None
        try:
            # Handle hex strings like "0x1234"
            if value.lower().startswith("0x"):
                return int(value, 16)
            return int(value)
        except ValueError:
            return None
    return None


def _safe_str(value) -> Optional[str]:
    """Safely convert a value to string, handling lists by joining them."""
    if value is None:
        return None
    if isinstance(value, str):
        return value if value.strip() else None
    if isinstance(value, list):
        # Join list items with semicolon
        return "; ".join(str(item) for item in value) if value else None
    return str(value)


class SecurityAgent:
    """
    AI-powered security analysis agent.
    
    Uses Claude to analyze Windows Event Logs and learns from analyst feedback.
    """
    
    def __init__(self, config: Optional[AgentConfig] = None):
        self.config = config or AgentConfig()
        
        # Initialize Anthropic client
        api_key = os.environ.get("ANTHROPIC_API_KEY")
        if not api_key:
            raise ValueError(
                "ANTHROPIC_API_KEY environment variable not set. "
                "Set it with: export ANTHROPIC_API_KEY=your-key-here"
            )
        self.client = anthropic.Anthropic(api_key=api_key)
        
        # Initialize learnings store (with vector search)
        self.learnings_store = LearningsStore(
            db_path=self.config.database_path,
            use_vectors=True
        )

        # Initialize events store (separate SQLite DB)
        events_db_path = str(Path(self.config.database_path).parent / "events.db")
        self.events_store = EventsStore(db_path=events_db_path)

        # Track current analysis for feedback
        self.current_analysis: Optional[AnalysisResult] = None
        self._events_cache: list[WindowsEvent] = []  # Filtered events (sent to Claude)
        self._all_events_cache: list[WindowsEvent] = []  # All parsed events

        # Token tracking
        self._total_input_tokens = 0
        self._total_output_tokens = 0
        self._show_tokens = False  # Control token output visibility

        # Cancellation support
        self._cancelled = threading.Event()
        self._cancel_lock = threading.Lock()

    def cancel(self):
        """
        Cancel any ongoing analysis operations.

        This signals all running operations to stop gracefully.
        Call this method when handling KeyboardInterrupt or when you want
        to abort an analysis.
        """
        with self._cancel_lock:
            self._cancelled.set()
            print("\n[Cancellation requested - stopping analysis...]")

    def reset_cancellation(self):
        """Reset the cancellation flag for a new analysis."""
        with self._cancel_lock:
            self._cancelled.clear()

    def is_cancelled(self) -> bool:
        """Check if cancellation has been requested."""
        return self._cancelled.is_set()

    def _check_cancelled(self):
        """
        Check if cancellation was requested and raise if so.

        Call this at key checkpoints during analysis to allow
        graceful cancellation.

        Raises:
            CancelledException: If cancellation was requested
        """
        if self._cancelled.is_set():
            raise CancelledException("Analysis was cancelled by user")

    def evaluate_evtx(
        self,
        file_path: str | list[str],
        filter_relevant: bool = True,
        max_events: Optional[int] = None,
        batch_size: Optional[int] = None,
        smart_filter: bool = True,
        filter_event_ids: Optional[list[int]] = None,
        filter_metadata: Optional[dict] = None,
        provider_filters: Optional[list[tuple[str, int]]] = None,
        show_tokens: bool = False
    ) -> AnalysisResult:
        """
        Analyze one or more EVTX files for suspicious activity.

        Args:
            file_path: Path to the EVTX file, or list of paths for multi-file analysis
            filter_relevant: If True, filter to security-relevant events first
            max_events: Maximum events to analyze after filtering (uses config default if None)
            batch_size: Events per batch for large files (uses config default if None)
            smart_filter: If True, use AI to identify relevant Event IDs first
            filter_event_ids: Optional list of Event IDs to filter to (overrides smart_filter)
            filter_metadata: Optional dict mapping Event IDs to metadata (type, reason) from filter file
            provider_filters: Optional list of (provider, event_id) tuples for provider-aware filtering
            show_tokens: If True, display token usage for each API call

        Returns:
            AnalysisResult with findings and summary
        """
        batch_size = batch_size or self.config.batch_size

        # Reset cancellation flag for new analysis
        self.reset_cancellation()

        # Set token display preference
        self._show_tokens = show_tokens

        # Reset token tracking for this analysis
        self._total_input_tokens = 0
        self._total_output_tokens = 0

        # Handle single file or multiple files
        if isinstance(file_path, str):
            file_paths = [file_path]
        else:
            file_paths = list(file_path)

        is_multi_file = len(file_paths) > 1

        # Parse EVTX file(s) - always parse all events
        all_events = []
        for fp in file_paths:
            print(f"Parsing {fp}...")
            file_events = parse_evtx_file(fp, max_events=None)
            all_events.extend(file_events)
            print(f"  Found {len(file_events)} events")

        # Sort all events by timestamp for proper correlation
        all_events.sort(key=lambda e: e.timestamp)

        # Cache all parsed events for potential storage
        self._all_events_cache = all_events

        if is_multi_file:
            print(f"Total events from {len(file_paths)} files: {len(all_events)}")
            # For display purposes, show combined path
            display_path = f"{len(file_paths)} files: " + ", ".join(Path(fp).name for fp in file_paths)
        else:
            display_path = file_paths[0]

        # Apply smart filtering for large files
        if filter_event_ids:
            # User provided specific Event IDs to filter
            if provider_filters:
                # Provider-aware filtering from CSV file
                print(f"Filtering to {len(provider_filters)} provider-specific Event IDs from filter file...")
                events = self._apply_provider_filter(all_events, provider_filters, filter_metadata)
            elif filter_metadata:
                print(f"Filtering to {len(filter_event_ids)} Event IDs from filter file...")
                # Show reasons for collection if available
                for eid in filter_event_ids[:5]:
                    if eid in filter_metadata:
                        reason = filter_metadata[eid].get('reason', '')
                        if reason:
                            print(f"  Event {eid}: {reason[:80]}")
                if len(filter_event_ids) > 5:
                    print(f"  ... and {len(filter_event_ids) - 5} more")
                events = [e for e in all_events if e.event_id in filter_event_ids]
            else:
                print(f"Filtering to user-specified Event IDs: {filter_event_ids}")
                events = [e for e in all_events if e.event_id in filter_event_ids]
        elif smart_filter and len(all_events) > 100:
            # Use AI to identify which Event IDs are security-relevant
            print(f"Using smart filter to identify security-relevant events from {len(all_events)} total...")
            relevant_ids = self._get_smart_filter(all_events)
            if relevant_ids:
                filtered_events = [e for e in all_events if e.event_id in relevant_ids]
                # If still too many events, sample up to max_per_id events per Event ID
                max_per_id = 50  # Limit events per Event ID to avoid overwhelming the API
                if len(filtered_events) > 500:
                    from collections import defaultdict
                    events_by_id = defaultdict(list)
                    for e in filtered_events:
                        events_by_id[e.event_id].append(e)

                    sampled_events = []
                    for eid, eid_events in events_by_id.items():
                        if len(eid_events) > max_per_id:
                            # Take first, last, and evenly spaced samples
                            step = len(eid_events) // max_per_id
                            sampled = eid_events[::step][:max_per_id]
                            sampled_events.extend(sampled)
                        else:
                            sampled_events.extend(eid_events)

                    events = sorted(sampled_events, key=lambda e: e.timestamp)
                    print(f"Sampled to {len(events)} events (max {max_per_id} per Event ID)")
                else:
                    events = filtered_events
                print(f"Smart filter selected {len(events)} events with Event IDs: {sorted(relevant_ids)}")
            else:
                # Fallback to standard filter
                events = filter_security_relevant_events(all_events) if filter_relevant else all_events
        elif filter_relevant:
            events = filter_security_relevant_events(all_events)
            if not events:
                events = all_events
        else:
            events = all_events

        self._events_cache = events
        print(f"Analyzing {len(events)} events (from {len(all_events)} total)...")

        # Get relevant learnings using fast Event ID-based lookup
        event_ids_in_batch = set(e.event_id for e in events)
        learnings = self.learnings_store.get_learnings_by_event_ids(event_ids_in_batch, limit=10)

        # Fall back to vector search if no Event ID-based learnings found
        if not learnings:
            events_summary = events_to_summary(events)
            learnings = self.learnings_store.get_relevant_learnings(events_summary, limit=10)

        if learnings:
            print(f"Applying {len(learnings)} relevant learnings from past feedback...")

        # Get relevant correlation rules
        event_ids_in_batch = set(e.event_id for e in events)
        correlation_rules = self.learnings_store.get_correlation_rules_for_events(event_ids_in_batch)
        if correlation_rules:
            print(f"Applying {len(correlation_rules)} correlation rules...")

        # Create analysis ID early so we can use it for event storage
        analysis_id = f"analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:8]}"

        # Save all parsed events to DB for later querying
        print(f"Saving {len(all_events)} events to database...")
        self.events_store.save_events(analysis_id, all_events)

        # Determine if we need batch processing
        if len(events) > batch_size:
            findings, summary = self._analyze_events_batched(events, learnings, batch_size, correlation_rules)
        else:
            findings, summary = self._analyze_events(events, learnings, correlation_rules=correlation_rules)

        result = AnalysisResult(
            id=analysis_id,
            file_path=display_path,
            total_events=len(all_events),
            events_analyzed=len(events),
            findings=findings,
            learnings_applied=[l.id for l in learnings],
            summary=summary
        )

        # Update learnings usage
        if learnings:
            self.learnings_store.update_applied([l.id for l in learnings])

        # Update correlation rules usage
        if correlation_rules:
            self.learnings_store.update_correlation_applied([r.id for r in correlation_rules])

        # Save to history
        self.learnings_store.save_analysis(
            analysis_id, display_path, len(all_events), findings, [l.id for l in learnings]
        )

        # Print total token usage
        if self._show_tokens:
            print(f"Total tokens used: {self._total_input_tokens:,} input, {self._total_output_tokens:,} output")

        self.current_analysis = result
        return result

    def _analyze_events_batched(
        self,
        events: list[WindowsEvent],
        learnings: list[Learning],
        batch_size: int,
        correlation_rules: Optional[list[CorrelationRule]] = None
    ) -> tuple[list[Finding], str]:
        """Analyze events in batches and aggregate findings."""
        import time

        all_findings: list[Finding] = []
        batch_summaries: list[str] = []
        total_batches = (len(events) + batch_size - 1) // batch_size

        # Rate limit: 30k tokens/min. With 20 events/batch (~10k tokens), ~3 batches/min safe
        batch_delay = 5  # Start with 5s, increase if rate limited

        print(f"Processing {len(events)} events in {total_batches} batches of {batch_size}...")

        for batch_num in range(total_batches):
            # Check for cancellation at the start of each batch
            self._check_cancelled()

            start_idx = batch_num * batch_size
            end_idx = min(start_idx + batch_size, len(events))
            batch_events = events[start_idx:end_idx]

            print(f"  Batch {batch_num + 1}/{total_batches}: events {start_idx + 1}-{end_idx}...")

            # Wait between batches to respect rate limit (check for cancellation during wait)
            if batch_num > 0:
                # Use smaller sleep intervals to allow faster cancellation response
                for _ in range(batch_delay):
                    self._check_cancelled()
                    time.sleep(1)

            # Analyze this batch with retry on rate limit
            max_retries = 3
            for attempt in range(max_retries):
                try:
                    batch_findings, batch_summary = self._analyze_events(
                        batch_events, learnings, batch_offset=start_idx,
                        correlation_rules=correlation_rules
                    )
                    break
                except anthropic.RateLimitError as e:
                    if attempt < max_retries - 1:
                        # Increase delay for future batches
                        batch_delay = min(batch_delay + 10, 45)
                        wait_time = 30 * (attempt + 1)  # 30s, 60s, 90s
                        print(f"    Rate limited, waiting {wait_time}s...")
                        # Use smaller sleep intervals to allow faster cancellation response
                        for _ in range(wait_time):
                            self._check_cancelled()
                            time.sleep(1)
                    else:
                        raise

            # Collect findings with updated IDs to avoid collisions
            for i, finding in enumerate(batch_findings):
                finding.id = f"finding_{datetime.now().strftime('%Y%m%d%H%M%S')}_b{batch_num}_{i}"
                all_findings.append(finding)

            batch_summaries.append(f"Batch {batch_num + 1} ({start_idx + 1}-{end_idx}): {batch_summary}")

        # Deduplicate similar findings
        deduplicated_findings = self._deduplicate_findings(all_findings)

        # Create overall summary
        if len(batch_summaries) > 1:
            overall_summary = self._create_aggregate_summary(deduplicated_findings, batch_summaries)
        else:
            overall_summary = batch_summaries[0] if batch_summaries else "Analysis complete."

        print(f"Found {len(deduplicated_findings)} unique findings across all batches.")
        return deduplicated_findings, overall_summary

    def _deduplicate_findings(self, findings: list[Finding]) -> list[Finding]:
        """
        Merge duplicate findings based on technique and normalized title similarity.

        Instead of discarding duplicates, this merges them into a single finding
        with multiple instances, preserving the unique details of each occurrence.

        Uses fuzzy matching to group findings that are semantically similar
        (e.g., "Active Akira Ransomware Deployment" and "Akira Ransomware - Active Deployment").
        """
        if not findings:
            return []

        # Filter out low-confidence findings (noise reduction)
        min_conf = self.config.min_confidence_score
        high_confidence = [f for f in findings if f.confidence >= min_conf]
        filtered_count = len(findings) - len(high_confidence)
        if filtered_count > 0:
            print(f"  Filtered {filtered_count} findings below {min_conf:.0%} confidence")
        findings = high_confidence

        if not findings:
            return []

        # Sort by severity (critical first) and confidence (highest first)
        severity_order = {
            Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2,
            Severity.LOW: 3, Severity.INFO: 4
        }
        sorted_findings = sorted(
            findings,
            key=lambda f: (severity_order.get(f.severity, 5), -f.confidence)
        )

        # Group findings by signature using fuzzy matching
        signature_to_findings: dict[str, list[Finding]] = {}
        for finding in sorted_findings:
            # Create a normalized signature for grouping
            signature = self._create_finding_signature(finding)

            # Check if this finding should merge with an existing group
            merged = False
            for existing_sig, existing_findings in list(signature_to_findings.items()):
                # Primary: signature-based matching
                if self._signatures_match(signature, existing_sig):
                    signature_to_findings[existing_sig].append(finding)
                    merged = True
                    break
                # Secondary: security context matching (same process + PID = same activity)
                if self._security_context_matches(finding, existing_findings[0]):
                    signature_to_findings[existing_sig].append(finding)
                    merged = True
                    break

            if not merged:
                signature_to_findings[signature] = [finding]

        # Merge findings with the same signature
        merged_findings: list[Finding] = []
        for signature, group in signature_to_findings.items():
            if len(group) == 1:
                # Single occurrence - no merging needed
                merged_findings.append(group[0])
            else:
                # Multiple occurrences - merge into one finding with instances
                primary = group[0]  # Highest severity/confidence

                # Create instances list from all occurrences
                instances: list[FindingInstance] = []
                all_related_events: list[dict] = []
                all_correlations: list[MatchedCorrelation] = []

                for f in group:
                    # Create an instance detail string
                    instance_detail = self._create_instance_detail(f)

                    # Get timestamp from related events or finding timestamp
                    instance_timestamp = f.timestamp
                    if f.related_events:
                        timestamps = [e.get("timestamp") for e in f.related_events if e.get("timestamp")]
                        if timestamps:
                            try:
                                parsed_ts = datetime.fromisoformat(min(timestamps).replace("Z", "+00:00"))
                                # Convert to naive datetime for consistent comparison
                                instance_timestamp = parsed_ts.replace(tzinfo=None)
                            except (ValueError, AttributeError):
                                pass

                    # Ensure timestamp is naive for consistent sorting
                    if instance_timestamp.tzinfo is not None:
                        instance_timestamp = instance_timestamp.replace(tzinfo=None)

                    # Only add instances that have meaningful details
                    # Skip instances with no details to avoid cluttering the report
                    if instance_detail:
                        instance = FindingInstance(
                            timestamp=instance_timestamp,
                            security_context=f.security_context,
                            related_events=f.related_events,
                            matched_correlations=f.matched_correlations,
                            instance_detail=instance_detail
                        )
                        instances.append(instance)

                    # Collect all related events (for comprehensive view)
                    all_related_events.extend(f.related_events)
                    all_correlations.extend(f.matched_correlations)

                # Sort instances by timestamp (all naive now)
                instances.sort(key=lambda i: i.timestamp)

                # Deduplicate correlations by rule_id
                seen_rule_ids = set()
                unique_correlations = []
                for mc in all_correlations:
                    if mc.rule_id not in seen_rule_ids:
                        seen_rule_ids.add(mc.rule_id)
                        unique_correlations.append(mc)

                # Create merged finding
                merged = Finding(
                    id=primary.id,
                    timestamp=primary.timestamp,
                    severity=primary.severity,
                    title=primary.title,
                    description=primary.description,
                    technique=primary.technique,
                    tactic=primary.tactic,
                    confidence=primary.confidence,
                    related_events=all_related_events,
                    recommendation=primary.recommendation,
                    security_context=primary.security_context,
                    matched_correlations=unique_correlations,
                    instances=instances
                )
                merged_findings.append(merged)

        return merged_findings

    def _create_instance_detail(self, finding: Finding) -> str:
        """Create a brief description of what makes this instance unique."""
        details = []
        sc = finding.security_context

        if sc:
            # File-related (ransomware README, encrypted files)
            if sc.target_filename:
                details.append(sc.target_filename)

            # Process info
            if sc.process_name:
                proc = sc.process_name
                if sc.process_id:
                    proc += f" (PID {sc.process_id})"
                details.append(proc)

            # User info
            if sc.user_name:
                user = f"{sc.user_domain}\\{sc.user_name}" if sc.user_domain else sc.user_name
                details.append(user)

            # Network info
            if sc.source_ip and sc.source_ip not in ("-", "::1", "127.0.0.1"):
                details.append(f"from {sc.source_ip}")

            if sc.destination_ip:
                details.append(f"to {sc.destination_ip}")

        # If no details from security context, try to extract from related events
        if not details and finding.related_events:
            for event in finding.related_events[:3]:  # Check first 3 events
                data = event.get("data", {})
                event_details = []

                # Try multiple common fields
                field_mappings = [
                    ("TargetFilename", None),
                    ("RelativeTargetName", None),
                    ("ShareName", None),
                    ("ObjectName", None),
                    ("Image", None),
                    ("ProcessName", None),
                    ("TargetUserName", "User: "),
                    ("SubjectUserName", "User: "),
                    ("IpAddress", "IP: "),
                    ("SourceAddress", "Source: "),
                ]

                for key, prefix in field_mappings:
                    if key in data and data[key] and data[key] not in ("-", ""):
                        value = data[key]
                        # Truncate long paths
                        if len(value) > 60:
                            value = "..." + value[-57:]
                        if prefix:
                            event_details.append(f"{prefix}{value}")
                        else:
                            event_details.append(value)
                        if len(event_details) >= 3:
                            break

                if event_details:
                    details.extend(event_details)
                    break

        return " | ".join(details) if details else ""

    def _create_finding_signature(self, finding: Finding) -> str:
        """
        Create a normalized signature for grouping similar findings.

        The signature consists of:
        1. MITRE technique (primary grouping key)
        2. Normalized key terms from the title
        """
        technique = finding.technique or "unknown"

        # Normalize the title to extract key terms
        title_lower = finding.title.lower()

        # Remove common filler words and punctuation
        filler_words = {
            "the", "a", "an", "via", "from", "to", "with", "and", "or", "for",
            "multiple", "detected", "activity", "suspicious", "potential",
            "possible", "observed", "access", "accessed", "accessing", "active",
            "remote", "note", "notes", "drops", "drop", "created", "creation",
            "file", "files", "system", "directory", "enumeration", "windows",
            "during", "based", "using", "user", "infrastructure", "protection",
            "location", "pattern", "performing", "external", "connection",
            "connections", "high", "privileges", "process"
        }

        # Synonyms/equivalents to normalize
        term_normalizations = {
            "deployment": "deploy",
            "deployed": "deploy",
            "deploying": "deploy",
            "executed": "execution",
            "executing": "execution",
            "lateral": "lateralmove",
            "movement": "lateralmove",
            "administrative": "admin",
            "administrator": "admin",
            "unauthorized": "unauth",
            "ransom": "ransomware",
            "credential": "cred",
            "credentials": "cred",
            "storage": "store",
            "stored": "store",
            "share": "smb",
            "shares": "smb",
            "smb": "smb",
            # C2/network communication synonyms
            "beacon": "c2",
            "beaconing": "c2",
            "communication": "c2",
            "communications": "c2",
            "network": "c2",
            "c2": "c2",
            # Executable variants
            "executable": "exe",
            "exe": "exe",
            "binary": "exe",
            # Desktop/user location
            "desktop": "userloc",
            "userprofile": "userloc",
        }

        # Extract key terms
        words = re.findall(r'[a-z0-9]+', title_lower)
        key_terms = []
        for w in words:
            if w in filler_words or len(w) <= 2:
                continue
            # Normalize the term
            normalized = term_normalizations.get(w, w)
            key_terms.append(normalized)

        # Sort for consistent ordering
        key_terms_sorted = sorted(set(key_terms))

        return f"{technique}|{'_'.join(key_terms_sorted)}"

    def _signatures_match(self, sig1: str, sig2: str) -> bool:
        """
        Check if two signatures represent the same type of finding.

        Uses Jaccard similarity on key terms with technique compatibility check.
        """
        parts1 = sig1.split("|")
        parts2 = sig2.split("|")

        technique1 = parts1[0]
        technique2 = parts2[0]

        # Check if techniques are compatible (same or in same family)
        if not self._techniques_compatible(technique1, technique2):
            return False

        # Get key terms
        terms1 = set(parts1[1].split("_")) if len(parts1) > 1 else set()
        terms2 = set(parts2[1].split("_")) if len(parts2) > 1 else set()

        if not terms1 or not terms2:
            return False

        # Calculate Jaccard similarity
        intersection = len(terms1 & terms2)
        union = len(terms1 | terms2)

        if union == 0:
            return False

        similarity = intersection / union

        # Require at least 50% overlap for merging
        # This allows "Akira Ransomware Deployment" to match "Active Akira Ransomware"
        return similarity >= 0.5

    def _techniques_compatible(self, tech1: str, tech2: str) -> bool:
        """
        Check if two MITRE techniques are compatible for merging.

        Techniques are compatible if they:
        1. Are exactly the same
        2. Share the same parent technique (e.g., T1555.004 and T1552.004 both relate to credentials)
        3. Are in the same technique family group
        """
        if tech1 == tech2:
            return True

        # Both unknown
        if tech1 == "unknown" and tech2 == "unknown":
            return True

        # One unknown, one known - don't merge
        if tech1 == "unknown" or tech2 == "unknown":
            return False

        # Get base technique (e.g., T1555.004 -> T1555)
        base1 = tech1.split(".")[0] if "." in tech1 else tech1
        base2 = tech2.split(".")[0] if "." in tech2 else tech2

        # Same base technique family (e.g., T1555.001 and T1555.004)
        if base1 == base2:
            return True

        # Define technique families that should be merged together
        # These are techniques that often describe the same underlying activity
        technique_families = [
            # Credential access techniques
            {"T1552", "T1555", "T1003"},  # Unsecured Credentials, Credentials from Password Stores, OS Credential Dumping
            # Discovery/enumeration techniques
            {"T1083", "T1135", "T1082"},  # File Discovery, Network Share Discovery, System Info Discovery
            # Lateral movement techniques
            {"T1021", "T1570"},  # Remote Services, Lateral Tool Transfer
            # C2/network/masquerading - often describe same suspicious exe activity
            {"T1071", "T1036", "T1105"},  # App Layer Protocol, Masquerading, Ingress Tool Transfer
            # Process injection variants
            {"T1055", "T1059"},  # Process Injection, Command and Scripting Interpreter
        ]

        for family in technique_families:
            if base1 in family and base2 in family:
                return True

        return False

    def _security_context_matches(self, finding1: Finding, finding2: Finding) -> bool:
        """
        Check if two findings describe the same activity based on security context.

        If both findings reference the same process (name + PID), they're likely
        describing different aspects of the same malicious activity.
        """
        sc1 = finding1.security_context
        sc2 = finding2.security_context

        if not sc1 or not sc2:
            return False

        # Same process name + PID = same activity
        if (sc1.process_name and sc2.process_name and
            sc1.process_id and sc2.process_id and
            sc1.process_name.lower() == sc2.process_name.lower() and
            sc1.process_id == sc2.process_id):
            return True

        return False

    def _create_aggregate_summary(
        self,
        findings: list[Finding],
        batch_summaries: list[str]
    ) -> str:
        """Create a chronological summary with rich context about detected activity."""
        if not findings:
            return "No suspicious activity detected in the analyzed events."

        # Filter findings by confidence threshold
        threshold = self.config.confidence_threshold
        filtered_findings = [f for f in findings if f.severity >= threshold]

        if not filtered_findings:
            hidden_count = len(findings)
            return f"No findings at {threshold.value.upper()} severity or above. ({hidden_count} lower-priority findings hidden)"

        # Sort findings by timestamp from their related events
        def get_earliest_timestamp(finding: Finding) -> str:
            timestamps = []
            for event in finding.related_events:
                if event.get("timestamp"):
                    timestamps.append(event["timestamp"])
            return min(timestamps) if timestamps else "9999"

        sorted_findings = sorted(filtered_findings, key=get_earliest_timestamp)

        # Count by severity (from filtered findings)
        critical_count = sum(1 for f in filtered_findings if f.severity == Severity.CRITICAL)
        high_count = sum(1 for f in filtered_findings if f.severity == Severity.HIGH)
        medium_count = sum(1 for f in filtered_findings if f.severity == Severity.MEDIUM)

        # Build header
        summary_parts = []
        severity_parts = []
        if critical_count:
            severity_parts.append(f"{critical_count} critical")
        if high_count:
            severity_parts.append(f"{high_count} high")
        if medium_count:
            severity_parts.append(f"{medium_count} medium")

        if severity_parts:
            summary_parts.append(f"Detected {', '.join(severity_parts)} severity finding(s).")
        else:
            summary_parts.append(f"Detected {len(filtered_findings)} finding(s).")

        summary_parts.append("")
        summary_parts.append("Activity Summary:")

        # Build chronological list with context
        for i, finding in enumerate(sorted_findings, 1):
            sc = finding.security_context

            # Build context string
            context_parts = []

            if sc:
                # User info
                if sc.user_name:
                    user = f"{sc.user_domain}\\{sc.user_name}" if sc.user_domain else sc.user_name
                    context_parts.append(f"User: {user}")

                # Process info
                if sc.process_name:
                    proc = sc.process_name
                    if sc.process_id:
                        proc += f" (PID {sc.process_id})"
                    context_parts.append(f"Process: {proc}")

                # Parent process
                if sc.parent_process_name:
                    parent = sc.parent_process_name
                    if sc.parent_process_id:
                        parent += f" (PID {sc.parent_process_id})"
                    context_parts.append(f"Parent: {parent}")

                # Network info
                if sc.source_ip and sc.source_ip not in ("-", "::1", "127.0.0.1"):
                    src = sc.source_ip
                    if sc.source_hostname and sc.source_hostname != "-":
                        src = f"{sc.source_hostname} ({sc.source_ip})"
                    context_parts.append(f"Source: {src}")

                if sc.destination_ip:
                    context_parts.append(f"Destination: {sc.destination_ip}")

            # Correlation rule info
            correlation_str = ""
            if finding.matched_correlations:
                rule_names = [mc.rule_name for mc in finding.matched_correlations if mc.rule_name]
                if rule_names:
                    correlation_str = f" [Matched: {', '.join(rule_names)}]"

            # Build the entry
            severity_indicator = finding.severity.value[0].upper()  # C, H, M, L, I

            entry = f"[{severity_indicator}] {finding.title}"
            if finding.technique:
                entry += f" ({finding.technique})"
            if correlation_str:
                entry += correlation_str

            summary_parts.append(entry)

            # Add context on next line if available
            if context_parts:
                summary_parts.append(f"    → {' | '.join(context_parts)}")

        # Note about hidden findings
        hidden_count = len(findings) - len(filtered_findings)
        if hidden_count > 0:
            summary_parts.append("")
            summary_parts.append(f"({hidden_count} findings below {threshold.value.upper()} threshold hidden)")

        return "\n".join(summary_parts)

    def _apply_provider_filter(
        self,
        events: list[WindowsEvent],
        provider_filters: list[tuple[str, int]],
        filter_metadata: Optional[dict] = None
    ) -> list[WindowsEvent]:
        """
        Filter events by provider/channel AND Event ID.

        Provider matching supports:
            - Exact match: "Microsoft-Windows-Sysmon/Operational"
            - Provider name match: "Microsoft-Windows-Sysmon"
            - Short alias match: "Sysmon", "Security", "PowerShell"
        """
        # Build provider aliases for flexible matching
        provider_aliases = {
            'sysmon': ['microsoft-windows-sysmon', 'microsoft-windows-sysmon/operational'],
            'security': ['microsoft-windows-security-auditing', 'security'],
            'powershell': ['microsoft-windows-powershell', 'microsoft-windows-powershell/operational', 'powershell'],
            'defender': ['microsoft-windows-windows defender', 'microsoft-windows-windows defender/operational'],
            'applocker': ['microsoft-windows-applocker', 'microsoft-windows-applocker/exe and dll', 'microsoft-windows-applocker/msi and script'],
            'bits': ['microsoft-windows-bits-client', 'microsoft-windows-bits-client/operational'],
            'wmi': ['microsoft-windows-wmi-activity', 'microsoft-windows-wmi-activity/operational'],
            'taskscheduler': ['microsoft-windows-taskscheduler', 'microsoft-windows-taskscheduler/operational'],
            'firewall': ['microsoft-windows-windows firewall with advanced security', 'microsoft-windows-windows firewall with advanced security/firewall'],
            'jonmon': ['jonmon', 'jonmon/operational'],
            'dotnet': ['microsoft-windows-dotnetruntime', 'microsoft-windows-dotnetruntime/operational', '.net runtime', 'clr'],
        }

        def matches_provider(event: WindowsEvent, filter_provider: str) -> bool:
            """Check if event matches the specified provider filter."""
            filter_lower = filter_provider.lower().strip()

            # Get event's provider and channel
            event_provider = (event.provider or '').lower()
            event_channel = (event.channel or '').lower()

            # Direct match on provider or channel
            if filter_lower in event_provider or filter_lower in event_channel:
                return True
            if event_provider in filter_lower or event_channel in filter_lower:
                return True

            # Check aliases
            for alias, full_names in provider_aliases.items():
                if filter_lower == alias or filter_lower in full_names:
                    # Filter uses this alias, check if event matches any of the full names
                    for full_name in full_names:
                        if full_name in event_provider or full_name in event_channel:
                            return True
                    if alias in event_provider or alias in event_channel:
                        return True

            return False

        # Filter events
        filtered_events = []
        matched_filters = set()

        for event in events:
            for provider, event_id in provider_filters:
                if event.event_id == event_id and matches_provider(event, provider):
                    filtered_events.append(event)
                    matched_filters.add((provider, event_id))
                    break

        # Show what we matched
        print(f"  Matched {len(filtered_events)} events from {len(matched_filters)} filter rules:")
        shown = 0
        for provider, event_id in sorted(matched_filters, key=lambda x: (x[0], x[1])):
            if shown < 5:
                # Try to get reason from metadata
                reason = ""
                if filter_metadata:
                    meta = filter_metadata.get((provider, event_id), {})
                    reason = meta.get('reason', '')[:50]
                if reason:
                    print(f"    {provider} Event {event_id}: {reason}")
                else:
                    print(f"    {provider} Event {event_id}")
                shown += 1
        if len(matched_filters) > 5:
            print(f"    ... and {len(matched_filters) - 5} more")

        return filtered_events

    def _get_smart_filter(self, events: list[WindowsEvent]) -> set[int]:
        """
        Use AI to identify which Event IDs are security-relevant for this file.

        Makes a single lightweight API call with a summary of the file's events,
        and returns the set of Event IDs that should be analyzed.
        """
        from collections import Counter

        # Build a summary of what's in the file
        event_id_counts = Counter(e.event_id for e in events)
        providers = set(e.provider for e in events if e.provider)
        channels = set(e.channel for e in events if e.channel)

        # Get sample event data keys for context
        sample_data_keys = set()
        for e in events[:50]:
            sample_data_keys.update(e.event_data.keys())

        summary = f"""Event Log Summary:
- Total events: {len(events)}
- Providers: {', '.join(sorted(providers)[:10]) or 'Unknown'}
- Channels: {', '.join(sorted(channels)[:5]) or 'Unknown'}
- Event ID distribution (ID: count):
{chr(10).join(f'  {eid}: {count}' for eid, count in event_id_counts.most_common(30))}
- Sample data fields: {', '.join(sorted(sample_data_keys)[:20])}"""

        try:
            # Check for cancellation before API call
            self._check_cancelled()

            response = self.client.messages.create(
                model=self.config.model,
                max_tokens=500,
                system="""You are a security analyst. Given a summary of a Windows Event Log file,
identify which Event IDs are security-relevant and should be analyzed for threats.

Consider:
- Events that could indicate attacks, persistence, lateral movement, exfiltration
- Events from security-relevant providers (Security, Sysmon, PowerShell, etc.)
- Events that show process creation, network activity, authentication, privilege changes
- For .NET/CLR logs: focus on assembly loading, JIT compilation anomalies, exceptions
- For RPC logs: focus on calls that could indicate lateral movement or exploitation

Return ONLY a JSON object with a list of Event IDs to analyze:
{"event_ids": [1, 4624, 4688, ...], "reason": "brief explanation"}""",
                messages=[{
                    "role": "user",
                    "content": f"Identify security-relevant Event IDs from this log:\n\n{summary}"
                }]
            )

            # Track token usage
            self._total_input_tokens += response.usage.input_tokens
            self._total_output_tokens += response.usage.output_tokens
            if self._show_tokens:
                print(f"  Smart filter tokens: {response.usage.input_tokens:,} in / {response.usage.output_tokens:,} out")

            response_text = response.content[0].text

            # Parse the JSON response
            if "```json" in response_text:
                json_str = response_text.split("```json")[1].split("```")[0]
            elif "```" in response_text:
                json_str = response_text.split("```")[1].split("```")[0]
            else:
                json_str = response_text

            result = json.loads(json_str)
            event_ids = set(result.get("event_ids", []))

            if result.get("reason"):
                print(f"  Filter reason: {result['reason']}")

            return event_ids

        except Exception as e:
            print(f"  Smart filter failed ({e}), using default filter...")
            return set()

    def _analyze_events(
        self,
        events: list[WindowsEvent],
        learnings: list[Learning],
        batch_offset: int = 0,
        correlation_rules: Optional[list[CorrelationRule]] = None
    ) -> tuple[list[Finding], str]:
        """Send events to Claude for analysis.

        Args:
            events: List of events to analyze
            learnings: Relevant learnings to apply
            batch_offset: Offset for event indices when processing in batches
            correlation_rules: Correlation rules to apply
        """
        # Build learnings context
        learnings_context = ""
        if learnings:
            learnings_context = "\n\n## Insights from past analyses (apply these):\n"
            for l in learnings:
                learnings_context += f"- {l.insight}\n"

        # Build correlation rules context
        correlation_context = ""
        if correlation_rules:
            correlation_context = CORRELATION_CONTEXT_HEADER
            for rule in correlation_rules:
                correlation_context += rule.to_prompt_context() + "\n"

        # Prepare events for analysis - OPTIMIZED for minimal tokens
        events_data = []
        for i, event in enumerate(events):
            # Only include non-empty data fields, aggressively truncate
            trimmed_data = {}
            for key, value in event.event_data.items():
                if value is not None and value != '':
                    if isinstance(value, str):
                        # Aggressive truncation - 150 chars max
                        value = value[:150] + '...' if len(value) > 150 else value
                    trimmed_data[key] = value

            # Minimal event structure
            event_dict = {
                "i": batch_offset + i,
                "ts": event.timestamp.strftime("%H:%M:%S"),
                "id": event.event_id,
                "p": event.provider,
                "d": trimmed_data
            }
            # Only add optional fields if present
            if event.user_sid:
                event_dict["u"] = event.user_sid
            events_data.append(event_dict)

        # Check for cancellation before API call
        self._check_cancelled()

        # Call Claude - compact JSON, no pretty printing
        response = self.client.messages.create(
            model=self.config.model,
            max_tokens=4096,
            system=ANALYSIS_SYSTEM_PROMPT + learnings_context + correlation_context,
            messages=[{
                "role": "user",
                "content": f"""Analyze events for threats. Return JSON: {{"findings":[{{"severity":"...","title":"...","description":"...","technique":"T____","tactic":"...","confidence":0.0-1.0,"related_event_indices":[...],"recommendation":"..."}}],"summary":"..."}}

Events (i=index,ts=time,id=EventID,p=provider,d=data,u=user):
{json.dumps(events_data, separators=(',', ':'), default=str)}"""
            }]
        )

        # Track token usage
        input_tokens = response.usage.input_tokens
        output_tokens = response.usage.output_tokens
        self._total_input_tokens += input_tokens
        self._total_output_tokens += output_tokens
        if self._show_tokens:
            print(f"  Tokens: {input_tokens:,} in / {output_tokens:,} out")
        
        # Parse response
        response_text = response.content[0].text
        
        # Extract JSON from response
        findings = []
        summary = ""
        
        try:
            # Try to find JSON in the response
            json_match = response_text
            if "```json" in response_text:
                json_match = response_text.split("```json")[1].split("```")[0]
            elif "```" in response_text:
                json_match = response_text.split("```")[1].split("```")[0]
            
            result = json.loads(json_match)
            
            # Parse findings
            for i, f in enumerate(result.get("findings", [])):
                finding_id = f"finding_{datetime.now().strftime('%Y%m%d%H%M%S')}_{i}"

                # Get related events
                related_events = []
                for idx in f.get("related_event_indices", []):
                    if 0 <= idx < len(events):
                        event = events[idx]
                        related_events.append({
                            "event_id": event.event_id,
                            "timestamp": event.timestamp.isoformat(),
                            "data": event.event_data
                        })

                # Parse security context if provided
                security_context = None
                if f.get("security_context"):
                    sc = f["security_context"]
                    security_context = SecurityContext(
                        process_name=_safe_str(sc.get("process_name")),
                        process_id=_safe_int(sc.get("process_id")),
                        process_command_line=_safe_str(sc.get("process_command_line")),
                        parent_process_name=_safe_str(sc.get("parent_process_name")),
                        parent_process_id=_safe_int(sc.get("parent_process_id")),
                        user_name=_safe_str(sc.get("user_name")),
                        user_domain=_safe_str(sc.get("user_domain")),
                        user_sid=_safe_str(sc.get("user_sid")),
                        logon_id=_safe_str(sc.get("logon_id")),
                        logon_type=_safe_int(sc.get("logon_type")),
                        source_ip=_safe_str(sc.get("source_ip")),
                        source_port=_safe_int(sc.get("source_port")),
                        destination_ip=_safe_str(sc.get("destination_ip")),
                        destination_port=_safe_int(sc.get("destination_port")),
                        source_hostname=_safe_str(sc.get("source_hostname")),
                        target_filename=_safe_str(sc.get("target_filename")),
                        registry_key=_safe_str(sc.get("registry_key")),
                        registry_value=_safe_str(sc.get("registry_value")),
                        assembly_name=_safe_str(sc.get("assembly_name")),
                        clr_version=_safe_str(sc.get("clr_version")),
                        target_user_name=_safe_str(sc.get("target_user_name")),
                        target_user_domain=_safe_str(sc.get("target_user_domain")),
                        target_logon_id=_safe_str(sc.get("target_logon_id")),
                        service_name=_safe_str(sc.get("service_name")),
                        task_name=_safe_str(sc.get("task_name")),
                        additional_fields=sc.get("additional_fields", {})
                    )

                # Parse matched correlations if provided
                matched_correlations = []
                for mc in f.get("matched_correlations", []):
                    # Try to find the rule_id from our correlation rules
                    rule_id = ""
                    if correlation_rules:
                        for rule in correlation_rules:
                            if rule.name == mc.get("rule_name"):
                                rule_id = rule.id
                                break

                    # Handle both old format (correlation_field) and new format (source_field/target_field)
                    source_field = mc.get("source_field") or mc.get("correlation_field", "")
                    target_field = mc.get("target_field") or mc.get("correlation_field", "")

                    matched_correlations.append(MatchedCorrelation(
                        rule_id=rule_id,
                        rule_name=mc.get("rule_name", ""),
                        source_event_id=mc.get("source_event_id", 0),
                        target_event_id=mc.get("target_event_id", 0),
                        source_field=source_field,
                        target_field=target_field,
                        matched_value=mc.get("matched_value")
                    ))

                finding = Finding(
                    id=finding_id,
                    severity=Severity(f.get("severity", "medium")),
                    title=f.get("title", "Unknown"),
                    description=f.get("description", ""),
                    technique=f.get("technique"),
                    tactic=f.get("tactic"),
                    confidence=float(f.get("confidence", 0.5)),
                    related_events=related_events,
                    recommendation=f.get("recommendation", ""),
                    security_context=security_context,
                    matched_correlations=matched_correlations
                )
                findings.append(finding)
            
            summary = result.get("summary", "Analysis complete.")
            
        except (json.JSONDecodeError, KeyError, IndexError) as e:
            # If JSON parsing fails, create a single finding with the raw response
            print(f"Warning: Could not parse structured response: {e}")
            findings = [Finding(
                id=f"finding_{datetime.now().strftime('%Y%m%d%H%M%S')}_0",
                severity=Severity.INFO,
                title="Analysis Results",
                description=response_text,
                confidence=0.5
            )]
            summary = "Analysis complete (unstructured response)"
        
        return findings, summary
    
    def add_feedback(
        self,
        finding_id: str,
        verdict: Verdict,
        explanation: str,
        event_ids_override: list[int] | None = None
    ) -> Learning:
        """
        Add analyst feedback on a finding.

        Args:
            finding_id: ID of the finding to provide feedback on
            verdict: Analyst verdict (false_positive, true_positive, etc.)
            explanation: Analyst's explanation
            event_ids_override: Optional list of Event IDs to use instead of auto-extraction

        Returns:
            The created Learning object
        """
        # Find the original finding and extract Event IDs
        finding_summary = ""
        event_ids: list[int] = []

        # If override provided, use it; otherwise auto-extract from finding
        if event_ids_override:
            event_ids = event_ids_override
        elif self.current_analysis:
            for f in self.current_analysis.findings:
                if f.id == finding_id:
                    finding_summary = f"{f.title}: {f.description[:200]}"
                    # Extract Event IDs from related events
                    for related_event in f.related_events:
                        eid = related_event.get('event_id')
                        if eid and eid not in event_ids:
                            event_ids.append(eid)
                    break

        # Still get finding summary if we used override
        if event_ids_override and self.current_analysis:
            for f in self.current_analysis.findings:
                if f.id == finding_id:
                    finding_summary = f"{f.title}: {f.description[:200]}"
                    break

        # Use Claude to extract the insight
        insight = self._extract_insight(finding_summary, verdict, explanation)

        # Extract keywords
        keywords = extract_keywords(f"{explanation} {finding_summary} {insight}")

        # Create learning with Event IDs for fast lookup
        learning = Learning(
            id=f"learning_{datetime.now().strftime('%Y%m%d%H%M%S')}_{uuid.uuid4().hex[:8]}",
            type=verdict,
            original_finding_id=finding_id,
            original_finding_summary=finding_summary,
            analyst_explanation=explanation,
            insight=insight,
            keywords=keywords,
            event_ids=event_ids
        )

        # Store it
        self.learnings_store.add_learning(learning)
        self.learnings_store.save_feedback(finding_id, verdict.value, explanation, learning.id)

        return learning
    
    def _extract_insight(self, finding_summary: str, verdict: Verdict, explanation: str) -> str:
        """Use Claude to extract a reusable insight from feedback."""
        # Check for cancellation before API call
        self._check_cancelled()

        response = self.client.messages.create(
            model=self.config.model,
            max_tokens=500,
            system=LEARNING_EXTRACTION_PROMPT,
            messages=[{
                "role": "user",
                "content": f"""Extract a reusable insight from this analyst feedback.

Finding that was flagged: {finding_summary}
Analyst verdict: {verdict.value}
Analyst explanation: {explanation}

Write a 1-3 sentence insight that can help with future analyses. Be specific about what to look for or ignore."""
            }]
        )

        # Track token usage
        if self._show_tokens:
            print(f"  Learning extraction tokens: {response.usage.input_tokens:,} input, {response.usage.output_tokens:,} output")

        return response.content[0].text.strip()
    
    def get_learnings(self, limit: int = 50) -> list[Learning]:
        """Get all stored learnings."""
        return self.learnings_store.get_all_learnings(limit=limit)

    def search_learnings(self, query: str) -> list[Learning]:
        """Search learnings by keyword or semantic similarity."""
        return self.learnings_store.search_learnings(query)

    def delete_learning(self, learning_id: str) -> bool:
        """Delete a learning."""
        return self.learnings_store.delete_learning(learning_id)

    def update_learning(self, learning_id: str, new_insight: str) -> bool:
        """Update a learning's insight text."""
        return self.learnings_store.update_learning_insight(learning_id, new_insight)

    def update_learning_event_ids(self, learning_id: str, event_ids: list[int]) -> bool:
        """Update a learning's Event IDs for fast lookup."""
        return self.learnings_store.update_learning_event_ids(learning_id, event_ids)

    def get_learning(self, learning_id: str):
        """Get a specific learning by ID."""
        return self.learnings_store.get_learning(learning_id)

    # ==================== Correlation Rules ====================

    def add_correlation_rule(
        self,
        source_event_id: int,
        target_event_id: int,
        source_field: str,
        target_field: str,
        name: str,
        description: str,
        security_context: str,
        source_conditions: Optional[dict] = None,
        target_conditions: Optional[dict] = None,
        severity_hint: Severity = Severity.MEDIUM,
        technique: Optional[str] = None,
        tactic: Optional[str] = None
    ) -> CorrelationRule:
        """
        Add a correlation rule that defines how events should be linked together.

        Supports correlating on different field names between source and target events.

        Example:
            agent.add_correlation_rule(
                source_event_id=4624,
                target_event_id=4688,
                source_field="TargetLogonId",
                target_field="SubjectLogonId",
                name="Network Logon to Process Execution",
                description="Links successful network logons to subsequent process creation",
                security_context="4624 with LogonType 3 correlating to 4688 through LogonId "
                                 "is a good indicator of potential lateral movement",
                source_conditions={"LogonType": "3"},
                severity_hint=Severity.HIGH,
                technique="T1021",
                tactic="Lateral Movement"
            )
        """
        # Extract keywords from the context
        keywords = extract_keywords(
            f"{name} {description} {security_context} "
            f"Event{source_event_id} Event{target_event_id} {source_field} {target_field}"
        )

        rule = CorrelationRule(
            id=f"corr_{datetime.now().strftime('%Y%m%d%H%M%S')}_{uuid.uuid4().hex[:8]}",
            source_event_id=source_event_id,
            source_conditions=source_conditions or {},
            target_event_id=target_event_id,
            target_conditions=target_conditions or {},
            source_field=source_field,
            target_field=target_field,
            name=name,
            description=description,
            security_context=security_context,
            severity_hint=severity_hint,
            technique=technique,
            tactic=tactic,
            keywords=keywords
        )

        self.learnings_store.add_correlation_rule(rule)
        return rule

    def get_correlation_rules(self, limit: int = 50) -> list[CorrelationRule]:
        """Get all stored correlation rules."""
        return self.learnings_store.get_all_correlation_rules(limit=limit)

    def delete_correlation_rule(self, rule_id: str) -> bool:
        """Delete a correlation rule."""
        return self.learnings_store.delete_correlation_rule(rule_id)

    def get_stats(self) -> dict:
        """Get agent statistics."""
        store_stats = self.learnings_store.get_stats()
        return {
            **store_stats,
            "total_stored_events": self.events_store.get_events_count(),
            "model": self.config.model,
            "current_analysis": self.current_analysis.id if self.current_analysis else None
        }

    # ==================== Events Storage ====================

    def get_events(self, analysis_id: Optional[str] = None,
                   event_ids: Optional[list[int]] = None,
                   limit: int = 1000) -> list[dict]:
        """
        Retrieve stored events.

        Args:
            analysis_id: Optional analysis ID to filter by
            event_ids: Optional list of Event IDs to filter by
            limit: Maximum events to return
        """
        if analysis_id:
            return self.events_store.get_events_for_analysis(analysis_id, event_ids, limit)
        else:
            return self.events_store.query_events(event_ids=event_ids, limit=limit)

    def query_events(self,
                     event_ids: Optional[list[int]] = None,
                     provider: Optional[str] = None,
                     start_time: Optional[str] = None,
                     end_time: Optional[str] = None,
                     limit: int = 1000) -> list[dict]:
        """
        Query stored events with flexible filters.

        Args:
            event_ids: Optional list of Event IDs to filter by
            provider: Optional provider name to filter by
            start_time: Optional start timestamp (ISO format)
            end_time: Optional end timestamp (ISO format)
            limit: Maximum events to return
        """
        return self.events_store.query_events(
            event_ids=event_ids,
            provider=provider,
            start_time=start_time,
            end_time=end_time,
            limit=limit
        )

    def get_events_count(self, analysis_id: Optional[str] = None) -> int:
        """Get count of stored events."""
        return self.events_store.get_events_count(analysis_id)

    def clear_events(self, analysis_id: Optional[str] = None) -> int:
        """
        Clear stored events from the database.

        Args:
            analysis_id: Optional analysis ID. If provided, only clear events
                        for that analysis. If None, clear ALL events.

        Returns:
            Number of events deleted
        """
        return self.events_store.clear_events(analysis_id)

    def analyze_continuous(
        self,
        file_path: str,
        filter_event_ids: set[int],
        interval: int = 60,
        batch_size: Optional[int] = None,
        on_finding: Optional[Callable[[Finding], None]] = None,
        max_events_per_iteration: int = 200,
        report_path: Optional[str] = None
    ) -> None:
        """
        Continuous analysis loop for monitoring EVTX files.

        Runs until KeyboardInterrupt, analyzing new events as they appear.
        Streams findings immediately via the on_finding callback.

        Args:
            file_path: Path to the EVTX file to monitor
            filter_event_ids: Set of Event IDs to analyze (others skipped)
            interval: Seconds between checks for new events
            batch_size: Events per analysis batch sent to Claude
            on_finding: Callback called immediately when a finding is detected
            max_events_per_iteration: Max events to process per iteration
            report_path: Optional path to HTML report file (updated on each finding)
        """
        # Use continuous batch size from config if not specified
        if batch_size is None:
            batch_size = self.config.continuous_batch_size

        # Start from "now" - only analyze events that occur after analysis starts
        # Use UTC since EVTX timestamps are in UTC
        from datetime import timezone
        state = ContinuousState(last_timestamp=datetime.now(timezone.utc))

        # Pre-load all learnings for the filter event IDs (no limit)
        learnings = self.learnings_store.get_learnings_by_event_ids(
            filter_event_ids, limit=10000
        )
        correlation_rules = self.learnings_store.get_correlation_rules_for_events(
            filter_event_ids
        )

        print()
        print(f"  ┌────────────────────────────────────────────────────────────────")
        print(f"  │ 🔍 CONTINUOUS ANALYSIS STARTED")
        print(f"  ├────────────────────────────────────────────────────────────────")
        print(f"  │ 📁 File: {file_path}")
        print(f"  │ 🎯 Filter: {len(filter_event_ids)} Event IDs")
        print(f"  │ ⏱️  Interval: {interval}s | Batch size: {batch_size}")
        print(f"  │ 🧠 Learnings loaded: {len(learnings)}")
        print(f"  │ 🔗 Correlation rules: {len(correlation_rules)}")
        print(f"  │ 📌 Mode: Watching for new events only (skipping historical)")
        if report_path:
            print(f"  │ 📄 Report: {report_path}")
        print(f"  └────────────────────────────────────────────────────────────────")
        print()

        # Generate initial HTML report if path provided
        if report_path:
            from .cli import generate_continuous_html_report
            generate_continuous_html_report(
                findings=state.all_findings,
                filename=report_path,
                file_path=file_path,
                start_time=state.start_time,
                total_events=state.total_events_analyzed,
                iteration_count=state.iteration_count,
                min_confidence=self.config.min_confidence_score
            )
            print(f"  📄 HTML report initialized: {report_path}")
            print()

        # Reset cancellation for continuous analysis
        self.reset_cancellation()

        try:
            while True:
                # Check for cancellation at the start of each iteration
                self._check_cancelled()

                state.iteration_count += 1
                findings, state = self._analyze_incremental(
                    file_path=file_path,
                    filter_event_ids=filter_event_ids,
                    state=state,
                    batch_size=batch_size,
                    max_events=max_events_per_iteration,
                    learnings=learnings,
                    correlation_rules=correlation_rules,
                    on_finding=on_finding,
                    report_path=report_path
                )

                # Wait for next iteration with cancellation check
                for _ in range(interval):
                    self._check_cancelled()
                    time.sleep(1)

        except (KeyboardInterrupt, CancelledException):
            # Print summary on exit
            runtime = (datetime.now() - state.start_time).total_seconds()
            print()
            print(f"  ┌────────────────────────────────────────────────────────────────")
            print(f"  │ ⏹️  CONTINUOUS ANALYSIS STOPPED")
            print(f"  ├────────────────────────────────────────────────────────────────")
            print(f"  │ ⏱️  Runtime: {runtime:.1f}s")
            print(f"  │ 📊 Events analyzed: {state.total_events_analyzed}")
            print(f"  │ 🚨 Findings detected: {state.total_findings}")
            print(f"  │ 🔄 Iterations: {state.iteration_count}")
            print(f"  └────────────────────────────────────────────────────────────────")
            print()

    def _analyze_incremental(
        self,
        file_path: str,
        filter_event_ids: set[int],
        state: ContinuousState,
        batch_size: int,
        max_events: int,
        learnings: list[Learning],
        correlation_rules: list[CorrelationRule],
        on_finding: Optional[Callable[[Finding], None]] = None,
        report_path: Optional[str] = None
    ) -> tuple[list[Finding], ContinuousState]:
        """
        Single iteration of continuous analysis.

        Args:
            file_path: Path to the EVTX file
            filter_event_ids: Event IDs to include
            state: Current continuous state
            batch_size: Events per batch for Claude
            max_events: Max events to process this iteration
            learnings: Pre-loaded learnings
            correlation_rules: Pre-loaded correlation rules
            on_finding: Callback for streaming findings

        Returns:
            Tuple of (findings list, updated state)
        """
        # Parse only new events matching our filter
        new_events, last_ts = parse_evtx_incremental(
            file_path=file_path,
            event_ids=filter_event_ids,
            since_timestamp=state.last_timestamp,
            max_events=max_events
        )

        if not new_events:
            print(f"  [{datetime.now().strftime('%H:%M:%S')}] ⏳ No new events, waiting...")
            return [], state

        print(f"  [{datetime.now().strftime('%H:%M:%S')}] 🔄 Analyzing {len(new_events)} new events...")

        # Update state
        state.last_timestamp = last_ts
        state.total_events_analyzed += len(new_events)

        all_findings = []

        # Process in batches
        for i in range(0, len(new_events), batch_size):
            # Check for cancellation at start of each batch
            self._check_cancelled()

            batch = new_events[i:i + batch_size]

            # Adaptive rate limiting based on batch size with cancellation check
            if i > 0:
                if len(batch) < 10:
                    pass  # No delay for tiny batches
                elif len(batch) < 25:
                    for _ in range(2):
                        self._check_cancelled()
                        time.sleep(1)
                else:
                    for _ in range(4):
                        self._check_cancelled()
                        time.sleep(1)

            # Retry loop for connection errors - keep trying until success
            retry_delay = 10  # Start with 10 seconds
            max_retry_delay = 120  # Cap at 2 minutes between retries

            while True:
                try:
                    # Analyze the batch (returns tuple of findings and summary)
                    findings, _ = self._analyze_events(
                        events=batch,
                        learnings=learnings,
                        correlation_rules=correlation_rules
                    )

                    # Process findings
                    filtered_count = 0
                    new_findings_count = 0
                    for finding in findings:
                        # Apply confidence filter
                        if finding.confidence < self.config.min_confidence_score:
                            filtered_count += 1
                            continue

                        all_findings.append(finding)
                        state.all_findings.append(finding)  # Track for report
                        state.total_findings += 1
                        new_findings_count += 1

                        if on_finding:
                            on_finding(finding)

                    # Update HTML report if we have new findings
                    if report_path and new_findings_count > 0:
                        from .cli import generate_continuous_html_report
                        generate_continuous_html_report(
                            findings=state.all_findings,
                            filename=report_path,
                            file_path=file_path,
                            start_time=state.start_time,
                            total_events=state.total_events_analyzed,
                            iteration_count=state.iteration_count,
                            min_confidence=self.config.min_confidence_score
                        )
                        # Brief console output for new findings
                        severity_icons = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}
                        for f in all_findings[-new_findings_count:]:
                            icon = severity_icons.get(f.severity.value, "⚪")
                            print(f"  [{datetime.now().strftime('%H:%M:%S')}] {icon} {f.severity.value.upper()}: {f.title} ({f.confidence:.0%})")
                        print(f"           📄 Report updated ({len(state.all_findings)} total findings)")

                    # Success - break out of retry loop
                    break

                except anthropic.APIConnectionError as e:
                    print(f"           ⚠️  Connection error: {e}")
                    print(f"           ⏳ Waiting {retry_delay}s for connection to restore...")
                    # Wait with cancellation checks
                    for _ in range(retry_delay):
                        self._check_cancelled()
                        time.sleep(1)
                    # Exponential backoff, capped at max_retry_delay
                    retry_delay = min(retry_delay * 2, max_retry_delay)
                    continue  # Retry the same batch

                except anthropic.RateLimitError as e:
                    print(f"           ⚠️  Rate limited: {e}")
                    print(f"           ⏳ Waiting 60s...")
                    for _ in range(60):
                        self._check_cancelled()
                        time.sleep(1)
                    continue  # Retry the same batch

                except Exception as e:
                    # For other errors, log and continue to next batch
                    # (these are likely parsing/response errors, not transient)
                    print(f"           Warning: Batch analysis failed: {e}")
                    break

        if not all_findings:
            print(f"  [{datetime.now().strftime('%H:%M:%S')}] ✅ No findings above threshold")
            # Still update report periodically to keep stats current
            if report_path:
                from .cli import generate_continuous_html_report
                generate_continuous_html_report(
                    findings=state.all_findings,
                    filename=report_path,
                    file_path=file_path,
                    start_time=state.start_time,
                    total_events=state.total_events_analyzed,
                    iteration_count=state.iteration_count,
                    min_confidence=self.config.min_confidence_score
                )

        return all_findings, state

    def _print_finding(self, finding: Finding, learnings: list[Learning] = None, correlation_rules: list[CorrelationRule] = None) -> None:
        """Print a finding in continuous mode format with rich detail."""
        severity_badges = {
            Severity.CRITICAL: "🔴 CRITICAL",
            Severity.HIGH: "🟠 HIGH",
            Severity.MEDIUM: "🟡 MEDIUM",
            Severity.LOW: "🔵 LOW",
            Severity.INFO: "⚪ INFO"
        }
        severity_str = severity_badges.get(finding.severity, "UNKNOWN")
        confidence_pct = int(finding.confidence * 100)
        timestamp = finding.timestamp.strftime("%Y-%m-%d %H:%M:%S")

        # Header with timestamp, severity, title
        print()
        print(f"  ╔══════════════════════════════════════════════════════════════════")
        print(f"  ║ {severity_str} | {timestamp}")
        print(f"  ║ {finding.title}")
        print(f"  ╟──────────────────────────────────────────────────────────────────")

        # MITRE ATT&CK mapping
        if finding.technique or finding.tactic:
            mitre = []
            if finding.technique:
                mitre.append(f"Technique: {finding.technique}")
            if finding.tactic:
                mitre.append(f"Tactic: {finding.tactic}")
            print(f"  ║ 🎯 MITRE: {' | '.join(mitre)}")

        # Confidence
        print(f"  ║ 📊 Confidence: {confidence_pct}%")

        # Description
        if finding.description:
            # Wrap description to fit
            desc = finding.description[:200] + "..." if len(finding.description) > 200 else finding.description
            print(f"  ║ 📝 {desc}")

        # Security Context - Artifacts
        if finding.security_context:
            ctx = finding.security_context
            print(f"  ╟──────────────────────────────────────────────────────────────────")
            print(f"  ║ 🔍 ARTIFACTS & CONTEXT:")

            # Process info
            if ctx.process_name or ctx.process_id:
                proc_info = []
                if ctx.process_name:
                    proc_info.append(ctx.process_name)
                if ctx.process_id:
                    proc_info.append(f"PID: {ctx.process_id}")
                print(f"  ║    Process: {' | '.join(proc_info)}")

            if ctx.process_command_line:
                cmd = ctx.process_command_line[:100] + "..." if len(ctx.process_command_line) > 100 else ctx.process_command_line
                print(f"  ║    Command: {cmd}")

            if ctx.parent_process_name or ctx.parent_process_id:
                parent_info = []
                if ctx.parent_process_name:
                    parent_info.append(ctx.parent_process_name)
                if ctx.parent_process_id:
                    parent_info.append(f"PID: {ctx.parent_process_id}")
                print(f"  ║    Parent:  {' | '.join(parent_info)}")

            # User info
            if ctx.user_name:
                user_str = f"{ctx.user_domain}\\{ctx.user_name}" if ctx.user_domain else ctx.user_name
                if ctx.logon_type:
                    logon_types = {3: "Network", 2: "Interactive", 10: "RemoteInteractive", 4: "Batch", 5: "Service"}
                    logon_desc = logon_types.get(ctx.logon_type, str(ctx.logon_type))
                    user_str += f" (Logon Type: {logon_desc})"
                print(f"  ║    User:    {user_str}")

            # Network info
            if ctx.source_ip or ctx.destination_ip:
                net_parts = []
                if ctx.source_ip:
                    src = ctx.source_ip
                    if ctx.source_port:
                        src += f":{ctx.source_port}"
                    if ctx.source_hostname:
                        src += f" ({ctx.source_hostname})"
                    net_parts.append(f"Src: {src}")
                if ctx.destination_ip:
                    dst = ctx.destination_ip
                    if ctx.destination_port:
                        dst += f":{ctx.destination_port}"
                    net_parts.append(f"Dst: {dst}")
                print(f"  ║    Network: {' → '.join(net_parts)}")

            # File artifacts
            if ctx.target_filename:
                print(f"  ║    File:    {ctx.target_filename}")

            # Registry artifacts
            if ctx.registry_key:
                print(f"  ║    Registry: {ctx.registry_key}")
                if ctx.registry_value:
                    print(f"  ║              Value: {ctx.registry_value}")

            # .NET/Assembly
            if ctx.assembly_name:
                print(f"  ║    Assembly: {ctx.assembly_name}")
                if ctx.clr_version:
                    print(f"  ║              CLR: {ctx.clr_version}")

            # Service/Task
            if ctx.service_name:
                print(f"  ║    Service: {ctx.service_name}")
            if ctx.task_name:
                print(f"  ║    Task:    {ctx.task_name}")

            # Target user (for lateral movement, etc.)
            if ctx.target_user_name:
                target_user = f"{ctx.target_user_domain}\\{ctx.target_user_name}" if ctx.target_user_domain else ctx.target_user_name
                print(f"  ║    Target User: {target_user}")

        # Related Events
        if finding.related_events:
            print(f"  ╟──────────────────────────────────────────────────────────────────")
            event_ids = set(e.get('event_id') for e in finding.related_events if e.get('event_id'))
            print(f"  ║ 📋 RELATED EVENTS: {len(finding.related_events)} events | Event IDs: {', '.join(map(str, sorted(event_ids)))}")

        # Matched Correlation Rules
        if finding.matched_correlations:
            print(f"  ╟──────────────────────────────────────────────────────────────────")
            print(f"  ║ 🔗 MATCHED CORRELATIONS:")
            for mc in finding.matched_correlations:
                print(f"  ║    • {mc.rule_name}")
                print(f"  ║      Event {mc.source_event_id} → Event {mc.target_event_id} via {mc.source_field}")
                if mc.matched_value:
                    print(f"  ║      Matched: {mc.matched_value}")

        # Learnings that were applied (if passed)
        if learnings:
            # Find learnings relevant to this finding's event IDs
            finding_event_ids = set(e.get('event_id') for e in finding.related_events if e.get('event_id'))
            relevant_learnings = [l for l in learnings if set(l.event_ids) & finding_event_ids]
            if relevant_learnings:
                print(f"  ╟──────────────────────────────────────────────────────────────────")
                print(f"  ║ 🧠 LEARNINGS APPLIED: {len(relevant_learnings)}")
                for l in relevant_learnings[:3]:  # Show max 3
                    insight_short = l.insight[:80] + "..." if len(l.insight) > 80 else l.insight
                    print(f"  ║    • [{l.type.value}] {insight_short}")

        # Recommendation
        if finding.recommendation:
            print(f"  ╟──────────────────────────────────────────────────────────────────")
            rec = finding.recommendation[:150] + "..." if len(finding.recommendation) > 150 else finding.recommendation
            print(f"  ║ 💡 RECOMMENDATION: {rec}")

        print(f"  ╚══════════════════════════════════════════════════════════════════")
        print()

    def close(self):
        """Clean up resources."""
        self.learnings_store.close()
        self.events_store.close()
