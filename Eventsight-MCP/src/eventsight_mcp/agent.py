"""Core security analysis agent using Claude."""

import json
import os
import re
import uuid
from datetime import datetime
from pathlib import Path
from typing import Optional

import anthropic

from .models import (
    AgentConfig, AnalysisResult, Finding, FindingInstance, Learning, Severity, Verdict, WindowsEvent,
    CorrelationRule, SecurityContext, MatchedCorrelation
)
from .parser import parse_evtx_file, events_to_summary, filter_security_relevant_events
from .learnings import LearningsStore, extract_keywords
from .events_store import EventsStore
from .prompts import (
    ANALYSIS_SYSTEM_PROMPT, LEARNING_EXTRACTION_PROMPT,
    CORRELATION_CONTEXT_HEADER
)


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
        embeddings_path = str(Path(self.config.database_path).parent / "embeddings.npy")
        self.learnings_store = LearningsStore(
            db_path=self.config.database_path,
            embeddings_path=embeddings_path,
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

        # Cancellation flag for graceful shutdown
        self._cancelled = False
    
    def evaluate_evtx(
        self,
        file_path: str | list[str],
        filter_relevant: bool = True,
        max_events: Optional[int] = None,
        parse_all: bool = False,
        batch_size: Optional[int] = None,
        smart_filter: bool = True,
        filter_event_ids: Optional[list[int]] = None,
        filter_metadata: Optional[dict] = None,
        provider_filters: Optional[list[tuple[str, int]]] = None
    ) -> AnalysisResult:
        """
        Analyze one or more EVTX files for suspicious activity.

        Args:
            file_path: Path to the EVTX file, or list of paths for multi-file analysis
            filter_relevant: If True, filter to security-relevant events first
            max_events: Maximum events to analyze (uses config default if None)
            parse_all: If True, parse the entire EVTX file (ignores max_events limit)
            batch_size: Events per batch for large files (uses config default if None)
            smart_filter: If True and parse_all, use AI to identify relevant Event IDs first
            filter_event_ids: Optional list of Event IDs to filter to (overrides smart_filter)
            filter_metadata: Optional dict mapping Event IDs to metadata (type, reason) from filter file
            provider_filters: Optional list of (provider, event_id) tuples for provider-aware filtering

        Returns:
            AnalysisResult with findings and summary
        """
        batch_size = batch_size or self.config.batch_size

        # Reset cancellation flag and token tracking for this analysis
        self._cancelled = False
        self._total_input_tokens = 0
        self._total_output_tokens = 0

        # Handle single file or multiple files
        if isinstance(file_path, str):
            file_paths = [file_path]
        else:
            file_paths = list(file_path)

        is_multi_file = len(file_paths) > 1

        # Parse EVTX file(s)
        all_events = []
        for fp in file_paths:
            print(f"Parsing {fp}...")
            if parse_all:
                file_events = parse_evtx_file(fp, max_events=None)
            else:
                max_ev = max_events or self.config.max_events_per_batch
                file_events = parse_evtx_file(fp, max_events=max_ev * 2)
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
        elif parse_all and smart_filter and len(all_events) > 100:
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
                events = all_events if parse_all else all_events[:max_events]
        else:
            events = all_events if parse_all else all_events[:max_events]

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

        print(f"Processing {len(events)} events in {total_batches} batches of {batch_size}...")

        for batch_num in range(total_batches):
            # Check for cancellation before processing each batch
            if self._cancelled:
                print(f"  Analysis cancelled after {batch_num} batches.")
                break

            start_idx = batch_num * batch_size
            end_idx = min(start_idx + batch_size, len(events))
            batch_events = events[start_idx:end_idx]

            print(f"  Batch {batch_num + 1}/{total_batches}: events {start_idx + 1}-{end_idx}...")

            # Small delay between batches (only if needed for rate limiting)
            if batch_num > 0:
                time.sleep(1)  # Minimal delay - retry logic handles rate limits

            # Analyze this batch with retry on rate limit
            max_retries = 3
            for attempt in range(max_retries):
                # Check for cancellation before each retry attempt
                if self._cancelled:
                    break

                try:
                    batch_findings, batch_summary = self._analyze_events(
                        batch_events, learnings, batch_offset=start_idx,
                        correlation_rules=correlation_rules
                    )
                    break
                except anthropic.RateLimitError as e:
                    if attempt < max_retries - 1:
                        wait_time = 60 * (attempt + 1)  # 60s, 120s, 180s
                        print(f"    Rate limited, waiting {wait_time}s before retry...")
                        # Check for cancellation during wait
                        for _ in range(wait_time):
                            if self._cancelled:
                                break
                            time.sleep(1)
                        if self._cancelled:
                            break
                    else:
                        raise

            # Skip collecting results if cancelled
            if self._cancelled:
                break

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
            for existing_sig in list(signature_to_findings.keys()):
                if self._signatures_match(signature, existing_sig):
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
            "during", "based", "using", "user", "infrastructure", "protection"
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
        ]

        for family in technique_families:
            if base1 in family and base2 in family:
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
        including CONTENT SAMPLES so Claude can identify suspicious activity
        even in unknown Event IDs.
        """
        from collections import Counter, defaultdict

        # Build a summary of what's in the file
        event_id_counts = Counter(e.event_id for e in events)
        providers = set(e.provider for e in events if e.provider)
        channels = set(e.channel for e in events if e.channel)

        # Group events by Event ID for sampling
        events_by_id = defaultdict(list)
        for e in events:
            events_by_id[e.event_id].append(e)

        # Sample actual content from each Event ID (up to 2 samples each)
        # This lets Claude see WHAT's in the events, not just the ID numbers
        content_samples = []
        security_fields = [
            'CommandLine', 'Image', 'ParentImage', 'TargetFilename',
            'TargetImage', 'SourceImage', 'User', 'TargetUserName',
            'SubjectUserName', 'IpAddress', 'DestinationIp', 'ServiceName',
            'ServiceFileName', 'TaskName', 'ObjectName', 'ProcessName',
            'Application', 'SourceAddress', 'DestinationAddress'
        ]

        for eid, eid_events in list(events_by_id.items())[:40]:  # Top 40 Event IDs
            samples_for_id = []
            for e in eid_events[:2]:  # 2 samples per Event ID
                # Extract security-relevant fields that have values
                sample_fields = {}
                for field in security_fields:
                    val = e.event_data.get(field)
                    if val and str(val).strip() and str(val) != '-':
                        # Truncate long values
                        val_str = str(val)
                        if len(val_str) > 150:
                            val_str = val_str[:150] + '...'
                        sample_fields[field] = val_str

                if sample_fields:
                    samples_for_id.append(sample_fields)

            if samples_for_id:
                content_samples.append({
                    "event_id": eid,
                    "count": len(eid_events),
                    "provider": eid_events[0].provider,
                    "samples": samples_for_id
                })

        # Format content samples for the prompt
        samples_text = ""
        for cs in content_samples[:30]:  # Limit to 30 to control token usage
            samples_text += f"\nEvent {cs['event_id']} ({cs['provider']}) - {cs['count']} occurrences:"
            for i, sample in enumerate(cs['samples'][:2]):
                sample_str = ", ".join(f"{k}={v}" for k, v in list(sample.items())[:5])
                samples_text += f"\n  Sample {i+1}: {sample_str}"

        summary = f"""Event Log Summary:
- Total events: {len(events)}
- Providers: {', '.join(sorted(providers)[:10]) or 'Unknown'}
- Channels: {', '.join(sorted(channels)[:5]) or 'Unknown'}
- Event ID distribution (ID: count):
{chr(10).join(f'  {eid}: {count}' for eid, count in event_id_counts.most_common(30))}

Content Samples (showing actual event data):
{samples_text}"""

        try:
            response = self.client.messages.create(
                model=self.config.model,
                max_tokens=500,
                system="""You are a security analyst. Given a summary of a Windows Event Log file WITH CONTENT SAMPLES,
identify which Event IDs are security-relevant and should be analyzed for threats.

IMPORTANT: Look at the ACTUAL CONTENT in the samples, not just the Event ID numbers!
- A process creation event (4688) with "powershell -enc" is very different from one with "notepad.exe"
- An unknown Event ID with suspicious content (encoded commands, unusual paths) should be included
- Don't skip Event IDs just because you don't recognize them - check the sample content

Consider:
- Events with suspicious content: encoded commands, unusual executables, sensitive file access
- Events from security-relevant providers (Security, Sysmon, PowerShell, Defender, etc.)
- Events showing: process creation, network activity, authentication, privilege changes
- Unknown Event IDs that have suspicious-looking sample content
- Low-frequency events that stand out from the baseline

Return ONLY a JSON object with a list of Event IDs to analyze:
{"event_ids": [1, 4624, 4688, ...], "reason": "brief explanation of what looks interesting"}""",
                messages=[{
                    "role": "user",
                    "content": f"Identify security-relevant Event IDs from this log. PAY ATTENTION TO THE CONTENT SAMPLES:\n\n{summary}"
                }]
            )

            # Track token usage
            self._total_input_tokens += response.usage.input_tokens
            self._total_output_tokens += response.usage.output_tokens
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

        # Prepare events for analysis (convert to JSON-serializable format)
        # Optimize payload size to avoid rate limits
        events_data = []
        for i, event in enumerate(events):
            # Trim event_data to most relevant fields and limit string lengths
            trimmed_data = {}
            for key, value in event.event_data.items():
                if value is not None and value != '':
                    # Truncate very long string values
                    if isinstance(value, str) and len(value) > 500:
                        value = value[:500] + '...'
                    trimmed_data[key] = value

            event_dict = {
                "index": batch_offset + i,
                "timestamp": event.timestamp.isoformat(),
                "event_id": event.event_id,
                "channel": event.channel,
                "provider": event.provider,
                "computer": event.computer,
                "user_sid": event.user_sid,
                "process_id": event.process_id,
                "data": trimmed_data
            }
            events_data.append(event_dict)
        
        # Call Claude
        response = self.client.messages.create(
            model=self.config.model,
            max_tokens=4096,
            # prompt construction
            system=ANALYSIS_SYSTEM_PROMPT + learnings_context + correlation_context,
            messages=[{
                "role": "user",
                "content": f"""Analyze these Windows events for suspicious activity.

Return your analysis as a JSON object with this structure:
{{
    "findings": [
        {{
            "severity": "critical|high|medium|low|info",
            "title": "Brief title",
            "description": "Detailed explanation",
            "technique": "MITRE ATT&CK ID (e.g., T1055)",
            "tactic": "MITRE ATT&CK tactic",
            "confidence": 0.0-1.0,
            "related_event_indices": [0, 5, 12],
            "recommendation": "What to investigate"
        }}
    ],
    "summary": "1-2 sentence security assessment focusing only on key threats found"
}}

Events to analyze:
{json.dumps(events_data, indent=2, default=str)}"""
            }]
        )

        # Track token usage
        input_tokens = response.usage.input_tokens
        output_tokens = response.usage.output_tokens
        self._total_input_tokens += input_tokens
        self._total_output_tokens += output_tokens
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
        """Use Claude to extract a reusable insight from feedback, with timeout and fallback."""
        try:
            # Use a timeout to prevent hanging - 30 seconds should be plenty
            response = self.client.messages.create(
                model=self.config.model,
                max_tokens=500,
                timeout=30.0,  # 30 second timeout
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
            print(f"  Learning extraction tokens: {response.usage.input_tokens:,} input, {response.usage.output_tokens:,} output")

            return response.content[0].text.strip()

        except Exception as e:
            # Fallback: generate a simple insight locally without API call
            print(f"  Warning: Could not extract insight via API ({type(e).__name__}), using local fallback")
            return self._generate_fallback_insight(finding_summary, verdict, explanation)

    def _generate_fallback_insight(self, finding_summary: str, verdict: Verdict, explanation: str) -> str:
        """Generate a simple insight locally when API call fails or times out."""
        verdict_text = {
            Verdict.FALSE_POSITIVE: "This is a false positive",
            Verdict.TRUE_POSITIVE: "This is a confirmed threat",
            Verdict.BENIGN: "This is benign activity",
            Verdict.NEEDS_CONTEXT: "This needs additional context"
        }.get(verdict, "Note")

        # Create a concise insight from the explanation
        insight = f"{verdict_text}: {explanation}"

        # Truncate if too long
        if len(insight) > 500:
            insight = insight[:497] + "..."

        return insight
    
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

    # ==================== Agentic RAG ====================

    def process_feedback(self, instruction: str) -> dict:
        """
        Process analyst feedback using Agentic RAG.

        This is the main entry point for the agentic feedback loop.
        The agent will autonomously search events, create learnings,
        and respond to the analyst's instruction.

        Args:
            instruction: Natural language instruction from the analyst
                Examples:
                - "Finding #2 is legitimate, that's CrowdStrike"
                - "You missed PsExec lateral movement, find it"
                - "Look for LSASS access and create a learning"

        Returns:
            Result dict with response, actions taken, and created learnings
        """
        from .agentic_rag import AgenticRAG

        agent = AgenticRAG(
            learnings_store=self.learnings_store,
            events_store=self.events_store,
            current_analysis=self.current_analysis,
            model=self.config.model
        )

        result = agent.process_feedback(instruction)

        print(f"  Agentic RAG: {result.get('iterations', 0)} iterations, "
              f"{result['tokens']['input']:,} input / {result['tokens']['output']:,} output tokens")

        return result

    def search_events_sql(self, event_ids: Optional[list[int]] = None,
                          field_contains: Optional[dict[str, str]] = None,
                          limit: int = 100) -> list[dict]:
        """
        Search stored events using SQL queries.

        Args:
            event_ids: Optional list of Event IDs to filter by
            field_contains: Optional dict of field -> substring to search for
                           e.g., {"CommandLine": "powershell", "Image": "lsass"}
            limit: Maximum results

        Returns:
            List of matching events
        """
        return self.events_store.search_events(
            event_ids=event_ids,
            field_contains=field_contains,
            limit=limit
        )

    def cancel(self):
        """Request cancellation of any running batch operations."""
        self._cancelled = True
        print("Cancellation requested - stopping batch processing...")

    def is_cancelled(self) -> bool:
        """Check if cancellation has been requested."""
        return self._cancelled

    def reset_cancellation(self):
        """Reset the cancellation flag for new operations."""
        self._cancelled = False

    def close(self):
        """Clean up resources."""
        self._cancelled = True
        self.learnings_store.close()
        self.events_store.close()
