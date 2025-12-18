"""Data models for the EVTX Security Agent."""

from datetime import datetime
from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field


class Severity(str, Enum):
    """Severity levels for findings."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @classmethod
    def get_order(cls) -> dict["Severity", int]:
        """Return severity ordering (lower number = higher severity)."""
        return {
            cls.CRITICAL: 0,
            cls.HIGH: 1,
            cls.MEDIUM: 2,
            cls.LOW: 3,
            cls.INFO: 4,
        }

    def __ge__(self, other: "Severity") -> bool:
        """Check if this severity is >= other (i.e., at least as severe)."""
        order = self.get_order()
        return order[self] <= order[other]

    def __gt__(self, other: "Severity") -> bool:
        """Check if this severity is > other (i.e., more severe)."""
        order = self.get_order()
        return order[self] < order[other]

    def __le__(self, other: "Severity") -> bool:
        """Check if this severity is <= other (i.e., at most as severe)."""
        order = self.get_order()
        return order[self] >= order[other]

    def __lt__(self, other: "Severity") -> bool:
        """Check if this severity is < other (i.e., less severe)."""
        order = self.get_order()
        return order[self] > order[other]


class Verdict(str, Enum):
    """Analyst verdict types for feedback."""
    FALSE_POSITIVE = "false_positive"
    TRUE_POSITIVE = "true_positive"
    MISSED_DETECTION = "missed_detection"
    NEEDS_CONTEXT = "needs_context"
    BENIGN = "benign"


class WindowsEvent(BaseModel):
    """Represents a parsed Windows Event Log entry."""
    timestamp: datetime
    event_id: int
    channel: str = ""
    computer: str = ""
    provider: str = ""
    level: int = 0
    task: int = 0
    opcode: int = 0
    keywords: str = ""
    user_sid: Optional[str] = None
    process_id: Optional[int] = None
    thread_id: Optional[int] = None
    event_data: dict = Field(default_factory=dict)
    raw_xml: Optional[str] = None
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }


class SecurityContext(BaseModel):
    """Security-relevant context extracted from events."""
    # Process information
    process_name: Optional[str] = None
    process_id: Optional[int] = None
    process_command_line: Optional[str] = None
    parent_process_name: Optional[str] = None
    parent_process_id: Optional[int] = None

    # User information
    user_name: Optional[str] = None
    user_domain: Optional[str] = None
    user_sid: Optional[str] = None
    logon_id: Optional[str] = None
    logon_type: Optional[int] = None

    # Network information
    source_ip: Optional[str] = None
    source_port: Optional[int] = None
    destination_ip: Optional[str] = None
    destination_port: Optional[int] = None
    source_hostname: Optional[str] = None

    # File/Registry information
    target_filename: Optional[str] = None
    registry_key: Optional[str] = None
    registry_value: Optional[str] = None

    # .NET/Assembly information
    assembly_name: Optional[str] = None
    clr_version: Optional[str] = None

    # Additional context
    target_user_name: Optional[str] = None
    target_user_domain: Optional[str] = None
    target_logon_id: Optional[str] = None
    service_name: Optional[str] = None
    task_name: Optional[str] = None

    # Raw key fields that don't fit above
    additional_fields: dict = Field(default_factory=dict)


class MatchedCorrelation(BaseModel):
    """Tracks which correlation rule contributed to a finding."""
    rule_id: str
    rule_name: str
    source_event_id: int
    target_event_id: int
    source_field: str
    target_field: str
    matched_value: Optional[str] = None  # The actual value that linked the events


class FindingInstance(BaseModel):
    """Represents a single occurrence of a finding pattern."""
    timestamp: datetime
    security_context: Optional["SecurityContext"] = None
    related_events: list[dict] = Field(default_factory=list)
    matched_correlations: list["MatchedCorrelation"] = Field(default_factory=list)
    # Brief description of what makes this instance unique
    instance_detail: str = ""


class Finding(BaseModel):
    """Represents a suspicious finding from analysis."""
    id: str
    timestamp: datetime = Field(default_factory=datetime.now)
    severity: Severity
    title: str
    description: str
    technique: Optional[str] = None  # MITRE ATT&CK technique
    tactic: Optional[str] = None     # MITRE ATT&CK tactic
    confidence: float = 0.0          # 0.0 to 1.0
    related_events: list[dict] = Field(default_factory=list)
    recommendation: str = ""

    # Security context extracted from events
    security_context: Optional[SecurityContext] = None

    # Correlation rules that contributed to this finding
    matched_correlations: list[MatchedCorrelation] = Field(default_factory=list)

    # Multiple instances of the same finding pattern (for merged findings)
    instances: list[FindingInstance] = Field(default_factory=list)

    # For tracking feedback
    feedback_received: bool = False
    analyst_verdict: Optional[Verdict] = None

    @property
    def instance_count(self) -> int:
        """Return total number of instances (1 if no merging, or len(instances) if merged)."""
        return len(self.instances) if self.instances else 1


class Learning(BaseModel):
    """Represents a learned insight from analyst feedback."""
    id: str
    created_at: datetime = Field(default_factory=datetime.now)
    type: Verdict

    # Original context
    original_finding_id: Optional[str] = None
    original_finding_summary: str = ""

    # Feedback
    analyst_explanation: str

    # Extracted insight (the key learning)
    insight: str

    # For retrieval
    keywords: list[str] = Field(default_factory=list)
    event_ids: list[int] = Field(default_factory=list)  # Event IDs this learning applies to

    # Usage tracking
    times_applied: int = 0
    last_applied: Optional[datetime] = None


class AnalysisResult(BaseModel):
    """Complete analysis result for an EVTX file."""
    id: str
    file_path: str
    analyzed_at: datetime = Field(default_factory=datetime.now)
    total_events: int
    events_analyzed: int
    findings: list[Finding] = Field(default_factory=list)
    learnings_applied: list[str] = Field(default_factory=list)  # Learning IDs
    summary: str = ""
    
    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)
    
    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.HIGH)
    
    @property
    def medium_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.MEDIUM)
    
    @property
    def low_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.LOW)

    @property
    def info_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.INFO)


class ConditionOperator(str, Enum):
    """Operators for condition matching."""
    EQUALS = "equals"
    CONTAINS = "contains"
    STARTS_WITH = "starts_with"
    ENDS_WITH = "ends_with"
    NOT_EQUALS = "not_equals"
    NOT_CONTAINS = "not_contains"


class CorrelationRule(BaseModel):
    """
    Represents a correlation rule between event types.

    Allows analysts to define relationships between events that should be
    analyzed together for security significance.

    Conditions format:
        {"field_name": {"op": "contains", "value": "Rubeus"}}
        {"field_name": {"op": "equals", "value": "3"}}
        {"field_name": "3"}  # shorthand for equals

    Field correlation:
        source_field and target_field allow joining on different field names:
        - Event 4624 TargetLogonId -> Event 4688 SubjectLogonId
        - Event 4688 NewProcessId -> Event 4688 ProcessId (parent-child)
    """
    id: str
    created_at: datetime = Field(default_factory=datetime.now)

    # Source event criteria
    source_event_id: int  # e.g., 4624 (logon)
    source_conditions: dict = Field(default_factory=dict)  # e.g., {"LogonType": "3"}

    # Target event criteria
    target_event_id: int  # e.g., 4688 (process creation)
    target_conditions: dict = Field(default_factory=dict)  # e.g., {}

    # Correlation fields - the fields that link events together
    # Supports different field names in source and target events
    source_field: str  # e.g., "TargetLogonId" (field in source event)
    target_field: str  # e.g., "SubjectLogonId" (field in target event)

    # Analysis context
    name: str  # Human-readable name, e.g., "Network Logon to Process Execution"
    description: str  # What this correlation indicates
    security_context: str  # Why this is security-relevant
    severity_hint: Severity = Severity.MEDIUM  # Suggested severity when matched
    technique: Optional[str] = None  # MITRE ATT&CK technique
    tactic: Optional[str] = None  # MITRE ATT&CK tactic

    # For retrieval/search
    keywords: list[str] = Field(default_factory=list)

    # Usage tracking
    times_applied: int = 0
    last_applied: Optional[datetime] = None

    @staticmethod
    def _format_condition(field: str, condition) -> str:
        """Format a single condition for display."""
        if isinstance(condition, dict):
            op = condition.get("op", "equals")
            value = condition.get("value", "")
            if op == "contains":
                return f"{field} contains '{value}'"
            elif op == "starts_with":
                return f"{field} starts with '{value}'"
            elif op == "ends_with":
                return f"{field} ends with '{value}'"
            elif op == "not_equals":
                return f"{field} != '{value}'"
            elif op == "not_contains":
                return f"{field} does not contain '{value}'"
            else:
                return f"{field}={value}"
        else:
            # Simple string value = equals
            return f"{field}={condition}"

    def to_prompt_context(self) -> str:
        """Convert to a context string for inclusion in analysis prompts."""
        conditions_str = ""
        if self.source_conditions:
            conds = ", ".join(
                self._format_condition(k, v)
                for k, v in self.source_conditions.items()
            )
            conditions_str = f" (when {conds})"

        target_conditions_str = ""
        if self.target_conditions:
            conds = ", ".join(
                self._format_condition(k, v)
                for k, v in self.target_conditions.items()
            )
            target_conditions_str = f" (when {conds})"

        # Format field correlation
        if self.source_field == self.target_field:
            field_str = f"via {self.source_field} field"
        else:
            field_str = f"via {self.source_field} -> {self.target_field}"

        return (
            f"- **{self.name}**: Event {self.source_event_id}{conditions_str} correlating to "
            f"Event {self.target_event_id}{target_conditions_str} {field_str}. "
            f"{self.security_context}"
        )


class AgentConfig(BaseModel):
    """Configuration for the security agent."""
    model: str = "claude-sonnet-4-20250514"
    max_events_per_batch: int = 50
    batch_size: int = 50  # Events per batch for one-shot analysis
    continuous_batch_size: int = 65  # Events per batch for continuous mode
    confidence_threshold: Severity = Severity.MEDIUM
    min_confidence_score: float = 0.65  # Filter out findings below this confidence (0.0-1.0)
    database_path: str = "./data/learnings/learnings.db"
    vector_db_path: str = "./data/learnings/vectors"
    include_raw_events: bool = False
    verbose: bool = False
