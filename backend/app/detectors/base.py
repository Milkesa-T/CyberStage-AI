"""
CyberSage AI — Base Detector Protocol

Defines the abstract interface and output contract for all modular threat detectors.

DESIGN RATIONALE:
- BaseDetector uses Python's ABC pattern so all detectors are guaranteed to implement
  `can_detect()` and `analyze()`. This prevents silent failures where a detector
  runs but returns nothing.
- DetectionResult is a plain dataclass (not Pydantic) for internal pipeline use,
  keeping detection logic decoupled from the external API schema.
- `confidence` (0.0 to 1.0) is a normalized score the DetectorRegistry uses to rank
  competing detector matches and select the primary threat category.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from app.schemas.incident import ExtractedIOCs, IncidentCategory, IncidentSeverity, MitreMapping


@dataclass
class DetectionResult:
    """
    Internal output of a single detector's analysis run.
    Contains all signals the TriageService needs to assemble an enriched triage response.
    """
    detected: bool = False
    category: IncidentCategory = IncidentCategory.OTHER
    severity: IncidentSeverity = IncidentSeverity.MEDIUM
    confidence: float = 0.0           # 0.0 = no match, 1.0 = perfect match
    mitre_mapping: MitreMapping = field(default_factory=MitreMapping)
    evidence: list[str] = field(default_factory=list)
    recommended_steps: list[str] = field(default_factory=list)
    summary: str = ""
    false_positive_risk: str = "MEDIUM"  # "LOW" | "MEDIUM" | "HIGH"

    def __post_init__(self):
        # Clamp confidence between 0.0 and 1.0
        self.confidence = max(0.0, min(1.0, self.confidence))


class BaseDetector(ABC):
    """
    Abstract base class for all CyberSage threat detectors.

    To add a new detector:
    1. Create a new file in `backend/app/detectors/`.
    2. Inherit from BaseDetector.
    3. Implement `can_detect()` (fast pre-check) and `analyze()` (deep analysis).
    4. Register the class in DetectorRegistry.

    No other changes to routing, triage, or prompt code are needed.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable detector name for logging and audit trails."""
        ...

    @abstractmethod
    def can_detect(self, combined_text: str) -> bool:
        """
        Fast pre-screening check — should run in O(n) string operations.
        Returns True if the detector should attempt a full analysis pass.
        The registry uses this to skip irrelevant detectors efficiently.
        """
        ...

    @abstractmethod
    def analyze(
        self,
        combined_text: str,
        iocs: ExtractedIOCs,
    ) -> DetectionResult:
        """
        Full analysis pass on combined incident text and pre-extracted IOCs.
        Returns a DetectionResult with confidence score, MITRE mapping, and evidence.
        """
        ...
