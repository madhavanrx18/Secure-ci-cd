from dataclasses import dataclass
from enum import Enum
from typing import List, Optional


class RiskLevel(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class Action(Enum):
    BLOCK = "BLOCK"           # Block deployment
    WARN = "WARN"             # Allow but warn
    IGNORE = "IGNORE"         # Ignore finding
    MONITOR = "MONITOR"       # Continue monitoring


@dataclass
class CVEInfo:
    cve_id: str
    cvss_score: float
    cvss_vector: str
    severity: str
    description: str
    published_date: str
    last_modified: str
    references: List[str]
    exploitability_score: float = 0.0
    impact_score: float = 0.0


@dataclass
class VulnerabilityFinding:
    tool: str
    vulnerability_id: str
    package_name: str
    current_version: str
    fixed_version: Optional[str]
    cve_info: Optional[CVEInfo]
    risk_level: RiskLevel
    action: Action
    reasoning: str
    file_path: Optional[str] = None
    line_number: Optional[int] = None
