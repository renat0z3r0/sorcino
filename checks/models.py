from dataclasses import dataclass
from enum import Enum
from typing import Optional


class Severity(Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


SEVERITY_ORDER = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


@dataclass(frozen=True)
class VulnFinding:
    check_name: str
    severity: Severity
    title: str
    description: str
    evidence: str
    remediation: str
    cvss_estimate: Optional[float] = None
