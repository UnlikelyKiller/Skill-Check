from typing import List, Optional, Union, Dict, Any
from pydantic import BaseModel, Field
from datetime import datetime

class Finding(BaseModel):
    file: str
    threat_type: str
    severity: str  # high, medium, low
    line_number: Optional[int] = None
    evidence: Optional[str] = None

class Anomaly(BaseModel):
    type: str
    target: Optional[str] = None
    severity: str
    description: Optional[str] = None

class PhaseResult(BaseModel):
    phase: str
    status: str  # PASS, FAIL
    findings: List[Finding] = Field(default_factory=list)
    anomalies: List[Anomaly] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)

class AcquisitionResult(PhaseResult):
    phase: str = "acquisition"
    artifact_sha256: str
    archive_type: str  # zip, tar.gz, directory
    quarantine_path: str

class ForensicReport(BaseModel):
    run_id: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    source_metadata: Dict[str, Any] = Field(default_factory=dict)
    artifact_sha256: str
    phase_results: List[PhaseResult] = Field(default_factory=list)
    final_decision: str  # APPROVED, REJECTED
    deployment_path: Optional[str] = None
    rejection_reason: Optional[str] = None

class ApprovalManifest(BaseModel):
    artifact_hash: str
    approval_timestamp: datetime = Field(default_factory=datetime.utcnow)
    forensic_report_path: str
    run_id: str
    status: str = "APPROVED"
