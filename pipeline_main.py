import os
import uuid
import json
from datetime import datetime
from typing import Optional, Dict, Any
from config import config
from models import ForensicReport, PhaseResult, AcquisitionResult
from acquisition import acquire_artifact
from scanner_algorithmic import run_algorithmic_scan
from scanner_semantic import run_semantic_scan
from sandbox_runner import run_sandbox_scan
from deploy import stage_artifact, deploy_artifact, cleanup_quarantine

def run_pipeline(source_path: str, source_metadata: Optional[Dict[str, Any]] = None) -> ForensicReport:
    """
    Orchestrates the full security evaluation pipeline.
    """
    run_id = str(uuid.uuid4())
    if not source_metadata:
        source_metadata = {}
    
    # Initialize results
    phase_results = []
    final_decision = "REJECTED"
    deployment_path = None
    rejection_reason = None
    artifact_sha256 = "unknown"
    acq_result = None

    # Ensure directories exist
    for d in [config.quarantine_dir, config.forensic_dir, config.approved_dir, config.staged_dir]:
        os.makedirs(d, exist_ok=True)

    try:
        # 1. Acquisition
        acq_result = acquire_artifact(source_path, run_id=run_id)
        phase_results.append(acq_result)
        artifact_sha256 = acq_result.artifact_sha256
        
        if acq_result.status == "FAIL":
            rejection_reason = f"Acquisition phase failed: {acq_result.findings[0].evidence if acq_result.findings else 'Unknown'}"
            raise Exception("Pipeline circuit breaker: Acquisition")

        # 2. Algorithmic Scan
        alg_result = run_algorithmic_scan(acq_result.quarantine_path)
        phase_results.append(alg_result)
        if alg_result.status == "FAIL":
            rejection_reason = "Algorithmic scanner detected high-severity threats."
            raise Exception("Pipeline circuit breaker: Algorithmic")

        # 3. Semantic Scan
        sem_result = run_semantic_scan(acq_result.quarantine_path)
        phase_results.append(sem_result)
        if sem_result.status == "FAIL":
            rejection_reason = "Semantic scanner detected cognitive/behavioral threats."
            raise Exception("Pipeline circuit breaker: Semantic")

        # 4. Sandbox Scan
        sandbox_result = run_sandbox_scan(acq_result.quarantine_path)
        phase_results.append(sandbox_result)
        if sandbox_result.status == "FAIL":
            rejection_reason = "Sandbox runner detected prohibited behavioral anomalies."
            raise Exception("Pipeline circuit breaker: Sandbox")

        # 5. Deployment
        final_decision = "APPROVED"
        staged_path = stage_artifact(acq_result.quarantine_path, run_id, artifact_sha256)
        deployment_path = deploy_artifact(staged_path, artifact_sha256)

    except Exception as e:
        # If not already set by a phase
        if not rejection_reason:
            rejection_reason = str(e)

    # 6. Cleanup and Forensic Report
    report = ForensicReport(
        run_id=run_id,
        timestamp=datetime.utcnow(),
        source_metadata=source_metadata,
        artifact_sha256=artifact_sha256,
        phase_results=phase_results,
        final_decision=final_decision,
        deployment_path=deployment_path,
        rejection_reason=rejection_reason
    )
    
    # Save forensic report
    report_path = os.path.join(config.forensic_dir, f"report_{run_id}.json")
    with open(report_path, "w") as f:
        f.write(report.model_dump_json(indent=2))
    
    # Cleanup quarantine
    if acq_result and acq_result.quarantine_path and os.path.exists(acq_result.quarantine_path):
        cleanup_quarantine(acq_result.quarantine_path)
        
    return report

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python pipeline_main.py <artifact_path>")
        sys.exit(1)
    
    report = run_pipeline(sys.argv[1])
    print(report.model_dump_json(indent=2))
