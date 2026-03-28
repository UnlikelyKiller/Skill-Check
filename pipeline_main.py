import os
import uuid
import json
from datetime import datetime, timezone
from typing import Optional, Dict, Any
from config import config
from models import ForensicReport, PhaseResult, AcquisitionResult, ApprovalManifest
from acquisition import acquire_artifact
from scanner_algorithmic import run_algorithmic_scan
from scanner_semantic import run_semantic_scan
from sandbox_runner import run_sandbox_scan
from deploy import stage_artifact, deploy_artifact, cleanup_quarantine
from logging_utils import logger
from errors import CircuitBreakerError

def run_pipeline(source_path: str, source_metadata: Optional[Dict[str, Any]] = None) -> ForensicReport:
    run_id = str(uuid.uuid4())
    logger.info(f"Starting pipeline run: {run_id} for source: {source_path}")
    
    phase_results = []
    final_decision = "REJECTED"
    deployment_path = None
    rejection_reason = None
    artifact_sha256 = "unknown"
    acq_result = None

    for d in [config.quarantine_dir, config.forensic_dir, config.approved_dir, config.staged_dir]:
        os.makedirs(d, exist_ok=True)

    try:
        # 1. Acquisition
        acq_result = acquire_artifact(source_path, run_id=run_id)
        phase_results.append(acq_result)
        artifact_sha256 = acq_result.artifact_sha256
        if acq_result.status == "FAIL":
            rejection_reason = f"Acquisition failed: {acq_result.findings[0].threat_type if acq_result.findings else 'Unknown'}"
            raise CircuitBreakerError("Acquisition")

        # 2. Algorithmic Scan
        alg_result = run_algorithmic_scan(acq_result.quarantine_path)
        phase_results.append(alg_result)
        if alg_result.status == "FAIL":
            rejection_reason = "Algorithmic scan detected threats or failed policy."
            raise CircuitBreakerError("Algorithmic")

        # 3. Semantic Scan
        sem_result = run_semantic_scan(acq_result.quarantine_path)
        phase_results.append(sem_result)
        if sem_result.status == "FAIL":
            rejection_reason = "Semantic scan detected threats."
            raise CircuitBreakerError("Semantic")

        # 4. Sandbox Scan
        sandbox_result = run_sandbox_scan(acq_result.quarantine_path)
        phase_results.append(sandbox_result)
        if sandbox_result.status == "FAIL":
            rejection_reason = "Sandbox scan detected anomalies."
            raise CircuitBreakerError("Sandbox")

        # 5. Deployment
        final_decision = "APPROVED"
        staged_path = stage_artifact(acq_result.quarantine_path, run_id, artifact_sha256)
        deployment_path = deploy_artifact(staged_path, artifact_sha256)
        
        # Create Approval Manifest
        manifest = ApprovalManifest(
            artifact_hash=artifact_sha256,
            run_id=run_id,
            forensic_report_path=os.path.join(config.forensic_dir, f"report_{run_id}.json")
        )
        with open(os.path.join(deployment_path, "manifest.json"), "w") as f:
            f.write(manifest.model_dump_json(indent=2))

    except Exception as e:
        logger.error(f"Pipeline error: {str(e)}")
        if not rejection_reason: rejection_reason = str(e)

    # 6. Forensic Report
    report = ForensicReport(
        run_id=run_id,
        timestamp=datetime.now(timezone.utc),
        source_metadata=source_metadata or {},
        artifact_sha256=artifact_sha256,
        phase_results=phase_results,
        final_decision=final_decision,
        deployment_path=deployment_path,
        rejection_reason=rejection_reason
    )
    
    report_path = os.path.join(config.forensic_dir, f"report_{run_id}.json")
    with open(report_path, "w") as f:
        f.write(report.model_dump_json(indent=2))
    
    if acq_result and acq_result.quarantine_path and os.path.exists(acq_result.quarantine_path):
        cleanup_quarantine(acq_result.quarantine_path)
        
    logger.info(f"Pipeline finished: {final_decision}")
    return report

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python pipeline_main.py <artifact_path>")
        sys.exit(1)
    report = run_pipeline(sys.argv[1])
    print(report.model_dump_json(indent=2))
