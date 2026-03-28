# Track 5 Specification: Orchestrator and Deployment

## Purpose
Coordinate all phases, enforce fail-closed policy, emit forensic records, and handle staged approval/deployment.

## Orchestration Logic
1. Run Acquisition.
2. If PASS, run Algorithmic Scanner.
3. If PASS, run Semantic Scanner.
4. If PASS, run Sandbox Runner.
5. If ALL PASS, stage and deploy the artifact.
6. On any FAIL, stop immediately and write a terminal rejection report.

## Deployment Process
- **Stage**: Copy approved artifacts to a staged directory, bound to the artifact hash and forensic report.
- **Deploy**: Move to the live skill directory only after successful staging.
- **Forensic Records**: Persistent JSON report on disk for every run.

## Forensic Report Requirements
- Run ID, timestamp, source metadata.
- Artifact SHA-256.
- Per-phase status, findings, and anomalies.
- Final decision and deployment/rejection reason.

## Status Logic
- FAIL-CLOSED on any required tool/model/docker unavailability.
- FAIL-CLOSED on any phase timeout or invalid JSON contract.

## Expected Final Output
Structured JSON decision and a path to the persistent forensic record.
```json
{
  "run_id": "...",
  "status": "APPROVED|REJECTED",
  "hash": "...",
  "deployment_path": "...",
  "forensic_report": "..."
}
```
