# Implementation Plan: Track 5 - Orchestrator and Deployment

## Milestone 5: Pipeline Completion

### Step 1: Deployment Logic (`deploy.py`)
Implement functions for staging and deploying approved artifacts.
- Copy from quarantine to `staged/`.
- Copy from `staged/` to `approved/` or `skills/`.
- Handle artifact hash binding and record metadata.

### Step 2: Orchestration Core (`pipeline_main.py`)
- Initialize all components.
- Sequence the phases: `acquisition` -> `algorithmic` -> `semantic` -> `sandbox`.
- Enforce the "fail-closed" and "circuit breaker" logic (stop on first FAIL).
- Manage intermediate state and phase results.

### Step 3: Forensic Reporting (`pipeline_main.py`)
- Create the final `ForensicReport` using the model.
- Write the report as a JSON file to the `forensic/` directory.

### Step 4: Cleanup
- Purge quarantine directory on completion/failure (unless configured otherwise).

### Step 5: End-to-End Tests (`tests/test_pipeline.py`)
- Full pass test with a benign skill.
- Failure test with a malicious skill (at different phases).
- Tool/Environment failure test (fail-closed check).

### Step 6: Final Documentation
- Review all documents and finalize README.
