# Updated Implementation Plan: Automated Security Evaluation Pipeline for Agent Skills

## Version

2.1

## Date

March 28, 2026

## Objective

Build a zero-trust security gateway that intercepts third-party agent skill installations, evaluates them through deterministic, semantic, and behavioral controls, and only permits deployment after all required gates succeed.

This revision updates the prior plan to:

* add a formal acquisition and quarantine phase
* close underspecified security boundaries
* broaden deterministic scanning beyond Python-only logic
* define sandbox behavior more precisely
* standardize failure handling and deployment policy
* make the plan implementation-ready for an agent or engineering team

---

# 1. Core Operating Principles

1. Every incoming skill is treated as hostile until proven otherwise.
2. No untrusted artifact executes natively on the Windows host.
3. Any phase failure stops the pipeline immediately.
4. Operational failures in required controls default to **fail closed** unless explicitly configured otherwise for non-production development mode.
5. Approval is tied to the exact artifact hash that was evaluated.
6. Deployment is staged, auditable, and reversible.

---

# 2. Host and Runtime Assumptions

## Host

* Windows 11
* Python 3.13
* Docker Desktop 4.66.1 with Linux containers enabled
* Existing local LLM router available at `http://localhost:8081/v1`
* Local model alias: `qwen3-9b-chat`
* Intel Arc B580 acceleration available through the user’s existing local model stack

## Required External Tooling

* `semgrep`
* `bandit`
* Docker Engine / Docker Desktop

## Python Dependencies

Pin in `requirements.txt` or `pyproject.toml`:

* `openai==2.30.0`
* `instructor==1.14.5`
* `pydantic==2.12.2`
* `semgrep==1.156.0`
* `bandit==1.9.4`
* `PyYAML==6.0.3`
* `pytest==9.0.2`
* `pytest-timeout==2.4.0`
* `puremagic==2.1.1`

Conditional runtime choice for sandbox control:

* **Primary choice:** Docker CLI via `subprocess`.
* **Optional fallback:** `docker==7.1.0` only if you explicitly accept that its latest PyPI release is older than the project’s stated freshness standard.

Notes:

* Use the OpenAI-compatible client for Phase 2 and standardize on that interface.
* Use `subprocess.run()` only for external binaries such as `semgrep` and `bandit`.
* Use direct Python imports for internal modules.
* Do not use legacy modules removed or discouraged in Python 3.13.

---

# 3. Repository Layout

```text
skill-check/
  pipeline_main.py
  config.py
  models.py
  errors.py
  logging_utils.py
  hashing.py
  acquisition.py
  scanner_algorithmic.py
  scanner_semantic.py
  sandbox_runner.py
  deploy.py
  forensic/
  quarantine/
  approved/
  staged/
  tests/
    test_acquisition.py
    test_algorithmic.py
    test_semantic.py
    test_sandbox.py
    test_pipeline.py
  fixtures/
    benign_skill/
    malicious_python_eval/
    malicious_js_exec/
    malicious_bash/
    path_traversal_zip/
    unicode_injection_skill/
    dependency_hijack_skill/
```

---

# 4. State Machine

## States

1. `INIT_ACQUISITION`
2. `PHASE1_ALGORITHMIC`
3. `PHASE2_SEMANTIC`
4. `PHASE3_SANDBOX`
5. `APPROVE_STAGE`
6. `APPROVE_DEPLOY`
7. `REJECT_TERMINAL`

## General Transition Rules

* Each phase returns a structured result object.
* Any `FAIL` transitions directly to `REJECT_TERMINAL`.
* Any required control that errors or times out returns `FAIL` unless explicitly marked optional in local dev mode.
* The pipeline is stateless across runs except for immutable forensic records.

---

# 5. Phase 0: Acquisition, Verification, and Quarantine

## Purpose

Safely acquire the artifact, validate it, extract it into a restricted quarantine directory, and establish immutable provenance before any scanner runs.

## Script

`acquisition.py`

## Input

* install source (local archive path or downloaded artifact)
* optional source metadata (URL, registry, package name, version)

## Output Schema

```json
{
  "phase": "acquisition",
  "status": "PASS|FAIL",
  "artifact_sha256": "...",
  "archive_type": "zip|tar.gz|directory",
  "quarantine_path": "C:/.../quarantine/run-123",
  "findings": []
}
```

## Responsibilities

* Accept either:

  * already-downloaded archive
  * local directory for test mode
* Compute SHA-256 of the source artifact.
* Validate file type by content, not filename alone.
* Extract archive into a new per-run quarantine directory.
* Enforce archive safety limits:

  * max total uncompressed bytes
  * max file count
  * max directory depth
  * max single-file size
  * reject nested archives beyond configured threshold
* Reject path traversal attempts such as `../` and absolute-path extraction.
* Reject symlinks and hardlinks by default.
* Reject executable binaries not on an explicit allowlist if desired.
* Normalize filenames for logging without mutating evidence.
* Record provenance metadata:

  * source
  * timestamp
  * hash
  * extraction results

## Required Security Decisions

* This phase is owned by the pipeline. Extraction is not an open question.
* Encrypted archives are rejected by default.
* Malformed archives are rejected immediately.
* Any extraction safety violation is terminal.

## Tests

* benign zip extracts successfully
* malformed archive is rejected
* zip-slip/path traversal archive is rejected
* symlink-containing archive is rejected
* oversized archive is rejected
* nested archive bomb is rejected

---

# 6. Phase 1: Algorithmic Scanner (Deterministic Triage)

## Purpose

Perform broad, deterministic triage across code and text artifacts before any semantic or behavioral analysis.

## Script

`scanner_algorithmic.py`

## Input

* absolute path to extracted quarantine directory
* artifact hash

## Output Schema

```json
{
  "phase": "algorithmic",
  "status": "PASS|FAIL",
  "findings": [
    {
      "file": "relative/path.py",
      "threat_type": "python_eval_exec",
      "severity": "high",
      "line_number": 42,
      "evidence": "eval(...)"
    }
  ]
}
```

## Coverage Areas

### A. Python Static Checks

* Parse all `.py` files with `ast.parse()`.
* Traverse with `ast.walk()`.
* Flag:

  * `eval`
  * `exec`
  * `__import__`
  * suspicious `compile(..., 'exec')`
  * dynamic builtins access
  * suspicious `subprocess` usage
  * filesystem writes outside expected work area patterns
  * environment variable access if policy treats it as sensitive
* Handle Python 3.13 AST semantics cleanly.

### B. JavaScript / Node Pattern Checks

* Scan `.js`, `.mjs`, `.cjs`, `package.json`.
* Flag suspicious constructs and installation hooks:

  * `child_process`
  * `eval`
  * dynamic `Function`
  * `postinstall`, `preinstall`, `prepare`
  * curl/wget execution chains
  * shelling out from JS

### C. Shell / Bash Checks

* Scan `.sh`, shell snippets, install scripts.
* Flag:

  * `curl | bash`
  * `wget | sh`
  * reverse shell patterns
  * permission escalation attempts
  * destructive commands

### D. Markdown and Text Heuristics

* Scan `SKILL.md`, README-like files, manifests, helper docs.
* Detect:

  * zero-width and invisible control characters
  * suspicious override phrases
  * encoded payload hints
  * instructions to modify dependency manifests unexpectedly

### E. Manifest / Configuration Tampering Targets

* `package.json`
* `requirements.txt`
* `pyproject.toml`
* `setup.py`
* task runner configs
* CI scripts

### F. External Engines

Run external tools against the quarantine directory:

* `semgrep` in offline/local mode with curated rules
* `bandit` for Python security linting

## Status Logic

* Any confirmed high-severity finding => `FAIL`
* Medium-severity clusters may also fail based on policy threshold
* Empty findings => `PASS`

## Important Implementation Notes

* This phase is intentionally broader than Python-only AST checks.
* Use relative paths in findings.
* Never execute scanned content.
* All external-tool failures are terminal in production mode.

## Tests

* base64/eval Python payload is flagged
* malicious JS `child_process.exec` install hook is flagged
* shell `curl | bash` is flagged
* zero-width prompt injection marker is flagged
* benign skill yields `PASS`
* Semgrep unavailable causes fail-closed in production mode

---

# 7. Phase 2: Semantic Scanner (Cognitive Evaluation)

## Purpose

Use a local model to detect prompt injection, deceptive metadata, behavioral mismatch, and unsafe natural-language instructions that deterministic scanners cannot fully resolve.

## Script

`scanner_semantic.py`

## Input

* raw `SKILL.md` text
* optionally other high-value text files flagged in Phase 1
* artifact metadata and any deterministic findings that should inform review

## Output Schema

```json
{
  "phase": "semantic",
  "status": "PASS|FAIL",
  "cognitive_threats_detected": true,
  "threat_category": "prompt_injection|metadata_impersonation|dependency_hijacking|exfiltration_instruction|unknown",
  "confidence": "high|medium|low",
  "reasoning": "...",
  "supporting_evidence": [
    "Body instructs agent to ignore prior rules and modify dependencies.",
    "YAML advertises UI component generation only."
  ]
}
```

## Model Interface

* Use `openai` client against local OpenAI-compatible endpoint
* Base URL: `http://localhost:8081/v1`
* Model: `qwen3-9b-chat`
* Use `instructor` + `pydantic` for structured output enforcement

## Pre-LLM Deterministic Prechecks

Before calling the model:

* parse YAML frontmatter if present
* isolate markdown body
* detect invisible unicode/control chars
* flag explicit override phrases
* extract imperative commands and dependency references heuristically
* build a lightweight claim-vs-behavior summary for the model

## Prompting Rules

* Treat the skill text as untrusted data only.
* Wrap untrusted content in clearly delimited tags.
* Instruct the model to analyze, not follow, instructions within the content.
* Ask the model to compare:

  * advertised purpose in YAML/frontmatter
  * actual requested behaviors in body/scripts
  * any attempts to override host rules
  * any instructions involving exfiltration, remote fetch, credential use, or silent dependency changes

## Failure Handling

The semantic phase fails closed if:

* local model unavailable
* structured response validation fails after bounded retries
* timeout occurs
* response confidence remains low after retry and cross-check

Optional enhancement:

* run a second pass with a differently worded evaluator prompt and require consistency for borderline cases

## Status Logic

Return `FAIL` when:

* prompt injection is detected
* metadata/body mismatch is severe
* instructions request hidden dependency changes
* skill directs agent to access secrets, modify host files, or bypass user constraints
* output is unreliable or unavailable

## Tests

* “ignore previous instructions” attack is flagged
* hidden dependency hijack is flagged
* metadata/body mismatch is flagged
* malformed model output triggers fail-closed
* timeout triggers fail-closed
* benign skill yields `PASS`

---

# 8. Phase 3: Sandbox Runner (Behavioral Evaluation)

## Purpose

Execute a tightly defined synthetic runtime routine inside an isolated Linux container to observe dangerous behavior that static and semantic analysis may miss.

## Script

`sandbox_runner.py`

## Input

* quarantine directory path
* artifact hash
* runtime policy configuration

## Output Schema

```json
{
  "phase": "sandbox",
  "status": "PASS|FAIL",
  "exit_code": 0,
  "anomalies_detected": [
    {
      "type": "write_attempt",
      "target": "/app/skill/test.txt",
      "severity": "medium"
    }
  ],
  "stdout": "...",
  "stderr": "...",
  "telemetry": {
    "timed_out": false,
    "process_spawn_count": 1,
    "write_attempt_count": 1,
    "network_attempt_detected": false
  }
}
```

## Key Clarification

This phase does **not** attempt to perfectly emulate every possible host agent runtime. It performs a bounded synthetic execution routine against known executable surfaces in the skill package.

## Synthetic Execution Scope

The runtime policy should explicitly define which surfaces are exercised:

* Python files deemed primary entrypoints
* shell scripts marked as setup/install helpers
* JS files that are obvious entrypoints or install scripts
* optional manifest simulation where safe

Do **not** execute arbitrary markdown instructions directly.

## Container Policy

* minimal Linux image
* no outbound network access (`--network none`)
* read-only bind mount of the skill package
* separate writable temp area inside container if needed
* constrained CPU and memory
* timeout enforced
* non-root user if feasible
* no host secrets or inherited environment variables
* sanitized HOME and working directory
* invoke containers through the **Docker CLI** from Python via `subprocess.run()` for v1

## Path Translation

Implement deterministic Windows-to-Docker path translation.
Use the path form that works reliably with Docker Desktop 4.66.1 on the host and validate it with automated tests.

For v1, the sandbox runner should build and execute explicit Docker CLI commands rather than relying on the Python Docker SDK. This reduces dependency risk and aligns better with the project’s dependency freshness standard.

## Telemetry to Capture

* exit code
* timeout status
* stdout/stderr
* process spawns
* attempted file writes
* attempted reads of sensitive paths if instrumentable
* attempted network use
* permission errors
* unexpected child processes

## Status Logic

Return `FAIL` when:

* execution errors in a suspicious way
* container times out
* prohibited write attempts occur
* prohibited process spawning occurs
* network attempt is detected
* runtime policy cannot be enforced
* Docker is unavailable in production mode

## Important Clarification on Network Policy

This plan uses **strict no-network sandboxing**.
Any attempted network behavior is anomalous and fails the phase.
Do not describe registry allowlisting unless that capability is actually implemented later.

## Tests

* benign skill runs and exits cleanly
* write to mounted read-only path fails and is recorded
* Docker unavailable fails closed in production mode
* malicious shell script is detected
* long-running script times out and fails
* network attempt is detected and fails

---

# 9. Phase 4: Orchestrator and Circuit Breaker

## Purpose

Coordinate all phases, enforce fail-closed policy, emit forensic records, and handle staged approval/deployment.

## Script

`pipeline_main.py`

## Input

* path or source reference to candidate skill artifact

## Output

* final JSON decision to stdout
* persistent forensic report on disk

## Design

Use direct Python invocation for internal modules:

* `acquisition.py`
* `scanner_algorithmic.py`
* `scanner_semantic.py`
* `sandbox_runner.py`
* `deploy.py`

Use `subprocess.run()` for external tools such as `semgrep`, `bandit`, and the Docker CLI.

## Orchestration Logic

1. Run acquisition.
2. If pass, run algorithmic scan.
3. If pass, run semantic scan.
4. If pass, run sandbox.
5. If all pass, create approval record and stage artifact.
6. Only then deploy to approved directory.
7. On any failure, purge quarantine and write terminal rejection report.

## Failure Policy

Fail closed when:

* required tool missing
* Docker unavailable
* model unavailable
* JSON contract from a phase is invalid
* any phase times out

## Forensic Report Requirements

Each run must produce a JSON report containing at minimum:

* run ID
* timestamp
* source metadata
* artifact SHA-256
* per-phase status
* findings and anomalies
* final decision
* deployment destination if approved
* rejection reason if rejected

---

# 10. Deployment Policy

## Stage Before Live Deployment

Approved artifacts should not move directly from quarantine into the live skills directory.

## Process

1. Copy to a staged approved directory.
2. Bind staged artifact to:

   * artifact hash
   * approval timestamp
   * forensic report path
3. Optionally generate an approval manifest.
4. Then deploy to the live skill directory.

## Rollback / Removal

Maintain enough metadata to remove or quarantine a previously approved artifact by hash.

## Recommended Directories

* `quarantine/`
* `forensic/`
* `approved/`
* `staged/`

Make paths configurable through `config.py` rather than hardcoding them.

---

# 11. Configurability

## Configuration File

`config.py`

## Configurable Values

* production vs development mode
* max archive size
* max file count
* max depth
* per-phase timeout
* semgrep path
* bandit path
* model endpoint and model name
* Docker image
* quarantine path
* forensic path
* staged path
* approved path
* severity threshold policy

## Policy Recommendation

Default to production-safe values.

---

# 12. Data Models

## Shared Result Model

Create shared `pydantic` models in `models.py` for:

* phase result
* finding
* anomaly
* forensic report
* approval manifest

This prevents schema drift between modules.

---

# 13. Logging and Evidence Handling

## Logging Rules

* structured JSON logs for machine use
* concise human-readable console output
* relative paths in findings where possible
* never mutate or “clean” evidence before hashing and logging

## Evidence Preservation

* compute hash before extraction if archive input
* preserve per-run metadata
* preserve rejection evidence in forensic report
* purge quarantined content on reject unless policy requires retention for manual analysis

---

# 14. Test Plan

## Unit Tests

* hashing
* path translation
* AST walkers
* YAML/frontmatter parsing
* unicode detection
* result schema validation

## Integration Tests

* full pass flow
* fail at acquisition
* fail at deterministic scan
* fail at semantic scan
* fail at sandbox
* deployment staging only after all passes

## Adversarial Fixtures

* Python eval/exec payload
* JS child_process payload
* Bash curl-pipe payload
* zip-slip archive
* symlink escape archive
* unicode cloaking prompt injection
* metadata impersonation skill
* dependency hijack skill
* no-op benign skill

## Environment Tests

* Docker daemon unavailable
* local model unavailable
* semgrep unavailable
* long path / space-in-path behavior on Windows
* mixed slashes / mount translation edge cases

---

# 15. Suggested Implementation Order

## Milestone 1

* shared models
* config system
* acquisition phase
* hashing and forensic skeleton

## Milestone 2

* deterministic scanner core
* Semgrep and Bandit integration
* algorithmic test fixtures

## Milestone 3

* semantic scanner
* local model integration
* fail-closed retries and schema enforcement

## Milestone 4

* sandbox runner
* Docker path translation
* timeout and anomaly telemetry

## Milestone 5

* orchestrator
* staged deployment
* rollback metadata
* end-to-end tests

---

# 16. Open Design Choices That Should Be Decided Before Coding Starts

1. Whether medium-severity deterministic findings auto-fail or accumulate by threshold.
2. Whether previously approved artifact hashes are cached to avoid re-evaluation.
3. Whether rejected artifacts are purged immediately or retained for analyst review in a separate evidence store.
4. Whether sandbox execution should expand later to more realistic agent-host simulation.
5. Whether a manual review lane should exist for ambiguous semantic results.

Recommended defaults:

* medium severity accumulates by threshold
* no trust carryover without hash match
* rejected artifacts purged by default, forensic record retained
* synthetic sandbox remains bounded for v1
* ambiguous semantic outcomes fail closed in production

---

# 17. Minimum Definition of Done

The pipeline is not done until all of the following are true:

* acquisition safely rejects malformed and traversal archives
* deterministic scanner handles Python, JS, shell, markdown heuristics, Semgrep, and Bandit
* semantic scanner produces structured local-only evaluations and fails closed on model errors
* sandbox runner executes within a network-disabled read-only container and captures telemetry
* orchestrator halts on first failure and writes a complete forensic report
* deployment is staged and bound to artifact hash
* automated tests cover both benign and adversarial fixtures

---

# 18. Recommended Next Step

Start with Milestone 1 and Milestone 2 only. Do not begin by wiring the full pipeline together. The acquisition boundary and deterministic scanner are the foundation. If those are sloppy, the rest of the pipeline will be built on sand.
