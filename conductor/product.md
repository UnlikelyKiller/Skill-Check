# Product Definition: Automated Security Evaluation Pipeline for Agent Skills

## Objective
Build a zero-trust security gateway that intercepts third-party agent skill installations, evaluates them through deterministic, semantic, and behavioral controls, and only permits deployment after all required gates succeed.

## Core Principles
1. **Hostile by Default**: Every incoming skill is treated as hostile until proven otherwise.
2. **Isolation**: No untrusted artifact executes natively on the Windows host.
3. **Fail-Fast**: Any phase failure stops the pipeline immediately.
4. **Fail-Closed**: Operational failures default to "fail closed".
5. **Hash-Bound**: Approval is tied to the exact artifact hash.
6. **Auditable**: Deployment is staged, auditable, and reversible.

## High-Level States
1. `INIT_ACQUISITION`
2. `PHASE1_ALGORITHMIC`
3. `PHASE2_SEMANTIC`
4. `PHASE3_SANDBOX`
5. `APPROVE_STAGE`
6. `APPROVE_DEPLOY`
7. `REJECT_TERMINAL`
