# Track 4 Specification: Sandbox Runner

## Purpose
Execute a synthetic runtime routine inside an isolated Linux container to observe dangerous behavior (e.g., unauthorized file writes, network attempts).

## Container Policy
- **Image**: Minimal Linux (e.g., `python:3.13-slim`).
- **Network**: None (`--network none`).
- **Mounts**: Read-only bind mount of the skill package.
- **Resources**: Constrained CPU and memory.
- **User**: Non-root.
- **Isolation**: No host secrets or environment variables.

## Telemetry to Capture
- Exit code.
- Timeout status.
- Stdout/Stderr.
- Process spawns.
- Attempted file writes.
- Network usage detection.

## Status Logic
- `FAIL` on suspicious execution errors or timeouts.
- `FAIL` on prohibited write or network attempts.
- `FAIL-CLOSED` if Docker is unavailable in production.

## Expected Output Schema
```json
{
  "phase": "sandbox",
  "status": "PASS|FAIL",
  "exit_code": 0,
  "anomalies_detected": [
    {
      "type": "write_attempt",
      "target": "...",
      "severity": "medium"
    }
  ],
  "telemetry": {
    "timed_out": false,
    "process_spawn_count": 1,
    "network_attempt_detected": false
  }
}
```
