# Implementation Plan: Track 4 - Sandbox Runner

## Milestone 4: Behavioral Evaluation

### Step 1: Docker Path Translation (`sandbox_runner.py`)
Implement a robust function to translate Windows absolute paths to Docker-compatible paths (e.g., `C:\path` to `/c/path`).
- Use `os.path.abspath()` and simple string replacement or `pathlib`.

### Step 2: Container Command Construction
- Build the `docker run` command string using `subprocess.list2cmdline` or passing a list to `subprocess.run`.
- Include safety flags: `--network none`, `--read-only`, `--tmpfs /tmp`, `--user 1000:1000`.
- Mount the quarantine directory as a read-only volume.

### Step 3: Execution and Telemetry Capture
- Use `subprocess.run` with `capture_output=True` and `timeout`.
- Capture `stdout`, `stderr`, and `exit_code`.
- Handle `TimeoutExpired` exception to flag long-running or hanging processes.

### Step 4: Anomaly Detection Logic
- Analyze the output and telemetry for anomalies:
    - Non-zero exit codes.
    - Suspicious output patterns.
    - Timeout as a "denial of service" or "evasion" indicator.

### Step 5: Unit and Integration Tests (`tests/test_sandbox.py`)
- Test with a benign Python script.
- Test with a script that attempts to write to a read-only area.
- Test with a long-running script (timeout).
- Test with a network-attempt script (if detectable via logs/exit code).

### Step 6: Orchestration
- Create `run_sandbox_scan(quarantine_path)` as the main entry point.
