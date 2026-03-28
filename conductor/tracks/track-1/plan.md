# Implementation Plan: Track 1 - Acquisition and Quarantine

## Milestone 1: Core Systems and Acquisition

### Step 1: Shared Models (`models.py`)
Create `pydantic` models for the pipeline and phase results, ensuring consistency across modules.
- `PhaseResult`
- `Finding`
- `Anomaly`
- `ForensicReport`

### Step 2: Configuration (`config.py`)
Define a centralized configuration system using `pydantic-settings` or a simple `dataclass`.
- Production vs. Development modes
- Resource limits (size, count, depth)
- Timeouts
- Directory paths (quarantine, forensic, approved, staged)

### Step 3: Hashing and File Utilities (`hashing.py`)
- SHA-256 calculation for files.
- File type validation by content (using `puremagic`).

### Step 4: Acquisition and Extraction (`acquisition.py`)
- Extraction of ZIP archives with safety checks.
- Path traversal prevention.
- Symlink rejection.
- Resource limit enforcement during extraction.

### Step 5: Unit Tests
- `test_acquisition.py`
- `test_hashing.py`

### Step 6: Integration
- Combine into a basic `acquisition` flow.
