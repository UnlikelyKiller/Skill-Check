# Track 1 Specification: Acquisition and Quarantine

## Purpose
Safely acquire the artifact, validate it, extract it into a restricted quarantine directory, and establish immutable provenance before any scanner runs.

## Responsibilities
- Accept local archives or directories.
- Compute SHA-256 of the source artifact.
- Validate file type by content (not just filename).
- Extract into a restricted quarantine directory.
- Enforce extraction safety limits:
    - Max uncompressed bytes
    - Max file count
    - Max directory depth
    - Max single-file size
- Reject path traversal attempts (`../`).
- Reject symlinks and hardlinks.
- Normalize filenames for logging.

## Security Decisions
- No encrypted archives allowed.
- Malformed archives must be rejected immediately.
- Extraction safety violations are terminal.

## Expected Output Schema
```json
{
  "phase": "acquisition",
  "status": "PASS|FAIL",
  "artifact_sha256": "...",
  "archive_type": "zip|tar.gz|directory",
  "quarantine_path": "...",
  "findings": []
}
```
