import os
import zipfile
import shutil
import uuid
from typing import List, Tuple, Optional
from pathlib import Path
from config import config
from hashing import compute_sha256, is_safe_archive
from models import AcquisitionResult, Finding

class AcquisitionError(Exception):
    pass

def safe_extract_zip(zip_path: str, extract_path: str) -> List[Finding]:
    """
    Safely extracts a ZIP archive with security checks.
    - Prevents zip-slip/path traversal.
    - Rejects symlinks/hardlinks.
    - Enforces extraction limits.
    """
    findings = []
    total_uncompressed_bytes = 0
    file_count = 0
    
    # Path objects for safety
    target_base = Path(extract_path).resolve()

    with zipfile.ZipFile(zip_path, 'r') as zf:
        # 1. Enforce file count limit
        if len(zf.infolist()) > config.max_file_count:
            raise AcquisitionError(f"Exceeded max file count ({config.max_file_count})")

        for member in zf.infolist():
            # 2. Path Traversal Check (Zip Slip)
            # resolve() will resolve '..' and other path components
            # We check if the final path is still within our extraction target_base
            member_path = Path(member.filename)
            target_path = (target_base / member_path).resolve()
            
            if not str(target_path).startswith(str(target_base)):
                raise AcquisitionError(f"Path traversal attempt detected: {member.filename}")

            # 3. Reject symlinks/hardlinks (if possible in ZIP)
            # ZipInfo.external_attr can indicate symlinks on Unix
            # (12th bit set in high 16 bits)
            # If (external_attr >> 16) & 0o170000 == 0o120000
            is_symlink = (member.external_attr >> 16) & 0o170000 == 0o120000
            if is_symlink:
                findings.append(Finding(
                    file=member.filename,
                    threat_type="symlink_detected",
                    severity="high",
                    evidence="Extraction blocked for symlink."
                ))
                continue

            # 4. Enforce resource limits during extraction
            total_uncompressed_bytes += member.file_size
            if total_uncompressed_bytes > config.max_archive_bytes:
                raise AcquisitionError(f"Exceeded max archive total bytes ({config.max_archive_bytes})")
            
            if member.file_size > config.max_single_file_size:
                raise AcquisitionError(f"Exceeded max single file size ({config.max_single_file_size}) in {member.filename}")

            # 5. Extraction
            if not member.is_dir():
                file_count += 1
                os.makedirs(target_path.parent, exist_ok=True)
                with zf.open(member) as source, open(target_path, "wb") as target:
                    shutil.copyfileobj(source, target)
            else:
                os.makedirs(target_path, exist_ok=True)

    return findings

def acquire_artifact(source_path: str, run_id: Optional[str] = None) -> AcquisitionResult:
    """
    Main entry point for acquisition.
    """
    if not run_id:
        run_id = str(uuid.uuid4())

    # 1. Compute Hash
    artifact_sha256 = compute_sha256(source_path)
    
    # 2. Validate content type
    if not is_safe_archive(source_path):
         return AcquisitionResult(
            phase="acquisition",
            status="FAIL",
            artifact_sha256=artifact_sha256,
            archive_type="unknown",
            quarantine_path="",
            findings=[Finding(
                file=source_path,
                threat_type="invalid_archive_type",
                severity="high",
                evidence="File content does not match allowed archive types."
            )]
        )

    # 3. Set up quarantine directory
    quarantine_path = os.path.join(config.quarantine_dir, run_id)
    os.makedirs(quarantine_path, exist_ok=True)

    try:
        findings = safe_extract_zip(source_path, quarantine_path)
        
        status = "PASS"
        # If any high severity finding was added during safe_extract
        if any(f.severity == "high" for f in findings):
            status = "FAIL"

        return AcquisitionResult(
            phase="acquisition",
            status=status,
            artifact_sha256=artifact_sha256,
            archive_type="zip",
            quarantine_path=quarantine_path,
            findings=findings
        )
    except Exception as e:
        return AcquisitionResult(
            phase="acquisition",
            status="FAIL",
            artifact_sha256=artifact_sha256,
            archive_type="zip",
            quarantine_path=quarantine_path,
            findings=[Finding(
                file=source_path,
                threat_type="extraction_error",
                severity="high",
                evidence=str(e)
            )]
        )
