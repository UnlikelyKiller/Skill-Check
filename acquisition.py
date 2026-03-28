import os
import zipfile
import tarfile
import shutil
import uuid
from typing import List, Tuple, Optional
from pathlib import Path
from config import config
from hashing import compute_sha256, is_safe_archive
from models import AcquisitionResult, Finding
from errors import AcquisitionError

def check_path_safety(target_path: Path, target_base: Path, filename: str):
    """Common path traversal and depth check."""
    if not str(target_path).startswith(str(target_base)):
        raise AcquisitionError(f"Path traversal attempt: {filename}")
    
    # Depth check
    rel_depth = len(Path(filename).parts)
    if rel_depth > config.max_directory_depth:
        raise AcquisitionError(f"Exceeded max directory depth ({config.max_directory_depth}): {filename}")

def check_file_size(size: int, filename: str):
    """Checks if a file exceeds the single file size limit."""
    if size > config.max_single_file_size:
        raise AcquisitionError(f"Exceeded max single file size ({config.max_single_file_size}): {filename}")

def is_archive_filename(filename: str) -> bool:
    """Detects if a filename suggests it is an archive."""
    return filename.endswith(('.zip', '.tar', '.gz', '.tar.gz', '.tgz'))

def safe_extract_zip(zip_path: str, extract_path: str) -> List[Finding]:
    findings = []
    total_uncompressed_bytes = 0
    target_base = Path(extract_path).resolve()
    nested_archives_count = 0

    with zipfile.ZipFile(zip_path, 'r') as zf:
        if len(zf.infolist()) > config.max_file_count:
            raise AcquisitionError(f"Exceeded max file count ({config.max_file_count})")

        for member in zf.infolist():
            target_path = (target_base / member.filename).resolve()
            check_path_safety(target_path, target_base, member.filename)
            check_file_size(member.file_size, member.filename)

            # Block symlinks
            is_symlink = (member.external_attr >> 16) & 0o170000 == 0o120000
            if is_symlink:
                findings.append(Finding(file=member.filename, threat_type="symlink_detected", severity="high", evidence="Blocked symlink."))
                continue

            # Nested archive check
            if is_archive_filename(member.filename):
                nested_archives_count += 1
                if nested_archives_count > config.max_nested_archives:
                    raise AcquisitionError(f"Exceeded max nested archives ({config.max_nested_archives})")

            total_uncompressed_bytes += member.file_size
            if total_uncompressed_bytes > config.max_archive_bytes:
                raise AcquisitionError("Exceeded max archive total size.")
            
            if not member.is_dir():
                os.makedirs(target_path.parent, exist_ok=True)
                with zf.open(member) as source, open(target_path, "wb") as target:
                    shutil.copyfileobj(source, target)
            else:
                os.makedirs(target_path, exist_ok=True)
    return findings

def safe_extract_tar(tar_path: str, extract_path: str) -> List[Finding]:
    findings = []
    total_uncompressed_bytes = 0
    target_base = Path(extract_path).resolve()
    nested_archives_count = 0

    with tarfile.open(tar_path, 'r:*') as tf:
        members = tf.getmembers()
        if len(members) > config.max_file_count:
            raise AcquisitionError(f"Exceeded max file count ({config.max_file_count})")

        for member in members:
            target_path = (target_base / member.name).resolve()
            check_path_safety(target_path, target_base, member.name)
            check_file_size(member.size, member.name)

            if member.issym() or member.islnk():
                findings.append(Finding(file=member.name, threat_type="link_detected", severity="high", evidence="Blocked link."))
                continue

            if is_archive_filename(member.name):
                nested_archives_count += 1
                if nested_archives_count > config.max_nested_archives:
                    raise AcquisitionError(f"Exceeded max nested archives ({config.max_nested_archives})")

            total_uncompressed_bytes += member.size
            if total_uncompressed_bytes > config.max_archive_bytes:
                raise AcquisitionError("Exceeded max archive total size.")

            if member.isreg():
                os.makedirs(target_path.parent, exist_ok=True)
                with tf.extractfile(member) as source, open(target_path, "wb") as target:
                    shutil.copyfileobj(source, target)
            elif member.isdir():
                os.makedirs(target_path, exist_ok=True)
    return findings

def scan_local_directory_safely(source_path: str, quarantine_path: str) -> List[Finding]:
    """Recursively validates and copies a local directory with policy enforcement."""
    findings = []
    total_bytes = 0
    file_count = 0
    source_base = Path(source_path).resolve()
    
    for root, dirs, files in os.walk(source_path):
        rel_root = os.path.relpath(root, source_path)
        if rel_root != ".":
            if len(Path(rel_root).parts) > config.max_directory_depth:
                raise AcquisitionError(f"Exceeded max directory depth in local source: {rel_root}")

        for f in files:
            file_count += 1
            if file_count > config.max_file_count:
                raise AcquisitionError("Exceeded max file count in local source.")
            
            fpath = Path(root) / f
            fsize = fpath.stat().st_size
            check_file_size(fsize, str(fpath.relative_to(source_base)))
            
            total_bytes += fsize
            if total_bytes > config.max_archive_bytes:
                raise AcquisitionError("Exceeded total size limit in local source.")
            
            # Link check for local files
            if fpath.is_symlink():
                findings.append(Finding(file=str(fpath.relative_to(source_base)), threat_type="symlink_detected", severity="high", evidence="Blocked local symlink."))
                continue

            # Copy to quarantine
            target_fpath = Path(quarantine_path) / fpath.relative_to(source_base)
            os.makedirs(target_fpath.parent, exist_ok=True)
            shutil.copy2(fpath, target_fpath)
            
    return findings

def acquire_artifact(source_path: str, run_id: Optional[str] = None) -> AcquisitionResult:
    if not run_id:
        run_id = str(uuid.uuid4())

    artifact_sha256 = compute_sha256(source_path)
    quarantine_path = os.path.join(config.quarantine_dir, run_id)
    os.makedirs(quarantine_path, exist_ok=True)
    
    archive_type = "unknown"
    findings = []

    try:
        if os.path.isdir(source_path):
            archive_type = "directory"
            findings = scan_local_directory_safely(source_path, quarantine_path)
        elif zipfile.is_zipfile(source_path):
            archive_type = "zip"
            findings = safe_extract_zip(source_path, quarantine_path)
        elif tarfile.is_tarfile(source_path):
            archive_type = "tar.gz"
            findings = safe_extract_tar(source_path, quarantine_path)
        else:
            raise AcquisitionError("Unsupported or invalid artifact type.")

        status = "FAIL" if any(f.severity == "high" for f in findings) else "PASS"
        return AcquisitionResult(
            status=status, artifact_sha256=artifact_sha256,
            archive_type=archive_type, quarantine_path=quarantine_path, findings=findings
        )
    except Exception as e:
        return AcquisitionResult(
            status="FAIL", artifact_sha256=artifact_sha256, archive_type=archive_type,
            quarantine_path=quarantine_path, findings=[Finding(file=source_path, threat_type="acquisition_error", severity="high", evidence=str(e))]
        )
