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

def safe_extract_zip(zip_path: str, extract_path: str) -> List[Finding]:
    findings = []
    total_uncompressed_bytes = 0
    target_base = Path(extract_path).resolve()

    with zipfile.ZipFile(zip_path, 'r') as zf:
        if len(zf.infolist()) > config.max_file_count:
            raise AcquisitionError(f"Exceeded max file count ({config.max_file_count})")

        for member in zf.infolist():
            target_path = (target_base / member.filename).resolve()
            if not str(target_path).startswith(str(target_base)):
                raise AcquisitionError(f"Path traversal attempt: {member.filename}")

            is_symlink = (member.external_attr >> 16) & 0o170000 == 0o120000
            if is_symlink:
                findings.append(Finding(file=member.filename, threat_type="symlink_detected", severity="high", evidence="Blocked symlink."))
                continue

            total_uncompressed_bytes += member.file_size
            if total_uncompressed_bytes > config.max_archive_bytes:
                raise AcquisitionError("Exceeded max archive size.")
            
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

    with tarfile.open(tar_path, 'r:*') as tf:
        members = tf.getmembers()
        if len(members) > config.max_file_count:
            raise AcquisitionError(f"Exceeded max file count ({config.max_file_count})")

        for member in members:
            target_path = (target_base / member.name).resolve()
            if not str(target_path).startswith(str(target_base)):
                raise AcquisitionError(f"Path traversal attempt: {member.name}")

            if member.issym() or member.islnk():
                findings.append(Finding(file=member.name, threat_type="link_detected", severity="high", evidence="Blocked link."))
                continue

            total_uncompressed_bytes += member.size
            if total_uncompressed_bytes > config.max_archive_bytes:
                raise AcquisitionError("Exceeded max archive size.")

            if member.isreg():
                os.makedirs(target_path.parent, exist_ok=True)
                with tf.extractfile(member) as source, open(target_path, "wb") as target:
                    shutil.copyfileobj(source, target)
            elif member.isdir():
                os.makedirs(target_path, exist_ok=True)
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
            # Copy directory to quarantine
            shutil.copytree(source_path, quarantine_path, dirs_exist_ok=True)
        elif zipfile.is_zipfile(source_path):
            archive_type = "zip"
            findings = safe_extract_zip(source_path, quarantine_path)
        elif tarfile.is_tarfile(source_path):
            archive_type = "tar.gz"
            findings = safe_extract_tar(source_path, quarantine_path)
        else:
            raise AcquisitionError("Unsupported or invalid archive type.")

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
