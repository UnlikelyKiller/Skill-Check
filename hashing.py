import hashlib
import os
import puremagic
import zipfile
import tarfile
from typing import Optional, List
from pathlib import Path

def compute_sha256(file_path: str) -> str:
    """
    Computes the SHA-256 hash of a file or directory.
    If directory, hashes the sorted list of file hashes and names.
    """
    if os.path.isdir(file_path):
        hasher = hashlib.sha256()
        for root, _, files in os.walk(file_path):
            for fname in sorted(files):
                fpath = os.path.join(root, fname)
                # Hash relative path and content
                rel_path = os.path.relpath(fpath, file_path)
                hasher.update(rel_path.encode())
                hasher.update(compute_sha256(fpath).encode())
        return hasher.hexdigest()

    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def get_file_type_by_content(file_path: str) -> List[str]:
    try:
        results = puremagic.from_file(file_path)
        return [r.extension or r.name for r in results]
    except Exception:
        return []

def is_safe_archive(file_path: str) -> bool:
    if os.path.isdir(file_path):
        return True
    if zipfile.is_zipfile(file_path):
        return True
    if tarfile.is_tarfile(file_path):
        return True
    types = get_file_type_by_content(file_path)
    safe_extensions = ['.zip', '.tar.gz', '.gz', '.tar']
    return any(ext in safe_extensions for ext in types)
