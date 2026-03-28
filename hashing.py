import hashlib
import os
import puremagic
import zipfile
import tarfile
from typing import Optional, List

def compute_sha256(file_path: str) -> str:
    """Computes the SHA-256 hash of a file."""
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        # Read and update hash string value in blocks of 4K
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def get_file_type_by_content(file_path: str) -> List[str]:
    """
    Identifies file type using puremagic (content-based).
    Returns a list of possible extensions/types.
    """
    try:
        results = puremagic.from_file(file_path)
        # puremagic returns a list of results, we extract the extension or name
        return [r.extension or r.name for r in results]
    except Exception:
        return []

def is_safe_archive(file_path: str) -> bool:
    """Checks if the file is a zip or tar.gz based on content."""
    if zipfile.is_zipfile(file_path):
        return True
    
    if tarfile.is_tarfile(file_path):
        return True

    types = get_file_type_by_content(file_path)
    # DEBUG
    # print(f"File: {file_path}, Detected types: {types}")
    safe_extensions = ['.zip', '.tar.gz', '.gz']
    return any(ext in safe_extensions for ext in types)
