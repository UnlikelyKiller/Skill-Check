import os
import zipfile
import shutil
import pytest
from acquisition import acquire_artifact, safe_extract_zip
from config import config

@pytest.fixture
def temp_dirs():
    """Sets up temporary test directories."""
    test_data_dir = "test_data"
    test_quarantine = "test_quarantine"
    os.makedirs(test_data_dir, exist_ok=True)
    os.makedirs(test_quarantine, exist_ok=True)
    
    # Override config for testing
    config.quarantine_dir = test_quarantine
    
    yield test_data_dir, test_quarantine
    
    # Cleanup
    shutil.rmtree(test_data_dir)
    shutil.rmtree(test_quarantine)

def create_zip(path, files):
    """Creates a zip file for testing."""
    with zipfile.ZipFile(path, 'w') as zf:
        for filename, content in files.items():
            zf.writestr(filename, content)

def test_acquire_benign_zip(temp_dirs):
    test_data_dir, _ = temp_dirs
    zip_path = os.path.join(test_data_dir, "benign.zip")
    files = {"test.txt": "hello world", "subdir/file.py": "print('ok')"}
    create_zip(zip_path, files)
    
    result = acquire_artifact(zip_path, run_id="test_run")
    
    assert result.status == "PASS"
    assert result.archive_type == "zip"
    assert os.path.exists(os.path.join(result.quarantine_path, "test.txt"))
    assert os.path.exists(os.path.join(result.quarantine_path, "subdir", "file.py"))

def test_acquire_path_traversal(temp_dirs):
    test_data_dir, _ = temp_dirs
    zip_path = os.path.join(test_data_dir, "malicious.zip")
    
    # Manually create a zip with path traversal
    with zipfile.ZipFile(zip_path, 'w') as zf:
        zf.writestr("../traversal.txt", "evil")
    
    result = acquire_artifact(zip_path, run_id="test_malicious")
    
    assert result.status == "FAIL"
    assert any("Path traversal" in f.evidence for f in result.findings)

def test_acquire_invalid_type(temp_dirs):
    test_data_dir, _ = temp_dirs
    dummy_path = os.path.join(test_data_dir, "not_a_zip.txt")
    with open(dummy_path, "w") as f:
        f.write("I am just a text file")
    
    result = acquire_artifact(dummy_path, run_id="test_invalid")
    
    assert result.status == "FAIL"
    assert any("invalid_archive_type" in f.threat_type for f in result.findings)
