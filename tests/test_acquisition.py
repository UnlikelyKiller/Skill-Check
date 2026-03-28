import os
import zipfile
import tarfile
import shutil
import pytest
from acquisition import acquire_artifact
from config import config

@pytest.fixture
def temp_dirs():
    test_data_dir = os.path.abspath("test_data")
    test_quarantine = os.path.abspath("test_quarantine")
    os.makedirs(test_data_dir, exist_ok=True)
    os.makedirs(test_quarantine, exist_ok=True)
    config.quarantine_dir = test_quarantine
    yield test_data_dir, test_quarantine
    shutil.rmtree(test_data_dir)
    shutil.rmtree(test_quarantine)

def create_zip(path, files):
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

def test_acquire_oversized_file(temp_dirs):
    test_data_dir, _ = temp_dirs
    zip_path = os.path.join(test_data_dir, "oversized.zip")
    large_content = "X" * (11 * 1024 * 1024)
    create_zip(zip_path, {"large.txt": large_content})
    result = acquire_artifact(zip_path, run_id="test_oversized")
    assert result.status == "FAIL"
    assert "Exceeded max single file size" in str(result.findings[0].evidence)

def test_acquire_nested_archives(temp_dirs):
    test_data_dir, _ = temp_dirs
    zip_path = os.path.join(test_data_dir, "nested.zip")
    create_zip(zip_path, {"inner.zip": "fake content"})
    result = acquire_artifact(zip_path, run_id="test_nested")
    assert result.status == "FAIL"
    assert "Exceeded max nested archives" in str(result.findings[0].evidence)

def test_acquire_depth_limit(temp_dirs):
    test_data_dir, _ = temp_dirs
    zip_path = os.path.join(test_data_dir, "deep.zip")
    deep_path = "a/b/c/d/e/f/g/h/i/j/k/l/m.py"
    create_zip(zip_path, {deep_path: "print(1)"})
    result = acquire_artifact(zip_path, run_id="test_deep")
    assert result.status == "FAIL"
    assert "Exceeded max directory depth" in str(result.findings[0].evidence)

def test_acquire_directory_safety(temp_dirs):
    test_data_dir, _ = temp_dirs
    dir_path = os.path.join(test_data_dir, "malicious_dir")
    os.makedirs(dir_path, exist_ok=True)
    with open(os.path.join(dir_path, "large.txt"), "w") as f:
        f.write("X" * (11 * 1024 * 1024))
    result = acquire_artifact(dir_path, run_id="test_dir_safety")
    assert result.status == "FAIL"
    assert "Exceeded max single file size" in str(result.findings[0].evidence)
