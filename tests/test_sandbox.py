import os
import shutil
import pytest
import subprocess
from sandbox_runner import run_sandbox_scan, translate_path_to_docker
from config import config

@pytest.fixture
def test_quarantine():
    path = os.path.abspath("test_sandbox_quarantine")
    os.makedirs(path, exist_ok=True)
    yield path
    shutil.rmtree(path)

def test_path_translation():
    assert translate_path_to_docker("C:\\Users\\Admin\\dev") == "/c/Users/Admin/dev"
    assert translate_path_to_docker("d:\\work") == "/d/work"

@pytest.mark.skipif(shutil.which("docker") is None, reason="Docker not installed")
def test_sandbox_benign(test_quarantine):
    py_path = os.path.join(test_quarantine, "benign.py")
    with open(py_path, "w") as f:
        f.write("print('hello from sandbox')\n")
    
    result = run_sandbox_scan(test_quarantine)
    
    assert result.status == "PASS"
    assert result.metadata["exit_code"] == 0

@pytest.mark.skipif(shutil.which("docker") is None, reason="Docker not installed")
def test_sandbox_write_attempt(test_quarantine):
    py_path = os.path.join(test_quarantine, "malicious.py")
    with open(py_path, "w") as f:
        # Attempt to write to the read-only mount
        f.write("with open('pwned.txt', 'w') as f: f.write('evil')\n")
    
    result = run_sandbox_scan(test_quarantine)
    
    assert result.status == "FAIL"
    assert any(a.type == "write_attempt" for a in result.anomalies)

@pytest.mark.skipif(shutil.which("docker") is None, reason="Docker not installed")
def test_sandbox_timeout(test_quarantine):
    py_path = os.path.join(test_quarantine, "hanging.py")
    with open(py_path, "w") as f:
        f.write("import time\ntime.sleep(10)\n")
    
    # Temporarily set short timeout
    old_timeout = config.sandbox_timeout
    config.sandbox_timeout = 2
    try:
        result = run_sandbox_scan(test_quarantine)
        assert result.status == "FAIL"
        assert result.metadata["timed_out"] is True
    finally:
        config.sandbox_timeout = old_timeout
