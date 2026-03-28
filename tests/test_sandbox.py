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

@pytest.mark.skipif(shutil.which("docker") is None, reason="Docker not installed")
def test_sandbox_benign(test_quarantine):
    py_path = os.path.join(test_quarantine, "benign.py")
    with open(py_path, "w") as f:
        f.write("print('hello from sandbox')\n")
    result = run_sandbox_scan(test_quarantine)
    assert result.status == "PASS"

@pytest.mark.skipif(shutil.which("docker") is None, reason="Docker not installed")
def test_sandbox_js_execution(test_quarantine):
    js_path = os.path.join(test_quarantine, "main.js")
    with open(js_path, "w") as f:
        f.write("console.log('hello from node')\n")
    # Verify it uses node image
    result = run_sandbox_scan(test_quarantine)
    assert result.status == "PASS"

@pytest.mark.skipif(shutil.which("docker") is None, reason="Docker not installed")
def test_sandbox_js_failure(test_quarantine):
    js_path = os.path.join(test_quarantine, "fail.js")
    with open(js_path, "w") as f:
        f.write("process.exit(1)\n")
    result = run_sandbox_scan(test_quarantine)
    assert result.status == "FAIL"
    assert any(a.type == "execution_error" and a.severity == "high" for a in result.anomalies)

@pytest.mark.skipif(shutil.which("docker") is None, reason="Docker not installed")
def test_sandbox_network_attempt(test_quarantine):
    py_path = os.path.join(test_quarantine, "net.py")
    with open(py_path, "w") as f:
        f.write("import socket\ntry: socket.create_connection(('8.8.8.8', 53), timeout=1)\nexcept Exception as e: print(f'Network error: {e}')\n")
    result = run_sandbox_scan(test_quarantine)
    # Even if it prints error, our telemetry should catch keywords in stderr/stdout
    # Note: run_in_container captures stdout/stderr. run_sandbox_scan checks res["stderr"]
    # Let's ensure net.py triggers something in stderr or we check both.
    assert result.status == "FAIL"
    assert any(a.type == "network_attempt" for a in result.anomalies)

@pytest.mark.skipif(shutil.which("docker") is None, reason="Docker not installed")
def test_sandbox_write_attempt(test_quarantine):
    py_path = os.path.join(test_quarantine, "write.py")
    with open(py_path, "w") as f:
        f.write("open('root_file.txt', 'w').write('data')\n")
    result = run_sandbox_scan(test_quarantine)
    assert result.status == "FAIL"
    assert any(a.type == "write_attempt" for a in result.anomalies)
