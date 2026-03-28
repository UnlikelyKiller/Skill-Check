import os
import shutil
import zipfile
import pytest
from unittest.mock import MagicMock, patch
from pipeline_main import run_pipeline
from scanner_semantic import SemanticAnalysis

@pytest.fixture
def temp_dirs():
    dirs = ["test_quarantine", "test_forensic", "test_approved", "test_staged"]
    for d in dirs:
        os.makedirs(d, exist_ok=True)
    yield dirs
    for d in dirs:
        if os.path.exists(d):
            shutil.rmtree(d)

def create_zip(path, files):
    with zipfile.ZipFile(path, 'w') as zf:
        for filename, content in files.items():
            zf.writestr(filename, content)

@patch("scanner_semantic.OpenAI")
@patch("instructor.patch")
@patch("sandbox_runner.run_in_container")
def test_pipeline_full_pass(mock_sandbox, mock_patch, mock_openai, temp_dirs):
    # Setup mocks
    mock_client = MagicMock()
    mock_patch.return_value = mock_client
    mock_client.chat.completions.create.return_value = SemanticAnalysis(
        cognitive_threats_detected=False,
        threat_category="none",
        confidence="high",
        reasoning="Safe",
        supporting_evidence=[],
        status="PASS"
    )
    
    mock_sandbox.return_value = {
        "status": "PASS",
        "exit_code": 0,
        "stdout": "ok",
        "stderr": "",
        "timed_out": False
    }

    # Create benign zip
    zip_path = "benign_pipeline.zip"
    create_zip(zip_path, {
        "SKILL.md": "# Benign\nDoes nothing.",
        "main.py": "print('hello')"
    })

    try:
        report = run_pipeline(zip_path)
        assert report.final_decision == "APPROVED"
        assert report.deployment_path is not None
        assert os.path.exists(report.deployment_path)
        assert len(report.phase_results) == 4
    finally:
        if os.path.exists(zip_path):
            os.remove(zip_path)

@patch("scanner_semantic.OpenAI")
@patch("instructor.patch")
@patch("sandbox_runner.run_in_container")
def test_pipeline_fail_algorithmic(mock_sandbox, mock_patch, mock_openai, temp_dirs):
    # Create malicious zip (high severity AST threat)
    zip_path = "malicious_alg.zip"
    create_zip(zip_path, {
        "SKILL.md": "# Bad",
        "main.py": "eval('evil')"
    })

    try:
        report = run_pipeline(zip_path)
        assert report.final_decision == "REJECTED"
        assert "Algorithmic" in report.rejection_reason
        # Circuit breaker should have stopped before semantic and sandbox
        assert len(report.phase_results) == 2
    finally:
        if os.path.exists(zip_path):
            os.remove(zip_path)
