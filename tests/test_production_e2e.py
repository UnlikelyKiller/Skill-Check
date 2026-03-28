import os
import shutil
import zipfile
import pytest
from pipeline_main import run_pipeline
from config import config
from models import ForensicReport

@pytest.fixture
def production_env():
    """Sets up a real production-like environment for E2E testing."""
    old_prod = config.production
    config.production = True
    
    # Ensure directories exist
    dirs = [config.quarantine_dir, config.forensic_dir, config.approved_dir, config.staged_dir]
    for d in dirs:
        os.makedirs(d, exist_ok=True)
        
    yield
    
    # Cleanup is handled by pipeline or manually if needed
    config.production = old_prod

def create_benign_zip(path):
    with zipfile.ZipFile(path, 'w') as zf:
        zf.writestr("SKILL.md", "---\nname: TestSkill\nversion: 1.0\n---\n# Helper\nDoes basic addition.")
        zf.writestr("main.py", "print(1+1)")

@pytest.mark.timeout(300) # Allow time for real LLM and Docker
def test_production_e2e_benign(production_env):
    """
    Verifies the actual production flow with real tools.
    Requires: docker, bandit, semgrep, and local LLM endpoint.
    """
    zip_path = "e2e_benign.zip"
    create_benign_zip(zip_path)
    
    try:
        report = run_pipeline(zip_path)
        
        # In this environment, we expect it to PASS if everything is set up.
        # If it REJECTS, we check why (e.g. LLM down).
        print(f"Final Decision: {report.final_decision}")
        if report.final_decision == "REJECTED":
            print(f"Rejection Reason: {report.rejection_reason}")
            
        assert isinstance(report, ForensicReport)
        assert report.run_id is not None
        assert len(report.phase_results) > 0
        
        # Verify Sandbox Telemetry in the report
        sandbox_res = next((r for r in report.phase_results if r.phase == "sandbox"), None)
        if sandbox_res:
            assert "telemetry" in sandbox_res.metadata
            assert len(sandbox_res.metadata["telemetry"]) > 0
            assert "stdout" in sandbox_res.metadata["telemetry"][0]

    finally:
        if os.path.exists(zip_path):
            os.remove(zip_path)

def test_sandbox_telemetry_contract():
    """Directly verifies the sandbox metadata matches the plan."""
    from sandbox_runner import run_sandbox_scan
    
    test_dir = "test_telemetry_quarantine"
    os.makedirs(test_dir, exist_ok=True)
    with open(os.path.join(test_dir, "main.py"), "w") as f:
        f.write("print('hello')\n")
        
    try:
        result = run_sandbox_scan(test_dir)
        metadata = result.metadata
        assert "telemetry" in metadata
        tel = metadata["telemetry"][0]
        assert "stdout" in tel
        assert "stderr" in tel
        assert "exit_code" in tel
        assert "process_spawn_count" in tel
    finally:
        shutil.rmtree(test_dir)
