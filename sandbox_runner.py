import os
import subprocess
import json
from typing import List, Dict, Any, Optional
from pathlib import Path
from models import PhaseResult, Finding, Anomaly
from config import config

def translate_path_to_docker(path: str) -> str:
    r"""
    Translates a Windows absolute path to a Docker-compatible path.
    Example: C:\dev\Skill-Check -> /c/dev/Skill-Check
    """
    abs_path = os.path.abspath(path)
    drive, rest = os.path.splitdrive(abs_path)
    # Drive letter to lowercase and remove colon
    drive_letter = drive[0].lower()
    # Replace backslashes with forward slashes
    docker_path = "/" + drive_letter + rest.replace("\\", "/")
    return docker_path

def run_in_container(quarantine_path: str, command: List[str], timeout: int) -> Dict[str, Any]:
    """
    Runs a command inside a Docker container with strict isolation.
    """
    docker_source = translate_path_to_docker(quarantine_path)
    docker_target = "/app/skill"
    
    # Base docker run command
    docker_cmd = [
        config.docker_path, "run", "--rm",
        "--network", "none",
        "--read-only",
        "--tmpfs", "/tmp",
        "--volume", f"{docker_source}:{docker_target}:ro",
        "--workdir", docker_target,
        "python:3.13-slim",
    ] + command

    try:
        result = subprocess.run(
            docker_cmd,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        return {
            "status": "PASS" if result.returncode == 0 else "FAIL",
            "exit_code": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "timed_out": False
        }
    except subprocess.TimeoutExpired as e:
        return {
            "status": "FAIL",
            "exit_code": -1,
            "stdout": e.stdout.decode() if e.stdout else "",
            "stderr": e.stderr.decode() if e.stderr else "",
            "timed_out": True
        }
    except Exception as e:
        return {
            "status": "FAIL",
            "exit_code": -2,
            "stdout": "",
            "stderr": str(e),
            "timed_out": False
        }

def run_sandbox_scan(quarantine_path: str) -> PhaseResult:
    """
    Performs behavioral evaluation by running synthetic routines.
    For v1, we'll try to execute any .py file that looks like an entrypoint or test.
    """
    anomalies = []
    
    # Look for a main.py or similar, otherwise try all .py files in root
    entrypoints = [f for f in os.listdir(quarantine_path) if f.endswith('.py')]
    
    if not entrypoints:
        return PhaseResult(phase="sandbox", status="PASS", findings=[], anomalies=[])

    # For simplicity, we'll run the first .py file found
    target_script = entrypoints[0]
    
    # Synthetic routine: try to run the script
    # Note: We use 'python' because our image is 'python:3.13-slim'
    container_result = run_in_container(
        quarantine_path, 
        ["python", target_script], 
        config.sandbox_timeout
    )
    
    if container_result["timed_out"]:
        anomalies.append(Anomaly(
            type="timeout",
            severity="high",
            description=f"Script {target_script} timed out after {config.sandbox_timeout}s."
        ))
    elif container_result["exit_code"] != 0:
        anomalies.append(Anomaly(
            type="execution_error",
            severity="medium",
            description=f"Script {target_script} exited with code {container_result['exit_code']}. Stderr: {container_result['stderr'][:200]}"
        ))

    # Basic anomaly detection from stderr (e.g., PermissionError on write)
    if "PermissionError" in container_result["stderr"] or "Read-only file system" in container_result["stderr"]:
        # In our case, this might be a 'PASS' if we are testing a malicious script,
        # but for behavioral evaluation, we want to flag it as an anomaly if it's unexpected.
        # If the script *should* be read-only but *tried* to write, it's a finding.
        anomalies.append(Anomaly(
            type="write_attempt",
            target=target_script,
            severity="medium",
            description="Attempted write to read-only filesystem detected."
        ))

    status = "PASS"
    if any(a.severity == "high" for a in anomalies):
        status = "FAIL"
    elif any(a.type == "write_attempt" for a in anomalies):
        # Explicit policy: any write attempt is a fail in this zero-trust model
        status = "FAIL"

    return PhaseResult(
        phase="sandbox",
        status=status,
        anomalies=anomalies,
        metadata={
            "exit_code": container_result["exit_code"],
            "timed_out": container_result["timed_out"],
            "script_run": target_script
        }
    )
