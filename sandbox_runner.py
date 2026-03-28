import os
import subprocess
import json
import re
from typing import List, Dict, Any, Optional
from pathlib import Path
from models import PhaseResult, Finding, Anomaly
from config import config

def translate_path_to_docker(path: str) -> str:
    abs_path = os.path.abspath(path)
    drive, rest = os.path.splitdrive(abs_path)
    drive_letter = drive[0].lower()
    return "/" + drive_letter + rest.replace("\\", "/")

def run_in_container(quarantine_path: str, command: List[str], timeout: int, image: str) -> Dict[str, Any]:
    docker_source = translate_path_to_docker(quarantine_path)
    docker_target = "/app/skill"
    docker_cmd = [
        config.docker_path, "run", "--rm", "--network", "none", "--read-only",
        "--tmpfs", "/tmp", "--volume", f"{docker_source}:{docker_target}:ro",
        "--workdir", docker_target, image
    ] + command

    try:
        result = subprocess.run(docker_cmd, capture_output=True, text=True, timeout=timeout)
        return {"status": "PASS" if result.returncode == 0 else "FAIL", "exit_code": result.returncode, "stdout": result.stdout, "stderr": result.stderr, "timed_out": False}
    except subprocess.TimeoutExpired as e:
        return {"status": "FAIL", "exit_code": -1, "stdout": e.stdout if e.stdout else "", "stderr": e.stderr if e.stderr else "", "timed_out": True}
    except Exception as e:
        return {"status": "FAIL", "exit_code": -2, "stdout": "", "stderr": str(e), "timed_out": False}

def run_sandbox_scan(quarantine_path: str) -> PhaseResult:
    anomalies = []
    entrypoints = []
    for root, _, files in os.walk(quarantine_path):
        for f in files:
            fpath = os.path.join(root, f)
            rel = os.path.relpath(fpath, quarantine_path)
            if f.endswith(('.py', '.js', '.sh')): entrypoints.append(rel)

    if not entrypoints: return PhaseResult(phase="sandbox", status="PASS", findings=[], anomalies=[])

    # Execute all identified entrypoints (bounded)
    for target in entrypoints[:10]:
        if target.endswith('.py'):
            cmd = ["python", target]
            image = config.sandbox_python_image
        elif target.endswith('.js'):
            cmd = ["node", target]
            image = config.sandbox_node_image
        else: # .sh
            cmd = ["sh", target]
            image = "debian:stable-slim"

        res = run_in_container(quarantine_path, cmd, config.sandbox_timeout, image)
        
        if res["timed_out"]:
            anomalies.append(Anomaly(type="timeout", severity="high", description=f"{target} timed out."))
        elif res["exit_code"] != 0:
            anomalies.append(Anomaly(type="execution_error", severity="high", description=f"{target} failed with exit code {res['exit_code']}."))

        # Telemetry from output (Check both stdout and stderr)
        combined_output = res["stdout"] + res["stderr"]
        if re.search(r"PermissionError|Read-only|EACCES|EPERM", combined_output, re.I):
            anomalies.append(Anomaly(type="write_attempt", target=target, severity="high", description="Unauthorized write detected."))
        if re.search(r"socket|connect|network|ECONNREFUSED|ENETUNREACH|TimeoutError", combined_output, re.I):
            anomalies.append(Anomaly(type="network_attempt", target=target, severity="high", description="Unauthorized network access detected."))

    status = "FAIL" if any(a.severity == "high" for a in anomalies) else "PASS"
    return PhaseResult(phase="sandbox", status=status, anomalies=anomalies)
