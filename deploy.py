import os
import shutil
from pathlib import Path
from typing import Optional
from config import config

def stage_artifact(quarantine_path: str, run_id: str, artifact_hash: str) -> str:
    """
    Copies an approved artifact from quarantine to the staged directory.
    Named by hash to prevent collisions and ensure provenance.
    """
    staged_path = os.path.join(config.staged_dir, f"{artifact_hash}_{run_id}")
    os.makedirs(staged_path, exist_ok=True)
    
    # Copy all files from quarantine to staged
    for item in os.listdir(quarantine_path):
        s = os.path.join(quarantine_path, item)
        d = os.path.join(staged_path, item)
        if os.path.isdir(s):
            shutil.copytree(s, d, dirs_exist_ok=True)
        else:
            shutil.copy2(s, d)
            
    return staged_path

def deploy_artifact(staged_path: str, artifact_hash: str) -> str:
    """
    Deploys a staged artifact to the final approved skills directory.
    Uses the hash as the directory name for the final deployment.
    """
    deploy_path = os.path.join(config.approved_dir, artifact_hash)
    
    # If it already exists, we might overwrite or skip depending on policy.
    # For v1, we overwrite to ensure the latest approved version is live.
    if os.path.exists(deploy_path):
        shutil.rmtree(deploy_path)
        
    shutil.copytree(staged_path, deploy_path)
    return deploy_path

def cleanup_quarantine(quarantine_path: str):
    """Purges the quarantine directory for a run."""
    if os.path.exists(quarantine_path):
        shutil.rmtree(quarantine_path)
