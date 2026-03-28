import os
from pydantic import Field, ConfigDict
from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import Optional

class PipelineConfig(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="SKILLCHECK_")
    
    # Mode - DEFAULT TO PRODUCTION SAFE
    production: bool = True
    
    # Directory paths
    quarantine_dir: str = "quarantine"
    forensic_dir: str = "forensic"
    approved_dir: str = "approved"
    staged_dir: str = "staged"
    live_skills_dir: str = "skills"
    
    # Acquisition limits
    max_archive_bytes: int = 50 * 1024 * 1024  # 50 MB
    max_file_count: int = 1000
    max_directory_depth: int = 10  # Reduced from 20
    max_single_file_size: int = 10 * 1024 * 1024  # 10 MB
    max_nested_archives: int = 0  # Default to no nested archives allowed for safety
    
    # External Tools Paths
    semgrep_path: str = "semgrep"
    bandit_path: str = "bandit"
    docker_path: str = "docker"
    
    # Sandbox Images
    sandbox_python_image: str = "python:3.13-slim"
    sandbox_node_image: str = "node:20-slim"
    
    # Model config
    llm_endpoint: str = "http://localhost:8081/v1"
    llm_model: str = "qwen3-9b-chat"
    
    # Timeouts (seconds)
    acquisition_timeout: int = 30
    algorithmic_timeout: int = 60
    semantic_timeout: int = 90
    sandbox_timeout: int = 120

# Global config instance
config = PipelineConfig()
