import ast
import os
import re
import json
import subprocess
from typing import List, Dict, Any
from pathlib import Path
from models import PhaseResult, Finding
from config import config

class PythonASTScanner(ast.NodeVisitor):
    def __init__(self, filename: str):
        self.filename = filename
        self.findings: List[Finding] = []
        self.dangerous_calls = {
            'eval': 'eval_detected',
            'exec': 'exec_detected',
            '__import__': 'dynamic_import_detected',
            'compile': 'suspicious_compile',
            'getattr': 'suspicious_getattr',
            'setattr': 'suspicious_setattr'
        }
        self.os_subprocess_calls = {
            'system': 'os_system_detected',
            'popen': 'os_popen_detected',
            'spawn': 'os_spawn_detected',
            'run': 'subprocess_run_detected',
            'call': 'subprocess_call_detected',
            'check_call': 'subprocess_check_call_detected',
            'check_output': 'subprocess_check_output_detected',
            'Popen': 'subprocess_Popen_detected'
        }

    def visit_Call(self, node: ast.Call):
        # 1. Simple call check: eval(), exec(), etc.
        if isinstance(node.func, ast.Name):
            if node.func.id in self.dangerous_calls:
                 self.findings.append(Finding(
                    file=self.filename,
                    threat_type=self.dangerous_calls[node.func.id],
                    severity="high",
                    line_number=node.lineno,
                    evidence=f"Call to {node.func.id}()"
                ))
        
        # 2. Module call check: os.system(), subprocess.run(), etc.
        elif isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name):
                module_name = node.func.value.id
                method_name = node.func.attr
                
                if module_name == 'os' and method_name in self.os_subprocess_calls:
                    self.findings.append(Finding(
                        file=self.filename,
                        threat_type=self.os_subprocess_calls[method_name],
                        severity="high",
                        line_number=node.lineno,
                        evidence=f"Call to os.{method_name}()"
                    ))
                elif module_name == 'subprocess' and method_name in self.os_subprocess_calls:
                    # Check if 'shell=True' is used, which is higher risk
                    is_shell = any(kw.arg == 'shell' and isinstance(kw.value, ast.Constant) and kw.value.value is True for kw in node.keywords)
                    severity = "high" if is_shell else "medium"
                    self.findings.append(Finding(
                        file=self.filename,
                        threat_type=self.os_subprocess_calls[method_name],
                        severity=severity,
                        line_number=node.lineno,
                        evidence=f"Call to subprocess.{method_name}(shell={is_shell})"
                    ))

        self.generic_visit(node)

    def visit_Import(self, node: ast.Import):
        for alias in node.names:
            if alias.name in ['os', 'subprocess', 'shutil', 'socket', 'requests']:
                 self.findings.append(Finding(
                    file=self.filename,
                    threat_type="sensitive_module_import",
                    severity="low",
                    line_number=node.lineno,
                    evidence=f"Imported {alias.name}"
                ))
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        if node.module in ['os', 'subprocess', 'shutil', 'socket', 'requests']:
             self.findings.append(Finding(
                    file=self.filename,
                    threat_type="sensitive_module_import",
                    severity="low",
                    line_number=node.lineno,
                    evidence=f"Imported from {node.module}"
                ))
        self.generic_visit(node)

def scan_python_file(file_path: str) -> List[Finding]:
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            tree = ast.parse(f.read(), filename=file_path)
        visitor = PythonASTScanner(file_path)
        visitor.visit(tree)
        return visitor.findings
    except Exception as e:
        return [Finding(
            file=file_path,
            threat_type="parse_error",
            severity="medium",
            evidence=str(e)
        )]

def scan_javascript_patterns(file_path: str) -> List[Finding]:
    findings = []
    dangerous_patterns = [
        (r'eval\(', 'js_eval_detected', 'high'),
        (r'child_process\.exec', 'js_child_process_exec', 'high'),
        (r'child_process\.spawn', 'js_child_process_spawn', 'high'),
        (r'new Function\(', 'js_dynamic_function', 'high'),
    ]
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
            for pattern, threat, severity in dangerous_patterns:
                matches = re.finditer(pattern, content)
                for match in matches:
                    # Basic line number estimation
                    line_no = content.count('\n', 0, match.start()) + 1
                    findings.append(Finding(
                        file=file_path,
                        threat_type=threat,
                        severity=severity,
                        line_number=line_no,
                        evidence=match.group(0)
                    ))
    except Exception as e:
         findings.append(Finding(file=file_path, threat_type="read_error", severity="medium", evidence=str(e)))
    return findings

def scan_shell_patterns(file_path: str) -> List[Finding]:
    findings = []
    dangerous_patterns = [
        (r'curl\s+.*\s*\|\s*bash', 'shell_pipe_bash', 'high'),
        (r'wget\s+.*\s*\|\s*sh', 'shell_pipe_sh', 'high'),
        (r'/dev/tcp/', 'reverse_shell_pattern', 'high'),
        (r'rm\s+-rf\s+/', 'destructive_command', 'high'),
    ]
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
            for pattern, threat, severity in dangerous_patterns:
                matches = re.finditer(pattern, content)
                for match in matches:
                    line_no = content.count('\n', 0, match.start()) + 1
                    findings.append(Finding(
                        file=file_path,
                        threat_type=threat,
                        severity=severity,
                        line_number=line_no,
                        evidence=match.group(0)
                    ))
    except Exception as e:
         findings.append(Finding(file=file_path, threat_type="read_error", severity="medium", evidence=str(e)))
    return findings

def scan_markdown_heuristics(file_path: str) -> List[Finding]:
    findings = []
    # Detect zero-width characters and other invisible control characters
    invisible_chars_pattern = r'[\u200b\u200c\u200d\u200e\u200f\uFEFF]'
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
            matches = re.finditer(invisible_chars_pattern, content)
            for match in matches:
                line_no = content.count('\n', 0, match.start()) + 1
                findings.append(Finding(
                    file=file_path,
                    threat_type="invisible_character_detected",
                    severity="medium",
                    line_number=line_no,
                    evidence=f"Char code: {hex(ord(match.group(0)))}"
                ))
    except Exception as e:
         findings.append(Finding(file=file_path, threat_type="read_error", severity="medium", evidence=str(e)))
    return findings

def run_bandit(quarantine_path: str) -> List[Finding]:
    findings = []
    try:
        # Run bandit and get JSON output
        result = subprocess.run(
            [config.bandit_path, "-r", quarantine_path, "-f", "json"],
            capture_output=True,
            text=True,
            timeout=config.algorithmic_timeout
        )
        if result.stdout:
            data = json.loads(result.stdout)
            for issue in data.get('results', []):
                findings.append(Finding(
                    file=issue.get('filename'),
                    threat_type=f"bandit_{issue.get('test_id')}",
                    severity=issue.get('issue_severity').lower(),
                    line_number=issue.get('line_number'),
                    evidence=issue.get('issue_text')
                ))
    except Exception as e:
        findings.append(Finding(
            file=quarantine_path,
            threat_type="bandit_execution_error",
            severity="medium",
            evidence=str(e)
        ))
    return findings

def run_semgrep(quarantine_path: str) -> List[Finding]:
    findings = []
    try:
        # Run semgrep scan and get JSON output
        result = subprocess.run(
            [config.semgrep_path, "scan", "--config", "auto", "--json", quarantine_path],
            capture_output=True,
            text=True,
            timeout=config.algorithmic_timeout
        )
        if result.stdout:
            data = json.loads(result.stdout)
            for issue in data.get('results', []):
                findings.append(Finding(
                    file=issue.get('path'),
                    threat_type=f"semgrep_{issue.get('check_id')}",
                    severity=issue.get('extra', {}).get('severity', 'medium').lower(),
                    line_number=issue.get('start', {}).get('line'),
                    evidence=issue.get('extra', {}).get('message')
                ))
    except Exception as e:
        findings.append(Finding(
            file=quarantine_path,
            threat_type="semgrep_execution_error",
            severity="medium",
            evidence=str(e)
        ))
    return findings

def run_algorithmic_scan(quarantine_path: str) -> PhaseResult:
    all_findings = []
    
    for root, dirs, files in os.walk(quarantine_path):
        for file in files:
            full_path = os.path.join(root, file)
            rel_path = os.path.relpath(full_path, quarantine_path)
            
            if file.endswith('.py'):
                all_findings.extend(scan_python_file(full_path))
            elif file.endswith(('.js', '.mjs', '.cjs')):
                all_findings.extend(scan_javascript_patterns(full_path))
            elif file.endswith('.sh'):
                all_findings.extend(scan_shell_patterns(full_path))
            elif file.endswith(('.md', '.txt')):
                all_findings.extend(scan_markdown_heuristics(full_path))
            
            # Manifest checks
            if file == 'package.json':
                # Add specific package.json checks if needed
                pass

    # External Tools
    all_findings.extend(run_bandit(quarantine_path))
    all_findings.extend(run_semgrep(quarantine_path))

    # Determine status
    status = "PASS"
    if any(f.severity == "high" for f in all_findings):
        status = "FAIL"
    # Logic for medium clusters can be added here
    
    return PhaseResult(
        phase="algorithmic",
        status=status,
        findings=all_findings
    )
