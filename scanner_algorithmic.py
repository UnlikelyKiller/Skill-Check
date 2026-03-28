import ast
import os
import re
import json
import shutil
import subprocess
from typing import List, Dict, Any
from pathlib import Path
from models import PhaseResult, Finding
from config import config
from errors import ScannerError

class PythonASTScanner(ast.NodeVisitor):
    def __init__(self, filename: str, root_path: str):
        self.filename = filename
        self.rel_path = os.path.relpath(filename, root_path)
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
        if isinstance(node.func, ast.Name):
            if node.func.id in self.dangerous_calls:
                 self.findings.append(Finding(
                    file=self.rel_path,
                    threat_type=self.dangerous_calls[node.func.id],
                    severity="high",
                    line_number=node.lineno,
                    evidence=f"Call to {node.func.id}()"
                ))
        elif isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name):
                module_name = node.func.value.id
                method_name = node.func.attr
                if module_name == 'os' and method_name in self.os_subprocess_calls:
                    self.findings.append(Finding(
                        file=self.rel_path,
                        threat_type=self.os_subprocess_calls[method_name],
                        severity="high",
                        line_number=node.lineno,
                        evidence=f"Call to os.{method_name}()"
                    ))
                elif module_name == 'subprocess' and method_name in self.os_subprocess_calls:
                    is_shell = any(kw.arg == 'shell' and isinstance(kw.value, ast.Constant) and kw.value.value is True for kw in node.keywords)
                    severity = "high" if is_shell else "medium"
                    self.findings.append(Finding(
                        file=self.rel_path,
                        threat_type=self.os_subprocess_calls[method_name],
                        severity=severity,
                        line_number=node.lineno,
                        evidence=f"Call to subprocess.{method_name}(shell={is_shell})"
                    ))
        self.generic_visit(node)

def scan_python_file(file_path: str, root_path: str) -> List[Finding]:
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            tree = ast.parse(f.read(), filename=file_path)
        visitor = PythonASTScanner(file_path, root_path)
        visitor.visit(tree)
        return visitor.findings
    except Exception as e:
        return [Finding(file=os.path.relpath(file_path, root_path), threat_type="parse_error", severity="medium", evidence=str(e))]

def scan_javascript_patterns(file_path: str, root_path: str) -> List[Finding]:
    findings = []
    rel_path = os.path.relpath(file_path, root_path)
    dangerous_patterns = [
        (r'eval\(', 'js_eval_detected', 'high'),
        (r'child_process\.exec', 'js_child_process_exec', 'high'),
        (r'new Function\(', 'js_dynamic_function', 'high'),
    ]
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
            for pattern, threat, severity in dangerous_patterns:
                for match in re.finditer(pattern, content):
                    line_no = content.count('\n', 0, match.start()) + 1
                    findings.append(Finding(file=rel_path, threat_type=threat, severity=severity, line_number=line_no, evidence=match.group(0)))
    except Exception as e:
         findings.append(Finding(file=rel_path, threat_type="read_error", severity="medium", evidence=str(e)))
    return findings

def scan_shell_patterns(file_path: str, root_path: str) -> List[Finding]:
    findings = []
    rel_path = os.path.relpath(file_path, root_path)
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
                for match in re.finditer(pattern, content):
                    line_no = content.count('\n', 0, match.start()) + 1
                    findings.append(Finding(file=rel_path, threat_type=threat, severity=severity, line_number=line_no, evidence=match.group(0)))
    except Exception:
         pass
    return findings

def scan_markdown_heuristics(file_path: str, root_path: str) -> List[Finding]:
    findings = []
    rel_path = os.path.relpath(file_path, root_path)
    invisible_chars_pattern = r'[\u200b\u200c\u200d\u200e\u200f\uFEFF]'
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
            for match in re.finditer(invisible_chars_pattern, content):
                line_no = content.count('\n', 0, match.start()) + 1
                findings.append(Finding(file=rel_path, threat_type="invisible_character_detected", severity="medium", line_number=line_no, evidence=hex(ord(match.group(0)))))
    except Exception:
         pass
    return findings

def check_manifests(file_path: str, root_path: str) -> List[Finding]:
    findings = []
    rel_path = os.path.relpath(file_path, root_path)
    fname = os.path.basename(file_path)
    try:
        with open(file_path, 'r') as f:
            content = f.read()
            if fname == 'package.json':
                data = json.loads(content)
                scripts = data.get('scripts', {})
                for sname, scmd in scripts.items():
                    if any(x in scmd for x in ['curl', 'wget', 'sh', 'bash']):
                        findings.append(Finding(file=rel_path, threat_type="suspicious_npm_script", severity="medium", evidence=f"{sname}: {scmd}"))
            elif fname == 'requirements.txt':
                if 'http' in content or 'git+' in content:
                    findings.append(Finding(file=rel_path, threat_type="remote_dependency_detected", severity="medium", evidence="Remote URL in requirements.txt"))
    except Exception:
        pass
    return findings

def run_external_tool(tool_path: str, args: List[str], tool_name: str) -> List[Dict[str, Any]]:
    if not shutil.which(tool_path):
        if config.production:
            raise ScannerError(f"Required tool {tool_name} is missing in production mode.")
        return []
    try:
        result = subprocess.run([tool_path] + args, capture_output=True, text=True, timeout=config.algorithmic_timeout, errors='replace')
        if result.stdout:
            try:
                data = json.loads(result.stdout)
                return data.get('results', [])
            except json.JSONDecodeError:
                return []
    except Exception as e:
        if config.production:
            raise ScannerError(f"Error running {tool_name}: {str(e)}")
    return []

def run_algorithmic_scan(quarantine_path: str) -> PhaseResult:
    all_findings = []
    for root, _, files in os.walk(quarantine_path):
        for file in files:
            fpath = os.path.join(root, file)
            if file.endswith('.py'): all_findings.extend(scan_python_file(fpath, quarantine_path))
            elif file.endswith(('.js', '.mjs', '.cjs')): all_findings.extend(scan_javascript_patterns(fpath, quarantine_path))
            elif file.endswith('.sh'): all_findings.extend(scan_shell_patterns(fpath, quarantine_path))
            elif file.endswith(('.md', '.txt')): all_findings.extend(scan_markdown_heuristics(fpath, quarantine_path))
            if file in ['package.json', 'requirements.txt', 'pyproject.toml']: all_findings.extend(check_manifests(fpath, quarantine_path))

    # Bandit
    bandit_results = run_external_tool(config.bandit_path, ["-r", quarantine_path, "-f", "json", "-q"], "Bandit")
    for issue in bandit_results:
        all_findings.append(Finding(file=os.path.relpath(issue.get('filename'), quarantine_path), threat_type=f"bandit_{issue.get('test_id')}", severity=issue.get('issue_severity').lower(), line_number=issue.get('line_number'), evidence=issue.get('issue_text')))

    # Semgrep - Use local rules and offline mode
    rules_path = os.path.abspath("semgrep_rules.yaml")
    semgrep_args = ["scan", "--config", rules_path, "--json", "--metrics", "off", "--no-git-ignore", quarantine_path]
    semgrep_results = run_external_tool(config.semgrep_path, semgrep_args, "Semgrep")
    for issue in semgrep_results:
        all_findings.append(Finding(file=os.path.relpath(issue.get('path'), quarantine_path), threat_type=f"semgrep_{issue.get('check_id')}", severity=issue.get('extra', {}).get('severity', 'medium').lower(), line_number=issue.get('start', {}).get('line'), evidence=issue.get('extra', {}).get('message')))

    status = "PASS"
    if any(f.severity == "high" for f in all_findings):
        status = "FAIL"
    elif len([f for f in all_findings if f.severity == "medium"]) >= 5:
        status = "FAIL"
    
    return PhaseResult(phase="algorithmic", status=status, findings=all_findings)
