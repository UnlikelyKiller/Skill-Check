# Implementation Plan: Track 2 - Algorithmic Scanner

## Milestone 2: Deterministic Triage

### Step 1: Python AST Scanner (`scanner_algorithmic.py`)
Implement an AST-based scanner that traverses the Python source tree.
- Use `ast.parse()` and `ast.NodeVisitor`.
- Flag `eval()`, `exec()`, `__import__()`.
- Detect suspicious `subprocess` and `os.system` calls.
- Identify filesystem writes outside approved patterns.
- Handle Python 3.13 specific AST nodes.

### Step 2: Pattern-Based Scanners (JS, Shell, Markdown)
- **JS/Node**: Regex/string matching for `child_process`, `eval`, and npm install hooks in `package.json`.
- **Shell**: Scan `.sh` files for `curl | bash`, `wget | sh`, and reverse shells.
- **Markdown**: Use `regex` to find zero-width characters (e.g., `\u200b`, `\u200c`) and suspicious instructions.

### Step 3: External Tool Integration
- **Bandit**: Run `bandit -r <path> -f json` and parse findings.
- **Semgrep**: Run `semgrep scan --config auto --json` and parse findings.
- Ensure "fail-closed" if tools are missing in production mode.

### Step 4: Manifest Analysis
- Check `package.json`, `requirements.txt`, `pyproject.toml` for suspicious dependencies or version pinning issues.

### Step 5: Unit and Integration Tests
- `test_algorithmic.py`
- Adversarial fixtures: `malicious_python_eval`, `malicious_js_exec`, `malicious_bash`.

### Step 6: Orchestration
- Create `run_algorithmic_scan(quarantine_path)` as the main entry point for this phase.
