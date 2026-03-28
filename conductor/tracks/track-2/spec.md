# Track 2 Specification: Algorithmic Scanner

## Purpose
Perform broad, deterministic triage across code and text artifacts before any semantic or behavioral analysis.

## Coverage Areas
- **Python AST Checks**: Parse `.py` files, flag `eval`, `exec`, `__import__`, suspicious `subprocess`, filesystem writes outside work area.
- **JavaScript/Node Pattern Checks**: Scan `.js`, `.mjs`, `.cjs`, `package.json`, flag `child_process`, `eval`, installation hooks (`postinstall`, etc.).
- **Shell/Bash Checks**: Scan `.sh`, flag `curl | bash`, reverse shell patterns, destructive commands.
- **Markdown/Text Heuristics**: Scan `SKILL.md`, detect zero-width/invisible control characters, suspicious override phrases.
- **Manifest Tampering**: Check `package.json`, `requirements.txt`, `pyproject.toml`, `setup.py`.
- **External Engines**: Integrate `semgrep` and `bandit`.

## Status Logic
- Any confirmed high-severity finding => `FAIL`.
- Medium-severity clusters may fail based on policy threshold.
- Empty findings => `PASS`.

## Expected Output Schema
```json
{
  "phase": "algorithmic",
  "status": "PASS|FAIL",
  "findings": [
    {
      "file": "...",
      "threat_type": "...",
      "severity": "high|medium|low",
      "line_number": 42,
      "evidence": "..."
    }
  ]
}
```
