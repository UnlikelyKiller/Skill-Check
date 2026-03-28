# Track 3 Specification: Semantic Scanner

## Purpose
Use a local model to detect prompt injection, deceptive metadata, behavioral mismatch, and unsafe natural-language instructions that deterministic scanners cannot fully resolve.

## Model Interface
- **Client**: `openai` (OpenAI-compatible)
- **Base URL**: `http://localhost:8081/v1`
- **Model**: `qwen3-9b-chat`
- **Structured Output**: `instructor` + `pydantic`

## Pre-LLM Checks
- Parse YAML frontmatter.
- Isolate markdown body.
- Detect invisible unicode/control chars (already in Track 2, but should be integrated).
- Flag explicit override phrases.

## Status Logic
- `FAIL` on detected prompt injection.
- `FAIL` on severe metadata/body mismatch.
- `FAIL` on instructions for hidden dependency changes or secret access.
- `FAIL-CLOSED` on model unavailability or structured validation failure.

## Expected Output Schema
```json
{
  "phase": "semantic",
  "status": "PASS|FAIL",
  "cognitive_threats_detected": true,
  "threat_category": "prompt_injection|metadata_impersonation|dependency_hijacking|exfiltration_instruction|unknown",
  "confidence": "high|medium|low",
  "reasoning": "...",
  "supporting_evidence": []
}
```
