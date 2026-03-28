# Implementation Plan: Track 3 - Semantic Scanner

## Milestone 3: Cognitive Evaluation

### Step 1: Pydantic Models for Instructor (`scanner_semantic.py`)
Define the `SemanticAnalysis` model to enforce structured output from the LLM.

### Step 2: LLM Client Setup
- Use `instructor.patch()` with the `openai` client.
- Configure for local endpoint `http://localhost:8081/v1`.

### Step 3: Text Pre-processing
- Implement `parse_skill_text` to separate metadata (YAML) from instructions (Markdown).

### Step 4: Prompt Engineering
- Develop a system prompt that defines the security auditor persona.
- Ensure the prompt instructs the model to analyze but not execute the untrusted content.

### Step 5: Finding Translation
- Map LLM assessments (cognitive threats, categories) to the common `Finding` and `PhaseResult` models.

### Step 6: Testing and Mocking
- Use `unittest.mock` to simulate LLM responses for unit testing.
- Test benign, injection, and error scenarios.
