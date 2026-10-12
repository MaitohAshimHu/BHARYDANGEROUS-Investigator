# Contributing to BHARYDANGEROUS-Investigator

Thank you for your interest in contributing to **BHARYDANGEROUS-Investigator**, an open-source digital forensics and incident response CLI created by Ashim.

## Core Forensic Engineering Principles

When contributing code, you must adhere to our non-negotiable forensic principles:

1. **Evidence Immutability:** Never modify, move, or delete original evidence files. Always open evidence with read-only file descriptors (`os.O_RDONLY`).
2. **Zero Dynamic Execution:** Never execute scripts, executables, or code extracted from evidence. Treat all evidence data as untrusted and potentially hostile.
3. **Epistemic Separation:** Strictly distinguish:
   - **Facts:** Deterministic parser output (byte offsets, hashes, timestamps).
   - **Heuristics:** Signature matches (YARA, entropy thresholds, regexes).
   - **Hypotheses:** Cross-artifact correlation patterns.
   - **AI Interpretations:** Generative reasoning, which must always link to verified finding IDs.
4. **Air-Gap & Offline Capability:** Core deterministic features must function 100% offline without network connectivity or API tokens. External tools and AI services must be optional adapters with graceful fallback.

## Development Workflow

1. Fork and clone the repository.
2. Set up the development environment:
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate  # On Windows: .\.venv\Scripts\Activate.ps1
   pip install -e ".[all]"
   ```
3. Run diagnostics and the test suite:
   ```bash
   bdinvestigator doctor
   pytest -v
   ```
4. Create a descriptive feature branch:
   ```bash
   git checkout -b feature/new-forensic-parser
   ```
5. Ensure 100% test pass rate with adversarial test cases before opening a Pull Request.

## Coding Standards

- Python 3.11+ syntax with type annotations.
- Strict subprocess argument arrays (never use `shell=True`).
- Pydantic models for structured records.
- Comprehensive docstrings explaining forensic artifacts and data structures.
