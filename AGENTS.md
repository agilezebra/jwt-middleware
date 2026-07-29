# Agent Instructions

## Completion Gate

- After every substantive repository change, run all tests in coverage mode with the dedicated test tool; workspace settings enable `-race`.
- Never use the terminal tool for this gate.
- Do not report the work complete unless the tests pass.
- Coverage must remain at 100%. Add meaningful tests for every changed behavior; do not weaken or exclude coverage to satisfy the threshold.
- Do not create commits unless the user explicitly requests one.

## Identifiers

- Use complete English words; common initialisms (`JWT`, `TCP`, `JWKS`) are allowed. Contracted (`recv`, `sock`) and single-letter names are prohibited, except Go's ubiquitous `ctx` and `err`.
- Still keep identifiers as short as possible while remaining clear and unambiguous. Use multiple words if necessary to avoid ambiguity but prefer fewer words if possible.
