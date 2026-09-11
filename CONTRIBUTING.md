# Contributing to Agent Vardøger

We welcome contributions, especially detection signatures that improve security for the entire community.

## Signature Contributions

The most impactful way to contribute is by submitting new detection patterns. We accept:

- **Regex signatures** for new attack patterns you've observed in the wild
- **Hash lookups** for known-malicious prompts
- **Detection policy rules** for term-combination patterns
- **False-positive corrections** that reduce over-detection on benign prompts

### Signature Submission Process

1. Fork the repository and create a branch: `git checkout -b sig/your-pattern-name`
2. Add your pattern to the appropriate file in `signatures/community/`
3. Include a test case in `tests/signatures/` that demonstrates the pattern matching a malicious prompt AND not matching a benign variant
4. Run the validation suite: `make test-signatures`
5. Submit a pull request with:
   - Description of the attack this pattern detects
   - Example malicious prompt (can be redacted if sensitive)
   - Example benign prompt that should NOT match
   - Source/reference if from a public disclosure

### Signature Quality Requirements

All submitted patterns must pass:

- **ReDoS screening:** No catastrophic backtracking risk (automated check in CI)
- **False-positive suite:** Must not flag the benign prompt test corpus
- **Regex compilation:** Must be valid Python `re` syntax
- **Minimum specificity:** Must not match on single common English words

### Pattern Format

```json
{
  "id": "sig-community-001",
  "severity": "high",
  "category": "prompt_injection",
  "pattern": "(?i)your\\s+regex\\s+here",
  "description": "Detects XYZ attack variant",
  "author": "your-github-handle",
  "references": ["https://example.com/disclosure"]
}
```

## Code Contributions

For changes to the detection engine, platform adapters, or control plane:

1. Open an issue describing the change before writing code
2. Follow existing code style (Python 3.12+, type hints, `ruff` formatting)
3. Include tests for new functionality
4. Ensure `make test` passes before submitting

## Reporting Vulnerabilities

If you discover a security vulnerability in Agent Vardøger itself, please report it privately via GitHub Security Advisories rather than opening a public issue.

## Code of Conduct

Be respectful, constructive, and focused on improving AI agent security for everyone.
