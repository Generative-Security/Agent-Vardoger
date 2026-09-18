"""Paths that swallow an exception must raise a degraded signal.

The whole premise of this system is that it does not fail silently: every
component reports degradation rather than dying, so an operator can tell a
working detector from a broken one. Three places swallowed and logged instead.

- Evidence encryption: a KMS denial, an AES-GCM error or a missing
  `cryptography` import dropped the blocked prompt and returned None. The system
  looked completely healthy while recording nothing.
- SNS publish: alerting silently off, so an operator concludes nothing is
  happening.

Returning None rather than raising is correct in both -- bookkeeping must never
undo enforcement. Being invisible is the part that is not.
"""
from __future__ import annotations

import ast
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]

# (file, function, why this one must not be silent)
GUARDED = [
    ("adapters/agentcore/crypto.py", "encrypt_and_log",
     "evidence for a blocked prompt is dropped"),
    ("adapters/agentcore/alerting.py", "_publish_sns_alert",
     "operator alerting is off"),
]


def _function(path: str, name: str) -> ast.FunctionDef:
    tree = ast.parse((REPO_ROOT / path).read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return node
    raise AssertionError(f"{name} not found in {path}")


def _calls_report_degraded(node: ast.AST) -> bool:
    for child in ast.walk(node):
        if isinstance(child, ast.Call):
            func = child.func
            if isinstance(func, ast.Name) and func.id == "report_degraded":
                return True
            if isinstance(func, ast.Attribute) and func.attr == "report_degraded":
                return True
    return False


@pytest.mark.parametrize("path,name,consequence", GUARDED)
def test_swallowing_handlers_report_degraded(path: str, name: str, consequence: str) -> None:
    func = _function(path, name)
    handlers = [h for h in ast.walk(func) if isinstance(h, ast.ExceptHandler)]
    assert handlers, f"{name} no longer has an exception handler to guard"

    silent = [
        h for h in handlers
        if not _calls_report_degraded(h)
        and not any(isinstance(n, ast.Raise) for n in ast.walk(h))
    ]
    assert not silent, (
        f"{path}:{name} swallows an exception without report_degraded, so "
        f"{consequence} with nothing to alarm on"
    )


def test_alerting_declares_its_own_component() -> None:
    """A degraded signal needs a component name an operator can act on."""
    from vardoger import health
    assert hasattr(health, "ALERTING"), "no ALERTING component to report against"
    assert health.ALERTING and isinstance(health.ALERTING, str)
