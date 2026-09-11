"""Tier 3 must read the env var names the CloudFormation template actually sets.

Tier 3's kill gate is defense-in-depth: mode must be enforce AND the global kill
switch AND the tier switch must all be on. A name mismatch between template and
handler does not fail loudly — it silently pins one input to False, so the
feature is simply unreachable and the outcome ledger blames "global_kill_disabled"
on an operator who did enable it.
"""
import importlib
from pathlib import Path

import pytest

TEMPLATE = "infra/self-hosted.yaml"


def _reload(monkeypatch, **env):
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    import vardoger.tier3.handler as h
    return importlib.reload(h)


@pytest.fixture(autouse=True)
def _restore():
    yield
    import vardoger.tier3.handler as h
    importlib.reload(h)


class TestGlobalKillSwitch:
    def test_reads_the_prefixed_name_the_template_sets(self, monkeypatch):
        h = _reload(monkeypatch, VARDOGER_GLOBAL_KILL_ENABLED="true")
        assert h.GLOBAL_KILL_ENABLED is True

    def test_unprefixed_name_still_honored(self, monkeypatch):
        """Backwards compatible with any existing manual override."""
        monkeypatch.delenv("VARDOGER_GLOBAL_KILL_ENABLED", raising=False)
        h = _reload(monkeypatch, GLOBAL_KILL_ENABLED="true")
        assert h.GLOBAL_KILL_ENABLED is True

    def test_defaults_off(self, monkeypatch):
        monkeypatch.delenv("VARDOGER_GLOBAL_KILL_ENABLED", raising=False)
        monkeypatch.delenv("GLOBAL_KILL_ENABLED", raising=False)
        h = _reload(monkeypatch)
        assert h.GLOBAL_KILL_ENABLED is False


def test_every_env_name_tier3_reads_is_set_by_the_template_or_defaulted():
    """Catch the class of bug directly: a name the handler reads that the
    template spells differently. Only names the template is expected to supply
    are checked — tuning knobs intentionally live on their code defaults.
    """
    template = Path(TEMPLATE).read_text(encoding="utf-8")
    # Names the stack is responsible for wiring, not operator tuning knobs.
    must_be_wired = {
        "VARDOGER_PROMPT_HISTORY_TABLE",
        "VARDOGER_SESSION_RISK_TABLE",
        "VARDOGER_DETECTION_EVENTS_TABLE",
        "VARDOGER_TENANTS_TABLE",
        "VARDOGER_OUTCOME_TABLE",
        "VARDOGER_ENFORCEMENT_FUNCTION",
        "VARDOGER_GLOBAL_KILL_ENABLED",
        "TIER3_ENABLED",
        "TIER3_KILL_ENABLED",
    }
    missing = [name for name in sorted(must_be_wired) if f"{name}:" not in template]
    assert not missing, f"handler reads env names the template never sets: {missing}"
