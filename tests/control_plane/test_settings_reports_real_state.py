"""The Settings panel must report the deployment, not its own defaults.

Every flag here read an environment variable that `ControlPlaneFunction` never
set, so the panel answered from code defaults: Tier 3 always enabled, ML never
configured, global kill always off, whatever the stack was really running. One
of them, `TIER3_ENABLED`, was missing the `VARDOGER_` prefix entirely, so it
could not be set even deliberately.

That is the exact failure this product exists to catch -- a component reporting
a state it is not in -- so it is worth a test that fails when the wiring breaks
rather than when someone notices the dashboard is wrong.

The name check matters as much as the value check: the frontend reads these keys
by name, and a rename that passes here while breaking the dashboard is the same
silent-disagreement bug one layer out.
"""
from __future__ import annotations

import os
import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
SETTINGS = REPO_ROOT / "control_plane" / "routers" / "settings.py"
TEMPLATE = REPO_ROOT / "infra" / "self-hosted.yaml"
CLIENT = REPO_ROOT / "frontend" / "src" / "api" / "client.ts"

# Each flag, and the environment variable it must read.
FLAGS = {
    "ml_endpoint_configured": "VARDOGER_ML_ENDPOINT",
    "tier3_enabled": "VARDOGER_TIER3_ENABLED",
    "global_kill_enabled": "VARDOGER_GLOBAL_KILL_ENABLED",
    "premium_signatures_configured": "VARDOGER_PREMIUM_SIGNATURE_BUCKET",
}


def _control_plane_env() -> str:
    """The ControlPlaneFunction environment block, as raw text."""
    text = TEMPLATE.read_text(encoding="utf-8")
    start = text.index("  ControlPlaneFunction:")
    # Up to the next top-level resource.
    rest = text[start + 10:]
    end = re.search(r"\n  [A-Za-z0-9]+:\n    Type:", rest)
    return rest[: end.start()] if end else rest


@pytest.mark.parametrize("flag,env_var", sorted(FLAGS.items()))
def test_every_flag_reads_a_variable_the_template_sets(flag: str, env_var: str) -> None:
    source = SETTINGS.read_text(encoding="utf-8")
    assert f'"{flag}"' in source, f"settings.py no longer reports {flag}"
    assert env_var in source, f"{flag} no longer reads {env_var}"
    assert f"{env_var}:" in _control_plane_env(), (
        f"{env_var} is read by the Settings panel but ControlPlaneFunction does "
        f"not set it, so {flag} reports a code default rather than the deployment"
    )


def test_no_flag_reads_an_unprefixed_variable() -> None:
    """`TIER3_ENABLED` without the prefix could not be set by any documented means."""
    source = SETTINGS.read_text(encoding="utf-8")
    bare = re.findall(r'os\.environ\.get\(\s*"(?!VARDOGER_)([A-Z][A-Z0-9_]{3,})"', source)
    assert not bare, (
        f"settings.py reads unprefixed environment variables {bare}; every "
        "deployment variable in this project is VARDOGER_-prefixed, so these "
        "can never be set and the flag silently reports its default"
    )


def test_the_frontend_reads_the_same_names() -> None:
    """A rename that only lands server-side shows the dashboard an undefined field."""
    client = CLIENT.read_text(encoding="utf-8")
    for flag in FLAGS:
        assert f"{flag}:" in client, (
            f"the control plane reports {flag} but frontend/src/api/client.ts "
            "does not declare it; the dashboard would render undefined"
        )


def test_tier3_default_matches_the_template_default() -> None:
    """Reporting a default of `true` while the stack ships Tier 3 off is a lie."""
    source = SETTINGS.read_text(encoding="utf-8")
    match = re.search(r'"tier3_enabled":\s*os\.environ\.get\(\s*"VARDOGER_TIER3_ENABLED"\s*,\s*"(\w+)"', source)
    assert match, "tier3_enabled is no longer read in a recognisable form"
    assert match.group(1).lower() == "false", (
        "Tier 3 ships off by default (Tier3Enabled defaults to 'false'), so a "
        "fallback of 'true' reports it enabled on any deploy that omits the var"
    )


def test_settings_endpoint_reflects_the_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    """End to end through the real function, not just the source text."""
    from control_plane.routers import settings as settings_module

    for env_var in FLAGS.values():
        monkeypatch.delenv(env_var, raising=False)
    monkeypatch.setenv("VARDOGER_TIER3_ENABLED", "true")
    monkeypatch.setenv("VARDOGER_ML_ENDPOINT", "some-endpoint")

    status = settings_module.status()
    body = status if isinstance(status, dict) else status.__dict__

    assert body["tier3_enabled"] is True
    assert body["ml_endpoint_configured"] is True
    assert body["global_kill_enabled"] is False
    assert body["premium_signatures_configured"] is False

    monkeypatch.setenv("VARDOGER_TIER3_ENABLED", "false")
    body = settings_module.status()
    body = body if isinstance(body, dict) else body.__dict__
    assert body["tier3_enabled"] is False, "the panel ignored the environment"


def test_os_is_imported_where_it_is_used() -> None:
    assert re.search(r"^import os$", SETTINGS.read_text(encoding="utf-8"), re.M)
    assert os.environ is not None  # sanity
