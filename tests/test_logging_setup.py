"""A security monitor that logs nothing cannot be operated.

`config.LOG_LEVEL` existed, was documented nowhere, and was never applied:
nothing in the codebase called `setLevel` or `basicConfig`, so every logger
inherited the Lambda runtime's root level, which drops INFO. The observable
result was a dispatcher log group holding only START/END/REPORT while detection
events were being written to DynamoDB — a component working correctly and
reporting nothing.

That silence actively misled this project twice. An empty log group was read as
"the interceptor was never invoked", which was true once and false the next
time, and there was no way to tell the cases apart from the outside.

Two things are guarded here, because fixing either alone leaves the gap open:

1. The configured level is actually applied to the ROOT logger — every module
   uses `getLogger(__name__)` and inherits from root, so setting a named logger
   would leave the rest silent.
2. Every Lambda entry module calls it. A handler that forgets is invisible
   again, and only in production.
"""
from __future__ import annotations

import ast
import logging
from pathlib import Path

import pytest

from vardoger import config, logging_setup

ROOT = Path(__file__).resolve().parents[1]

# Every module AWS invokes directly. Each needs the call at import time.
ENTRY_MODULES = [
    "adapters/agentcore/dispatcher.py",
    "adapters/agentcore/alerting.py",
    "adapters/agentcore/enforcement_handler.py",
    "vardoger/tier2/handler.py",
    "vardoger/tier3/handler.py",
    # Missed on the first pass, and the omission cost a diagnosis: the control
    # plane's log group was silent while a dashboard call was failing.
    "control_plane/lambda_handler.py",
]


@pytest.fixture(autouse=True)
def _restore_root_level():
    original = logging.getLogger().level
    yield
    logging.getLogger().setLevel(original)


class TestTheLevelIsActuallyApplied:
    def test_the_configured_level_reaches_the_root_logger(self, monkeypatch) -> None:
        monkeypatch.setattr(config, "LOG_LEVEL", "DEBUG")
        logging_setup.configure_logging()
        assert logging.getLogger().level == logging.DEBUG

    def test_an_info_line_survives_the_default_configuration(self, monkeypatch, caplog) -> None:
        """The exact failure: INFO dropped, so a healthy run logged nothing."""
        monkeypatch.setattr(config, "LOG_LEVEL", "INFO")
        logging_setup.configure_logging()
        with caplog.at_level(logging.INFO):
            logging.getLogger("adapters.agentcore.dispatcher").info("evaluated")
        assert "evaluated" in caplog.text

    def test_root_is_configured_not_one_named_logger(self, monkeypatch) -> None:
        """Modules use getLogger(__name__); only root covers all of them."""
        monkeypatch.setattr(config, "LOG_LEVEL", "WARNING")
        logging_setup.configure_logging()
        child = logging.getLogger("vardoger.some.module.that.does.not.exist")
        assert child.getEffectiveLevel() == logging.WARNING


class TestBadConfigurationDoesNotSilenceEverything:
    @pytest.mark.parametrize("bad", ["", "  ", "verbose", "TRACE", "9"])
    def test_an_invalid_level_falls_back_to_info(self, monkeypatch, bad) -> None:
        """A typo must not be the reason a monitor goes dark."""
        monkeypatch.setattr(config, "LOG_LEVEL", bad)
        assert logging_setup.configure_logging() == "INFO"
        assert logging.getLogger().level == logging.INFO

    def test_lowercase_is_accepted(self, monkeypatch) -> None:
        monkeypatch.setattr(config, "LOG_LEVEL", "debug")
        assert logging_setup.configure_logging() == "DEBUG"

    def test_it_never_raises(self, monkeypatch) -> None:
        """Logging setup failing must not take the handler down with it."""
        monkeypatch.delattr(config, "LOG_LEVEL", raising=False)
        assert logging_setup.configure_logging() == "INFO"


class TestEveryEntryModuleConfiguresLogging:
    """One that forgets is silent in production and nowhere else."""

    @pytest.mark.parametrize("rel", ENTRY_MODULES)
    def test_the_module_calls_configure_logging_at_import_time(self, rel: str) -> None:
        tree = ast.parse((ROOT / rel).read_text(encoding="utf-8"))
        called = any(
            isinstance(node, ast.Expr)
            and isinstance(node.value, ast.Call)
            and getattr(node.value.func, "id", "") == "configure_logging"
            for node in tree.body  # module level only: import time, not per call
        )
        assert called, (
            f"{rel} never calls configure_logging() at module level, so its INFO "
            "lines are dropped by the runtime's root level and the log group "
            "stays empty while the handler runs normally."
        )


class TestTheDispatcherReportsNormalTraffic:
    """Before this, every log line sat on an error or block branch.

    So the ONLY way a dispatcher spoke was by failing. A correctly working one
    was indistinguishable from an absent one, which is how an empty log group
    got read as a wiring failure while detection was in fact running.
    """

    SOURCE = (ROOT / "adapters/agentcore/dispatcher.py").read_text(encoding="utf-8")

    def test_an_evaluated_prompt_is_logged(self) -> None:
        assert "Evaluated prompt:" in self.SOURCE, (
            "the dispatcher logs nothing on the normal path, so a working "
            "interceptor produces an empty log group"
        )

    def test_the_log_line_records_whether_the_session_id_was_asserted(self) -> None:
        """The field that has been unanswerable from outside the Lambda.

        Synthesised ids differ per prompt, so session risk never accumulates.
        Whether that is happening is invisible unless the line says so.
        """
        assert "authentic_session" in self.SOURCE

    def test_no_prompt_text_is_logged(self) -> None:
        """CloudWatch is not the place for content — the prompt may be the attack.

        Evidence storage is encrypted with a CMK precisely so that content lives
        somewhere with different access controls from the log group.
        """
        marker = self.SOURCE.index("Evaluated prompt:")
        statement = self.SOURCE[marker:marker + 900]
        for leak in ("parsed.prompt", "inspectable_text", "request_body"):
            assert leak not in statement, f"the evaluation log line includes {leak}"
