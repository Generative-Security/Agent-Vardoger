"""AWS Lambda entry point wrapping the FastAPI app via Mangum."""
from __future__ import annotations

from mangum import Mangum

from control_plane.main import app
from vardoger.logging_setup import configure_logging

# Applies VARDOGER_LOG_LEVEL. Without it the runtime's own root level applies and
# every INFO line is dropped, so this log group holds only START/END/REPORT --
# which is exactly how a failing dashboard call became undiagnosable. This
# module was missed when the other five handlers were wired up.
configure_logging()

handler = Mangum(app)
