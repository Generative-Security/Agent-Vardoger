"""AWS Lambda entry point wrapping the FastAPI app via Mangum."""
from __future__ import annotations

from mangum import Mangum

from control_plane.main import app

handler = Mangum(app)
