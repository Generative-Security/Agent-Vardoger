"""Control plane — FastAPI dashboard and management API.

Provides:
- Dashboard views (sessions, detections, timeline, categories)
- Prompt history search
- Tier policy management
- Troubleshooting views
- Outcome ledger / evaluation metrics (local data only in self-hosted mode)

All records are partitioned by scope_id (the isolation key; "local" in
self-hosted deployments) and segmented by source ("<aws_account_id>/<agent>").
Access is governed by role-based access control (viewer < operator < admin).
"""
