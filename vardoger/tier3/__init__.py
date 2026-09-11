"""Tier 3 — Scheduled cross-session pattern detection.

Scans recent prompt history for repeated/near-duplicate/category-burst
attack waves across sessions. Detection methods:
- Exact hash matching
- SimHash near-duplicate detection
- Normalized prompt pattern bursts
- Category bursts
- Session risk bursts
- Optional semantic embedding clusters

Kill mode is disabled by default; findings are alert-only until the
operator explicitly enables enforcement.
"""
