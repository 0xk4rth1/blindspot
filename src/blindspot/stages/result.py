"""Stage results shared by the orchestrator."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class StageResult:
    name: str
    inserted: int = 0
    skipped: int = 0
    note: str = ""
