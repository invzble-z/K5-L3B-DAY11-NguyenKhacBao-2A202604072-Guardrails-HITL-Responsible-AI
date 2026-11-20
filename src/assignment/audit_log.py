"""
Assignment 11 — Audit Log starter (TODO).

Records every interaction for forensics. Never blocks by itself —
other layers catch attacks; this layer makes them reviewable.
"""
from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from pathlib import Path


def default_audit_log_path() -> str:
    """Always resolve to <repo>/outputs/… (safe when cwd is src/)."""
    repo_root = Path(__file__).resolve().parents[2]
    return str(repo_root / "outputs" / "audit_log.json")


class AuditLogPlugin:
    """Framework-agnostic audit logger (wire into ADK callbacks or your pipeline)."""

    def __init__(self):
        self.name = "audit_log"
        self.logs: list[dict] = []
        self._open: dict[str, dict] = {}

    def record_input(self, *, user_id: str, text: str, request_id: str | None = None) -> str:
        """Store input + start timestamp keyed by request_id/user_id."""
        req_id = request_id or f"{user_id}_{len(self.logs)}_{time.time()}"
        self._open[req_id] = {
            "user_id": user_id,
            "input": text,
            "start_time": time.time(),
        }
        return req_id

    def record_output(
        self,
        *,
        user_id: str,
        text: str,
        blocked: bool = False,
        layer: str | None = None,
        request_id: str | None = None,
    ) -> dict:
        """Store output, layer decision, latency; append to self.logs."""
        latency = 0.0
        input_text = ""
        if request_id and request_id in self._open:
            info = self._open.pop(request_id)
            latency = time.time() - info["start_time"]
            input_text = info.get("input", "")

        entry = {
            "timestamp": utc_now_iso(),
            "user_id": user_id,
            "request_id": request_id,
            "input": input_text,
            "output": text,
            "blocked": blocked,
            "layer": layer,
            "latency_seconds": round(latency, 4),
        }
        self.logs.append(entry)
        return entry

    def export_json(self, filepath: str | None = None) -> str:
        """Write logs to disk (JSON array) under repo-root ``outputs/`` by default."""
        target = Path(filepath or default_audit_log_path())
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(self.logs, indent=2, ensure_ascii=False), encoding="utf-8")
        return str(target)


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
