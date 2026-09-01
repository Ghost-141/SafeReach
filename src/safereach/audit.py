"""Append-only audit log.

This tool reaches production, so "what did the agent actually run" has to be answerable
without reconstructing a chat transcript. Every attempt is recorded — including the ones
that were refused, which are the interesting ones when tuning the allowlist.

The shim keeps its own log on each host. That one is authoritative, because it records
what was *received* rather than what this process believes it sent.
"""

from __future__ import annotations

import json
import os
import sys
import threading
import time
from pathlib import Path
from typing import Any

__all__ = ["AuditLog"]


class AuditLog:
    """Line-delimited JSON, one record per attempt.

    Writes are serialised with a lock and opened in append mode per record. That is
    slower than holding a handle, but it survives log rotation and concurrent fan-out
    without interleaving partial lines.
    """

    def __init__(self, path: Path | str) -> None:
        self.path = Path(path).expanduser()
        self._lock = threading.Lock()
        self._warned = False

    def _ensure_parent(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def write(self, **record: Any) -> None:
        record.setdefault("ts", time.time())
        record.setdefault("pid", os.getpid())
        line = json.dumps(record, separators=(",", ":"), default=str)
        try:
            with self._lock:
                self._ensure_parent()
                with self.path.open("a", encoding="utf-8") as fh:
                    fh.write(line + "\n")
        except OSError as exc:
            # Never let an unwritable log break a diagnostic session — but say so once,
            # on stderr, because stdout is the JSON-RPC channel.
            if not self._warned:
                print(
                    f"safereach: cannot write audit log {self.path}: {exc}",
                    file=sys.stderr,
                )
                self._warned = True

    def allowed(
        self,
        *,
        host: str,
        requested: str,
        executed: str,
        exit_code: int,
        duration_ms: int,
        bytes_out: int,
        truncated: bool,
    ) -> None:
        self.write(
            decision="allowed",
            host=host,
            requested=requested,
            executed=executed,
            exit_code=exit_code,
            duration_ms=duration_ms,
            bytes_out=bytes_out,
            truncated=truncated,
        )

    def rejected(self, *, host: str, requested: str, reason: str) -> None:
        self.write(decision="rejected", host=host, requested=requested, reason=reason)

    def error(self, *, host: str, requested: str, error: str) -> None:
        self.write(decision="error", host=host, requested=requested, error=error)
