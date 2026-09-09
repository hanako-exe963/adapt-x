"""
ingestion.py
------------
Loads attacker session data into a common pandas DataFrame schema:

    session_id, src_ip, ts, command, stage, success

Two sources are supported:
  1. Synthetic data from data_generator.py (for demo/testing)
  2. Real Cowrie honeypot JSON logs (newline-delimited JSON), commonly
     produced by the open-source Cowrie SSH/Telnet honeypot.

Only log *parsing* is implemented here -- this module never issues
network requests or executes commands; it strictly reads text/JSON
already collected by a honeypot or SIEM export.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable

import pandas as pd

from .data_generator import generate_dataset, sessions_to_records
from .killchain import tag_stage


def load_synthetic(n_sessions: int = 150, seed: int | None = 42) -> pd.DataFrame:
    sessions = generate_dataset(n_sessions=n_sessions, seed=seed)
    records = sessions_to_records(sessions)
    df = pd.DataFrame(records)
    df["ts"] = pd.to_datetime(df["ts"])
    return df


def load_cowrie_jsonl(path: str | Path) -> pd.DataFrame:
    """
    Parse a Cowrie-style newline-delimited JSON log file.

    Expected (simplified) Cowrie event shape, one JSON object per line:
        {"eventid": "cowrie.command.input", "session": "abc123",
         "src_ip": "203.0.113.7", "timestamp": "2026-01-01T00:00:03.123Z",
         "input": "whoami"}
        {"eventid": "cowrie.login.success", "session": "abc123", ...}

    Only command-input events are used to build the behavioral sequence;
    login/session events are used to enrich src_ip/session metadata.
    """
    path = Path(path)
    rows = []
    session_ip = {}

    with path.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
            except json.JSONDecodeError:
                continue

            sess_id = ev.get("session", "unknown")
            if ev.get("src_ip"):
                session_ip[sess_id] = ev["src_ip"]

            if ev.get("eventid") == "cowrie.command.input":
                command = ev.get("input", "").strip()
                if not command:
                    continue
                rows.append({
                    "session_id": sess_id,
                    "src_ip": session_ip.get(sess_id, ev.get("src_ip", "unknown")),
                    "ts": ev.get("timestamp"),
                    "command": command,
                    "success": True,  # cowrie logs the command as executed in the shell jail
                })

    df = pd.DataFrame(rows)
    if df.empty:
        return df
    df["ts"] = pd.to_datetime(df["ts"], errors="coerce")
    df["stage"] = df["command"].apply(tag_stage)
    return df


def load(source: str = "synthetic", **kwargs) -> pd.DataFrame:
    """Unified entry point. source = 'synthetic' or a path to a cowrie .jsonl file."""
    if source == "synthetic":
        return load_synthetic(**kwargs)
    return load_cowrie_jsonl(source)
