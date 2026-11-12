"""
ingestion.py
------------
Loads attacker session data into a common pandas DataFrame schema:

    session_id, src_ip, ts, command, stage, success

Two sources are supported:
  1. Synthetic data from data_generator.py (for demo/testing)
  2. Real Cowrie honeypot JSON logs (newline-delimited JSON), or remote URLs from internet.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable
import io
import requests

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
                    "success": True,
                })

    df = pd.DataFrame(rows)
    if df.empty:
        return df
    df["ts"] = pd.to_datetime(df["ts"], errors="coerce")
    df["stage"] = df["command"].apply(tag_stage)
    return df


def load_from_url(url: str) -> pd.DataFrame:
    """
    Download and parse remote dataset logs (JSONL or CSV) directly from the internet.
    """
    response = requests.get(url)
    response.raise_for_status()
    if url.endswith(".csv"):
        df = pd.read_csv(io.StringIO(response.text))
        df["ts"] = pd.to_datetime(df["ts"], errors="coerce")
        if "stage" not in df.columns and "command" in df.columns:
            df["stage"] = df["command"].apply(tag_stage)
        return df
    else:
        # Parse remote newline-delimited JSON (Cowrie format style)
        rows = []
        session_ip = {}
        for line in response.text.splitlines():
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
                    "success": True,
                })

        df = pd.DataFrame(rows)
        if df.empty:
            return df
        df["ts"] = pd.to_datetime(df["ts"], errors="coerce")
        df["stage"] = df["command"].apply(tag_stage)
        return df


def load(source: str = "synthetic", **kwargs) -> pd.DataFrame:
    """Unified entry point. source = 'synthetic', a web URL (http/https), or local file path."""
    if source == "synthetic":
        return load_synthetic(**kwargs)
    elif source.startswith("http://") or source.startswith("https://"):
        return load_from_url(source)
    return load_cowrie_jsonl(source)