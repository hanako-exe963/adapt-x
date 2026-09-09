"""
features.py
-----------
Turns raw per-event log records into a behavioral fingerprint per
attacker (grouped by src_ip, aggregating across all their sessions).

Features are chosen to separate automated/bot behavior from deliberate
human operator behavior, which is exactly the signal needed for
downstream clustering and risk scoring:

  - volume & tempo   : event count, sessions, mean/std inter-command gap
  - diversity         : unique command ratio (entropy-like signal)
  - success ratio     : fraction of commands that "succeeded"
  - kill-chain reach  : how far along the kill chain the attacker got
  - stage diversity   : how many distinct stages were touched
"""

from __future__ import annotations

import math
from collections import Counter

import numpy as np
import pandas as pd

from .killchain import STAGES


def _entropy(values: list[str]) -> float:
    if not values:
        return 0.0
    counts = Counter(values)
    total = len(values)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def _inter_event_gaps(ts_series: pd.Series) -> np.ndarray:
    ts_sorted = ts_series.sort_values()
    gaps = ts_sorted.diff().dt.total_seconds().dropna().values
    return gaps


def build_attacker_features(df: pd.DataFrame) -> pd.DataFrame:
    """
    df: DataFrame with columns [session_id, src_ip, ts, command, stage, success]
    returns: one row per src_ip with engineered features + stage reach info.
    """
    rows = []
    stage_order = {s: i for i, s in enumerate(STAGES)}

    for ip, g in df.groupby("src_ip"):
        g = g.sort_values("ts")
        n_events = len(g)
        n_sessions = g["session_id"].nunique()
        commands = g["command"].tolist()
        stages_seen = g["stage"].tolist()

        gaps = _inter_event_gaps(g["ts"])
        mean_gap = float(np.mean(gaps)) if len(gaps) else np.nan
        std_gap = float(np.std(gaps)) if len(gaps) else np.nan

        unique_cmd_ratio = len(set(commands)) / n_events if n_events else 0.0
        cmd_entropy = _entropy(commands)
        success_rate = float(g["success"].mean()) if "success" in g else np.nan

        stage_counts = Counter(stages_seen)
        stage_diversity = len(stage_counts)
        furthest_stage = max(stages_seen, key=lambda s: stage_order.get(s, -1)) if stages_seen else STAGES[0]
        furthest_stage_idx = stage_order.get(furthest_stage, 0)

        span_seconds = (g["ts"].max() - g["ts"].min()).total_seconds() if n_events > 1 else 0.0

        rows.append({
            "src_ip": ip,
            "n_events": n_events,
            "n_sessions": n_sessions,
            "mean_gap_s": mean_gap,
            "std_gap_s": std_gap,
            "unique_cmd_ratio": unique_cmd_ratio,
            "cmd_entropy": cmd_entropy,
            "success_rate": success_rate,
            "stage_diversity": stage_diversity,
            "furthest_stage": furthest_stage,
            "furthest_stage_idx": furthest_stage_idx,
            "span_seconds": span_seconds,
            "stage_sequence": stages_seen,  # kept for the Markov predictor, not a numeric feature
        })

    feat_df = pd.DataFrame(rows)
    numeric_cols = ["mean_gap_s", "std_gap_s"]
    feat_df[numeric_cols] = feat_df[numeric_cols].fillna(feat_df[numeric_cols].median())
    return feat_df


FEATURE_COLUMNS = [
    "n_events", "n_sessions", "mean_gap_s", "std_gap_s",
    "unique_cmd_ratio", "cmd_entropy", "success_rate",
    "stage_diversity", "furthest_stage_idx", "span_seconds",
]
