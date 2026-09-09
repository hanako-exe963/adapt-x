"""
risk.py
-------
Combines behavioral profile + kill-chain progression + activity volume
into a single composite risk score in [0, 100] per attacker, plus a
categorical risk level for quick SOC triage.

The formula is a transparent weighted sum (not a black box) so an
analyst can see exactly why an IP was scored the way it was --
important for a defensible/auditable security tool.
"""

from __future__ import annotations

import numpy as np
import pandas as pd

from .killchain import STAGES

ARCHETYPE_WEIGHT = {
    "Automated Bot": 0.3,
    "Script Kiddie": 0.6,
    "Skilled Operator": 1.0,
}

WEIGHTS = {
    "kill_chain_progress": 0.40,   # how far down the kill chain they got
    "archetype_severity": 0.25,    # behavioral sophistication
    "stage_diversity": 0.15,       # breadth of tactics used
    "persistence": 0.10,           # repeated sessions (returning attacker)
    "success_rate": 0.10,          # how often their commands "worked"
}


def _normalize(series: pd.Series) -> pd.Series:
    if series.max() == series.min():
        return pd.Series(np.zeros(len(series)), index=series.index)
    return (series - series.min()) / (series.max() - series.min())


def score_attackers(profiled_df: pd.DataFrame) -> pd.DataFrame:
    df = profiled_df.copy()

    kill_chain_progress = df["furthest_stage_idx"] / (len(STAGES) - 1)
    archetype_severity = df["archetype"].map(ARCHETYPE_WEIGHT).fillna(0.5)
    stage_diversity_norm = _normalize(df["stage_diversity"])
    persistence_norm = _normalize(df["n_sessions"])
    success_rate = df["success_rate"].fillna(0.0)

    composite = (
        WEIGHTS["kill_chain_progress"] * kill_chain_progress
        + WEIGHTS["archetype_severity"] * archetype_severity
        + WEIGHTS["stage_diversity"] * stage_diversity_norm
        + WEIGHTS["persistence"] * persistence_norm
        + WEIGHTS["success_rate"] * success_rate
    )

    df["risk_score"] = (composite * 100).round(1)

    def level(score: float) -> str:
        if score >= 75:
            return "Critical"
        if score >= 50:
            return "High"
        if score >= 25:
            return "Medium"
        return "Low"

    df["risk_level"] = df["risk_score"].apply(level)
    return df
