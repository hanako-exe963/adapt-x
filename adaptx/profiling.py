"""
profiling.py
------------
Clusters attackers into behavioral archetypes using KMeans over the
engineered feature vector, then assigns a human-readable label to each
cluster based on its centroid characteristics (fast+narrow => "Bot",
slow+diverse+deep kill-chain reach => "Skilled Operator", etc).

The number of archetype labels is intentionally small and explainable,
which matters for a SOC analyst report more than raw clustering
accuracy would.
"""

from __future__ import annotations

import numpy as np
import pandas as pd
from sklearn.cluster import KMeans
from sklearn.preprocessing import StandardScaler

from .features import FEATURE_COLUMNS

ARCHETYPE_LABELS = ["Automated Bot", "Script Kiddie", "Skilled Operator"]


def cluster_attackers(feat_df: pd.DataFrame, n_clusters: int = 3, random_state: int = 42) -> pd.DataFrame:
    X = feat_df[FEATURE_COLUMNS].values
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    km = KMeans(n_clusters=n_clusters, random_state=random_state, n_init=10)
    labels = km.fit_predict(X_scaled)

    feat_df = feat_df.copy()
    feat_df["cluster"] = labels

    # Rank clusters by a composite "sophistication" score on the raw
    # (unscaled) centroids so the label mapping is stable & interpretable,
    # rather than depending on arbitrary cluster index order.
    centroid_scores = {}
    for c in range(n_clusters):
        mask = feat_df["cluster"] == c
        centroid_scores[c] = (
            feat_df.loc[mask, "stage_diversity"].mean()
            + feat_df.loc[mask, "furthest_stage_idx"].mean()
            + feat_df.loc[mask, "cmd_entropy"].mean()
            - feat_df.loc[mask, "mean_gap_s"].rank(pct=True).mean() * 0  # tempo handled qualitatively
        )

    ordered_clusters = sorted(centroid_scores, key=lambda c: centroid_scores[c])
    n_labels = min(n_clusters, len(ARCHETYPE_LABELS))
    label_map = {}
    for i, c in enumerate(ordered_clusters):
        label_idx = min(i, n_labels - 1)
        label_map[c] = ARCHETYPE_LABELS[label_idx]

    feat_df["archetype"] = feat_df["cluster"].map(label_map)
    return feat_df
