"""
pipeline.py
-----------
End-to-end ADAPT-X pipeline:

    ingestion -> features -> clustering/profiling -> risk scoring
                                   -> Markov next-stage prediction

Exposes `run_pipeline()` for programmatic/dashboard use and a CLI via
`python -m adaptx.pipeline`.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import pandas as pd

from .features import build_attacker_features
from .ingestion import load
from .killchain import MarkovStagePredictor
from .profiling import cluster_attackers
from .risk import score_attackers


def run_pipeline(source: str = "synthetic", n_sessions: int = 150, seed: int | None = 42,
                  n_clusters: int = 3) -> pd.DataFrame:
    # 1. Ingest
    kwargs = {"n_sessions": n_sessions, "seed": seed} if source == "synthetic" else {}
    events_df = load(source, **kwargs)
    if events_df.empty:
        raise ValueError("No events parsed from source; check log format/path.")

    # 2. Feature engineering (per attacker IP)
    feat_df = build_attacker_features(events_df)

    # 3. Behavioral clustering / archetype labeling
    profiled_df = cluster_attackers(feat_df, n_clusters=n_clusters)

    # 4. Risk scoring
    scored_df = score_attackers(profiled_df)

    # 5. Kill-chain next-stage prediction (Markov chain trained across ALL attackers)
    predictor = MarkovStagePredictor()
    predictor.fit(scored_df["stage_sequence"].tolist())
    scored_df["current_stage"] = scored_df["furthest_stage"]
    scored_df["predicted_next_stage"] = scored_df["current_stage"].apply(
        lambda s: predictor.predict_next(s, top_k=1)[0][0] if predictor.predict_next(s) else s
    )
    scored_df["predicted_next_stage_prob"] = scored_df["current_stage"].apply(
        lambda s: round(predictor.predict_next(s, top_k=1)[0][1], 3) if predictor.predict_next(s) else 0.0
    )

    result = scored_df.drop(columns=["stage_sequence"]).sort_values("risk_score", ascending=False)
    return result.reset_index(drop=True)


def save_report(result: pd.DataFrame, out_dir: str = "outputs") -> dict:
    out_path = Path(out_dir)
    out_path.mkdir(parents=True, exist_ok=True)

    csv_path = out_path / "adaptx_report.csv"
    json_path = out_path / "adaptx_report.json"

    result.to_csv(csv_path, index=False)
    result.to_json(json_path, orient="records", indent=2)

    return {"csv": str(csv_path), "json": str(json_path)}


def main():
    parser = argparse.ArgumentParser(description="ADAPT-X — Autonomous Attacker Digital Profiling & Threat Prediction Engine")
    parser.add_argument("--source", default="synthetic",
                         help="'synthetic' or path to a Cowrie .jsonl honeypot log file")
    parser.add_argument("--n-sessions", type=int, default=150, help="Number of synthetic sessions (synthetic mode only)")
    parser.add_argument("--clusters", type=int, default=3, help="Number of behavioral clusters")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--out", default="outputs", help="Output directory for reports")
    parser.add_argument("--top", type=int, default=10, help="How many top-risk attackers to print")
    args = parser.parse_args()

    result = run_pipeline(source=args.source, n_sessions=args.n_sessions, seed=args.seed, n_clusters=args.clusters)
    paths = save_report(result, args.out)

    display_cols = ["src_ip", "archetype", "risk_score", "risk_level",
                     "current_stage", "predicted_next_stage", "n_sessions", "n_events"]

    print("\n=== ADAPT-X Threat Report — Top Risk Attackers ===\n")
    print(result[display_cols].head(args.top).to_string(index=False))
    print(f"\nFull report written to:\n  {paths['csv']}\n  {paths['json']}")
    print(f"\nTotal attackers profiled: {len(result)}")
    print(result['archetype'].value_counts().to_string())


if __name__ == "__main__":
    main()
