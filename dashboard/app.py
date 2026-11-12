"""
dashboard/app.py
-----------------
Lightweight Flask dashboard for ADAPT-X. Runs the full pipeline (or
loads a cached report) and displays attacker profiles, risk scores,
and predicted next kill-chain stage in a sortable table + summary
charts.

Run:
    python dashboard/app.py
Then open http://127.0.0.1:5000
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from flask import Flask, render_template, request, jsonify
from adaptx.pipeline import run_pipeline

app = Flask(__name__)

_CACHE = {"df": None}


def get_data(refresh: bool = False):
    if _CACHE["df"] is None or refresh:
        _CACHE["df"] = run_pipeline(source="synthetic", n_sessions=200, seed=None)
    return _CACHE["df"]


@app.route("/")
def index():
    df = get_data()
    display_cols = ["src_ip", "archetype", "risk_score", "risk_level",
                     "current_stage", "predicted_next_stage", "predicted_next_stage_prob",
                     "n_sessions", "n_events", "cmd_entropy", "success_rate"]
    records = df[display_cols].to_dict(orient="records")

    archetype_counts = df["archetype"].value_counts().to_dict()
    risk_counts = df["risk_level"].value_counts().to_dict()
    stage_counts = df["current_stage"].value_counts().to_dict()

    return render_template(
        "index.html",
        records=records,
        archetype_counts=archetype_counts,
        risk_counts=risk_counts,
        stage_counts=stage_counts,
        total=len(df),
    )


@app.route("/refresh")
def refresh():
    get_data(refresh=True)
    return jsonify({"status": "ok", "count": len(_CACHE["df"])})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
