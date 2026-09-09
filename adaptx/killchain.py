"""
killchain.py
------------
Maps observed commands to Cyber Kill Chain stages (with a loose MITRE
ATT&CK tactic reference) and implements a first-order Markov chain
used to predict the *next* stage an attacker is likely to move to.

This is a defensive analytics component: it classifies text that a
defender has already captured from a honeypot/IDS. It does not
generate or suggest attack commands.
"""

from __future__ import annotations

import re
from collections import defaultdict
from typing import Optional

# Ordered kill chain stages (simplified Lockheed Martin model, mapped
# loosely onto MITRE ATT&CK tactics for readability in reports).
STAGES = ["recon", "delivery", "exploitation", "installation", "c2", "actions_on_objective"]

MITRE_TACTIC = {
    "recon": "TA0043 Reconnaissance / TA0007 Discovery",
    "delivery": "TA0001 Initial Access",
    "exploitation": "TA0002 Execution",
    "installation": "TA0003 Persistence",
    "c2": "TA0011 Command and Control",
    "actions_on_objective": "TA0010 Exfiltration / TA0040 Impact",
}

# Simple, transparent rule-based classifier. In a production system this
# would be replaced/augmented by a trained text classifier, but rules
# keep the prototype auditable and dependency-light.
_PATTERNS = [
    (re.compile(r"\b(whoami|uname|id|ifconfig|netstat|ps aux|df -h|cpuinfo|ls -la|cat /etc/passwd)\b"), "recon"),
    (re.compile(r"\b(wget|curl|tftp|ftp)\b.*(http|ftp)"), "delivery"),
    (re.compile(r"\b(chmod \+x|\./|python[23]? .*exploit|exploit\.py|poc)\b"), "exploitation"),
    (re.compile(r"\b(crontab|useradd|systemctl enable|/etc/rc\.local|authorized_keys)\b"), "installation"),
    (re.compile(r"\b(nc -e|/bin/sh|beacon|ssh -R|reverse|meterpreter)\b"), "c2"),
    (re.compile(r"\b(tar -cz|scp .*@|rm -rf /var/log|history -c|exfil)\b"), "actions_on_objective"),
]


def tag_stage(command: str) -> str:
    """Classify a single observed command string into a kill-chain stage."""
    if not command:
        return "recon"
    cmd = command.lower()
    for pattern, stage in _PATTERNS:
        if pattern.search(cmd):
            return stage
    return "recon"  # safest default for unrecognized/benign-looking commands


class MarkovStagePredictor:
    """
    First-order Markov chain over kill-chain stages.

    fit() learns P(next_stage | current_stage) from historical stage
    sequences (one sequence per session). predict_next() then returns
    the most probable next stage(s) for a given current stage, which is
    used as the attacker's "predicted next move".
    """

    def __init__(self, stages: Optional[list[str]] = None):
        self.stages = stages or STAGES
        self.transition_counts: dict[str, dict[str, int]] = {s: defaultdict(int) for s in self.stages}
        self._fitted = False

    def fit(self, sequences: list[list[str]]) -> "MarkovStagePredictor":
        for seq in sequences:
            for a, b in zip(seq, seq[1:]):
                if a in self.transition_counts:
                    self.transition_counts[a][b] += 1
        self._fitted = True
        return self

    def transition_matrix(self) -> dict[str, dict[str, float]]:
        matrix = {}
        for stage, counts in self.transition_counts.items():
            total = sum(counts.values())
            if total == 0:
                matrix[stage] = {s: 0.0 for s in self.stages}
            else:
                matrix[stage] = {s: counts.get(s, 0) / total for s in self.stages}
        return matrix

    def predict_next(self, current_stage: str, top_k: int = 2) -> list[tuple[str, float]]:
        if not self._fitted:
            raise RuntimeError("MarkovStagePredictor.fit() must be called before predicting.")
        matrix = self.transition_matrix()
        row = matrix.get(current_stage, {s: 0.0 for s in self.stages})
        ranked = sorted(row.items(), key=lambda kv: kv[1], reverse=True)
        # Filter out zero-probability entries unless everything is zero
        nonzero = [r for r in ranked if r[1] > 0]
        return (nonzero or ranked)[:top_k]

    def furthest_stage_reached(self, seq: list[str]) -> str:
        """Returns the most advanced stage (by kill-chain order) seen in a sequence."""
        order = {s: i for i, s in enumerate(self.stages)}
        return max(seq, key=lambda s: order.get(s, -1)) if seq else self.stages[0]
