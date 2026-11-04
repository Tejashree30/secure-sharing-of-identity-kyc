"""Synthetic network-flow generator.

`make_event(label, rng)` produces ONE flow record (used by the real-time stream).
`generate()` produces a labelled dataset (used for training and offline evaluation).

The "c2_beacon" family is excluded from supervised training so the system's
ability to catch UNKNOWN threats can be measured honestly.
"""
import numpy as np
import pandas as pd

FEATURES = [
    "duration", "bytes_out", "bytes_in", "packets", "failed_logins",
    "conn_per_min", "unique_ports", "hour", "dst_port",
]
KNOWN_ATTACKS = ["port_scan", "brute_force", "ddos", "exfiltration"]
UNKNOWN_ATTACKS = ["c2_beacon"]
ATTACK_KINDS_ALL = KNOWN_ATTACKS + UNKNOWN_ATTACKS

INTERNAL_PREFIX = "10.0."
COMMON_PORTS = [80, 443, 53, 22, 25, 3306, 8080]


def rand_ip(rng, internal=True):
    if internal:
        return f"{INTERNAL_PREFIX}{rng.integers(0, 8)}.{rng.integers(2, 250)}"
    return f"{rng.integers(11, 223)}.{rng.integers(0, 255)}.{rng.integers(0, 255)}.{rng.integers(1, 255)}"


def _normal(rng):
    return dict(
        duration=rng.gamma(2, 3), bytes_out=rng.lognormal(7, 1), bytes_in=rng.lognormal(9, 1),
        packets=rng.poisson(30), failed_logins=rng.poisson(0.05),
        conn_per_min=rng.gamma(2, 3), unique_ports=rng.integers(1, 4),
        hour=int(np.clip(rng.normal(13, 3.5), 0, 23)),
        dst_port=rng.choice(COMMON_PORTS, p=[.2, .45, .15, .05, .03, .02, .1]))


def _port_scan(rng):
    return dict(
        duration=rng.uniform(0.1, 2), bytes_out=rng.lognormal(4.5, .4), bytes_in=rng.lognormal(3, .5),
        packets=rng.poisson(200), failed_logins=0, conn_per_min=rng.uniform(80, 400),
        unique_ports=rng.integers(40, 900), hour=rng.integers(0, 24), dst_port=rng.integers(1, 65535))


def _brute_force(rng):
    return dict(
        duration=rng.uniform(5, 60), bytes_out=rng.lognormal(6, .5), bytes_in=rng.lognormal(6, .5),
        packets=rng.poisson(120), failed_logins=rng.integers(15, 200), conn_per_min=rng.uniform(20, 90),
        unique_ports=1, hour=rng.integers(0, 24), dst_port=rng.choice([22, 3389, 21]))


def _ddos(rng):
    return dict(
        duration=rng.uniform(1, 30), bytes_out=rng.lognormal(10, .6), bytes_in=rng.lognormal(5, .5),
        packets=rng.poisson(5000), failed_logins=0, conn_per_min=rng.uniform(800, 5000),
        unique_ports=rng.integers(1, 3), hour=rng.integers(0, 24), dst_port=rng.choice([80, 443]))


def _exfiltration(rng):
    return dict(
        duration=rng.uniform(60, 600), bytes_out=rng.lognormal(16, .5), bytes_in=rng.lognormal(6, .5),
        packets=rng.poisson(3000), failed_logins=0, conn_per_min=rng.uniform(1, 5),
        unique_ports=rng.integers(1, 3), hour=rng.choice([0, 1, 2, 3, 4, 23]),
        dst_port=rng.choice([443, 21, 8443]))


def _c2_beacon(rng):
    # UNKNOWN family: low-and-slow periodic beaconing to an external host at odd hours
    return dict(
        duration=rng.uniform(0.2, 1.0), bytes_out=rng.lognormal(5.2, .1), bytes_in=rng.lognormal(5.5, .1),
        packets=rng.poisson(6), failed_logins=0, conn_per_min=rng.uniform(0.9, 1.1),
        unique_ports=1, hour=rng.choice([1, 2, 3, 4]), dst_port=rng.choice([4444, 8081, 6667]))


# label -> (feature generator, source is internal, destination is internal)
GENERATORS = {
    "normal": (_normal, True, False),
    "port_scan": (_port_scan, False, True),
    "brute_force": (_brute_force, False, True),
    "ddos": (_ddos, False, True),
    "exfiltration": (_exfiltration, True, False),
    "c2_beacon": (_c2_beacon, True, False),
}


def make_event(label, rng, src_ip=None, dst_ip=None):
    fn, src_internal, dst_internal = GENERATORS[label]
    r = fn(rng)
    r.update(label=label,
             src_ip=src_ip or rand_ip(rng, src_internal),
             dst_ip=dst_ip or rand_ip(rng, dst_internal))
    return r


def generate(n_normal=6000, n_attack=300, n_unknown=150, seed=42):
    rng = np.random.default_rng(seed)
    counts = {"normal": n_normal, "port_scan": n_attack, "brute_force": n_attack,
              "ddos": n_attack, "exfiltration": n_attack, "c2_beacon": n_unknown}
    rows = [make_event(label, rng) for label, n in counts.items() for _ in range(n)]
    df = pd.DataFrame(rows).sample(frac=1, random_state=seed).reset_index(drop=True)
    df["timestamp"] = pd.date_range("2026-10-29 00:00", periods=len(df), freq="3s")
    return df
