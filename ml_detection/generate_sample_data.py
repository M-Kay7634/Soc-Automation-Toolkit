"""
generate_sample_data.py
-------------------------
Generates a larger, synthetic SSH login dataset for ML testing.

Why synthetic data? Isolation Forest needs a reasonable number of
data points to learn what "normal" looks like. Our earlier sample
auth.log (used for the rule-based detector) only has a handful of
IPs - not enough for a model to learn meaningful patterns from.

This generates ~30 simulated IPs: most behaving like real humans
(occasional typos, human-paced retries), a few behaving like
automated attack tools (rapid, many attempts, many usernames).
We know which is which here (for validating the model works), but
the model itself is NOT told this - it's unsupervised, exactly like
a real deployment where you don't have pre-labeled attack data.
"""

import random
from datetime import datetime, timedelta

random.seed(42)  # reproducible results for demo/report purposes


def generate_normal_ip_behavior(ip: str, start_time: datetime) -> list:
    """
    Simulates a real human occasionally mistyping their password.
    1-3 attempts, spaced 10-60 seconds apart (human reaction time),
    same username each time (people don't guess random usernames).
    """
    events = []
    num_attempts = random.randint(1, 3)
    current_time = start_time
    username = random.choice(["manish", "deploy", "admin", "backup_user"])

    for _ in range(num_attempts):
        events.append({"ip": ip, "user": username, "timestamp": current_time})
        current_time += timedelta(seconds=random.randint(10, 60))

    return events


def generate_attacker_ip_behavior(ip: str, start_time: datetime) -> list:
    """
    Simulates an automated brute-force tool: many attempts, many
    different usernames, very short/consistent gaps between
    attempts (a script doesn't pause to think like a human does).
    """
    events = []
    num_attempts = random.randint(15, 40)
    current_time = start_time
    usernames = ["root", "admin", "test", "oracle", "postgres", "guest", "ftp", "www"]

    for _ in range(num_attempts):
        username = random.choice(usernames)
        events.append({"ip": ip, "user": username, "timestamp": current_time})
        current_time += timedelta(seconds=random.uniform(0.5, 3))  # bot-fast

    return events


def generate_dataset() -> list:
    """
    Builds the full synthetic dataset: 27 normal IPs + 3 attacker
    IPs, all with randomized start times across a day.
    """
    all_events = []
    base_time = datetime(2026, 1, 15, 0, 0, 0)

    # 27 normal IPs
    for i in range(27):
        ip = f"10.0.{i // 254}.{i % 254 + 1}"
        start = base_time + timedelta(minutes=random.randint(0, 1440))
        all_events.extend(generate_normal_ip_behavior(ip, start))

    # 3 attacker IPs - realistic external attacker-looking addresses
    attacker_ips = ["45.155.205.233", "185.220.101.45", "198.51.100.99"]
    for ip in attacker_ips:
        start = base_time + timedelta(minutes=random.randint(0, 1440))
        all_events.extend(generate_attacker_ip_behavior(ip, start))

    return all_events


if __name__ == "__main__":
    events = generate_dataset()
    print(f"Generated {len(events)} total login events across 30 IPs (27 normal, 3 attacker)")

    from collections import Counter
    ip_counts = Counter(e["ip"] for e in events)
    print("\nTop 5 IPs by event count:")
    for ip, count in ip_counts.most_common(5):
        print(f"  {ip}: {count} attempts")