"""
anomaly_detector.py
---------------------
Turns raw login events into per-IP numeric features, then uses
Isolation Forest to flag IPs that behave differently from the
majority - WITHOUT any hardcoded threshold like our rule-based
detector uses (BRUTE_FORCE_THRESHOLD = 5).

Features engineered per IP:
  - total_attempts: how many login attempts came from this IP
  - unique_usernames: how many different usernames were tried
    (a real user tries their own username; a bot tries many)
  - time_span_seconds: how long the activity lasted
  - avg_seconds_between_attempts: the pacing of attempts - humans
    pause to think/retype; scripts fire rapidly and consistently
"""

import pandas as pd
from sklearn.ensemble import IsolationForest


def engineer_features(events: list) -> pd.DataFrame:
    """
    Converts a flat list of {ip, user, timestamp} events into
    one row per IP with engineered numeric features. This is the
    step that turns "raw log data" into "something a model can
    actually learn from" - ML models need numbers, not timestamps
    and usernames directly.
    """
    df = pd.DataFrame(events)
    df["timestamp"] = pd.to_datetime(df["timestamp"])

    rows = []
    for ip, group in df.groupby("ip"):
        group = group.sort_values("timestamp")
        timestamps = group["timestamp"].tolist()

        total_attempts = len(group)
        unique_usernames = group["user"].nunique()

        if len(timestamps) > 1:
            time_span = (timestamps[-1] - timestamps[0]).total_seconds()
            gaps = [
                (timestamps[i + 1] - timestamps[i]).total_seconds()
                for i in range(len(timestamps) - 1)
            ]
            avg_gap = sum(gaps) / len(gaps)
        else:
            time_span = 0
            avg_gap = 0

        rows.append({
            "ip": ip,
            "total_attempts": total_attempts,
            "unique_usernames": unique_usernames,
            "time_span_seconds": time_span,
            "avg_seconds_between_attempts": avg_gap,
        })

    return pd.DataFrame(rows)


def detect_anomalies(features_df: pd.DataFrame, contamination: float = 0.1) -> pd.DataFrame:
    """
    Runs Isolation Forest on the engineered features.

    contamination: the expected PROPORTION of anomalies in the data
    (e.g. 0.1 = "I expect roughly 10% of IPs to be anomalous").
    This is the one parameter you have to set based on domain
    knowledge - it's not learned from the data itself. In a real
    deployment you'd tune this based on your environment's typical
    attack ratio.
    """
    feature_columns = ["total_attempts", "unique_usernames", "time_span_seconds", "avg_seconds_between_attempts"]
    X = features_df[feature_columns]

    model = IsolationForest(contamination=contamination, random_state=42)
    # fit_predict returns -1 for anomalies, 1 for normal points
    predictions = model.fit_predict(X)
    # decision_function gives a continuous anomaly score - more negative = more anomalous
    scores = model.decision_function(X)

    result = features_df.copy()
    result["is_anomaly"] = predictions == -1
    result["anomaly_score"] = scores

    return result.sort_values("anomaly_score")


# Quick manual test
if __name__ == "__main__":
    from generate_sample_data import generate_dataset

    events = generate_dataset()
    features = engineer_features(events)
    print(f"Engineered features for {len(features)} unique IPs\n")

    results = detect_anomalies(features, contamination=0.1)

    print("=== Isolation Forest Results (sorted by anomaly score, most anomalous first) ===\n")
    print(results.to_string(index=False))

    flagged = results[results["is_anomaly"]]
    print(f"\n{len(flagged)} IP(s) flagged as anomalous:")
    for _, row in flagged.iterrows():
        print(f"  {row['ip']}: {row['total_attempts']} attempts, {row['unique_usernames']} usernames, score={row['anomaly_score']:.3f}")