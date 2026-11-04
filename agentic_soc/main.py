"""End-to-end pipeline: generate logs -> train -> detect -> agent responds -> report."""
import json
import os
import pandas as pd
from sklearn.metrics import classification_report, confusion_matrix

from data_gen import generate, UNKNOWN_ATTACKS
from detector import HybridDetector
from threat_intel import ThreatIntel
from agent import ResponseAgent

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "output")
os.makedirs(OUT, exist_ok=True)


def main():
    df = generate()
    # Train only on benign + KNOWN attacks; c2_beacon is held out as a zero-day
    train_pool = df[~df["label"].isin(UNKNOWN_ATTACKS)]
    split = int(len(train_pool) * 0.7)
    train = train_pool.sample(frac=1, random_state=1).iloc[:split]
    test = pd.concat([train_pool.drop(train.index), df[df["label"].isin(UNKNOWN_ATTACKS)]])
    test = test.sort_values("timestamp").reset_index(drop=True)

    det = HybridDetector().fit(train)
    res = det.predict(test)

    y_true = (test["label"] != "normal").map({True: "threat", False: "normal"})
    print("=== Binary detection (threat vs normal) ===")
    print(classification_report(y_true, res["verdict"], digits=3))
    print(confusion_matrix(y_true, res["verdict"], labels=["normal", "threat"]))

    print("\n=== Recall per attack family ===")
    fam = res.assign(label=test["label"]).groupby("label")["verdict"].apply(lambda s: (s == "threat").mean())
    print(fam.round(3).to_string())
    zd = fam.get("c2_beacon", float("nan"))
    print(f"\nZero-day (c2_beacon, never seen in training) detection rate: {zd:.1%}")

    agent = ResponseAgent(intel=ThreatIntel(), allowlist={"10.0.0.2"})
    threats = res[res["verdict"] == "threat"]
    for _, ev in threats.iterrows():
        agent.act(ev)

    agent.save_audit(os.path.join(OUT, "audit_log.json"))
    res.to_csv(os.path.join(OUT, "detections.csv"), index=False)
    summary = {
        "events_scanned": int(len(res)),
        "threats_flagged": int(len(threats)),
        "ips_blocked": len(agent.blocked_ips),
        "hosts_isolated": len(agent.isolated_hosts),
        "zero_day_detection_rate": round(float(zd), 3),
    }
    with open(os.path.join(OUT, "summary.json"), "w") as f:
        json.dump(summary, f, indent=2)
    print("\n=== Agent summary ===")
    print(json.dumps(summary, indent=2))
    print("\nSample agent decisions:")
    for r in agent.audit[:3]:
        print(" -", r["explanation"])


if __name__ == "__main__":
    main()
