"""Train and evaluate the hybrid detector on CIC-IDS2017 (or any CSV with the same columns).

    python train_real.py --data path/to/CIC-IDS2017/MachineLearningCSV --max-rows 300000 [--xgb]

What it does
  1. loads every *.csv in the folder (or one file), strips the leading spaces in column names
  2. maps CIC flow columns onto the detector's feature set (see MAP below)
  3. maps labels: BENIGN->normal, DDoS/DoS*->ddos, PortScan->port_scan, *-Patator->brute_force,
     Bot->c2_beacon (held out of supervised training as the "unknown" family), everything else -> other_attack
  4. trains HybridDetector, prints metrics, saves models/detector_cic.joblib
  5. with --xgb also benchmarks an XGBoost classifier against the Random Forest

HONEST LIMITS: CIC-IDS2017 has no 'failed logins', 'unique ports' or 'hour' columns, so those features are
set to constants. The model trained here is therefore a benchmark of the method, not a drop-in replacement
for live capture (whose features come from soc/capture.py). Use it to report real-data accuracy.
"""
import argparse
import glob
import os
import sys

import numpy as np
import pandas as pd
from sklearn.metrics import classification_report
from sklearn.model_selection import train_test_split

from data_gen import FEATURES
from detector import HybridDetector

LABELS = {"BENIGN": "normal", "PortScan": "port_scan", "Bot": "c2_beacon", "FTP-Patator": "brute_force",
          "SSH-Patator": "brute_force"}


def map_label(x):
    x = str(x).strip()
    if x in LABELS:
        return LABELS[x]
    if x.startswith("DoS") or x == "DDoS":
        return "ddos"
    return "other_attack"


def load(path, max_rows):
    files = sorted(glob.glob(os.path.join(path, "*.csv"))) if os.path.isdir(path) else [path]
    if not files:
        sys.exit(f"No CSV files found in {path}")
    frames = []
    for f in files:
        d = pd.read_csv(f, low_memory=False, encoding="latin-1")
        d.columns = [c.strip() for c in d.columns]
        frames.append(d)
    df = pd.concat(frames, ignore_index=True)
    if len(df) > max_rows:
        df = df.sample(max_rows, random_state=1)
    return df


def to_features(df):
    need = ["Destination Port", "Flow Duration", "Total Fwd Packets", "Total Backward Packets",
            "Total Length of Fwd Packets", "Total Length of Bwd Packets", "Flow Packets/s", "Label"]
    missing = [c for c in need if c not in df.columns]
    if missing:
        sys.exit(f"CSV is missing expected CIC-IDS2017 columns: {missing}")
    out = pd.DataFrame({
        "duration": df["Flow Duration"] / 1e6,
        "bytes_out": df["Total Length of Fwd Packets"],
        "bytes_in": df["Total Length of Bwd Packets"],
        "packets": df["Total Fwd Packets"] + df["Total Backward Packets"],
        "failed_logins": 0,
        "conn_per_min": df["Flow Packets/s"],
        "unique_ports": 1,
        "hour": 12,
        "dst_port": df["Destination Port"],
    })[FEATURES].apply(pd.to_numeric, errors="coerce").replace([np.inf, -np.inf], np.nan)
    out["label"] = df["Label"].map(map_label)
    out = out.dropna()
    for c in ("duration", "bytes_out", "bytes_in", "packets", "conn_per_min"):
        out[c] = out[c].clip(lower=0)
    return out.reset_index(drop=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", required=True)
    ap.add_argument("--max-rows", type=int, default=300000)
    ap.add_argument("--xgb", action="store_true")
    ap.add_argument("--out", default="models/detector_cic.joblib")
    a = ap.parse_args()

    data = to_features(load(a.data, a.max_rows))
    print("Class counts:\n", data["label"].value_counts().to_string())
    known = data[data["label"] != "c2_beacon"]
    train, test_known = train_test_split(known, test_size=0.3, random_state=1, stratify=known["label"])
    test = pd.concat([test_known, data[data["label"] == "c2_beacon"]])

    det = HybridDetector().fit(train)
    res = det.predict(test)
    y_true = np.where(test["label"] == "normal", "normal", "threat")
    print("\n=== Hybrid detector: threat vs normal ===")
    print(classification_report(y_true, res["verdict"], digits=3, zero_division=0))
    fam = res.assign(label=test["label"].values).groupby("label")["verdict"].apply(lambda s: (s == "threat").mean())
    print("Detection rate per class:\n", fam.round(3).to_string())
    if "c2_beacon" in fam:
        print(f"\nHeld-out 'Bot' family (never in supervised training): {fam['c2_beacon']:.1%} detected")

    import joblib
    os.makedirs(os.path.dirname(a.out) or ".", exist_ok=True)
    joblib.dump(det, a.out)
    print("Saved", a.out)

    if a.xgb:
        try:
            from xgboost import XGBClassifier
        except ImportError:
            sys.exit("xgboost is not installed: pip install xgboost")
        from sklearn.preprocessing import LabelEncoder
        enc = LabelEncoder().fit(train["label"])
        x_tr, x_te = det.scaler.transform(__import__("detector")._prep(train)), det.scaler.transform(__import__("detector")._prep(test_known))
        m = XGBClassifier(n_estimators=200, max_depth=6, n_jobs=-1, eval_metric="mlogloss").fit(x_tr, enc.transform(train["label"]))
        pred = enc.inverse_transform(m.predict(x_te))
        rf = det.clf.predict(x_te)
        print("\n=== Known-attack classification: XGBoost vs Random Forest (macro F1) ===")
        from sklearn.metrics import f1_score
        print(f"XGBoost       {f1_score(test_known['label'], pred, average='macro'):.3f}")
        print(f"RandomForest  {f1_score(test_known['label'], rf, average='macro'):.3f}")


if __name__ == "__main__":
    main()
