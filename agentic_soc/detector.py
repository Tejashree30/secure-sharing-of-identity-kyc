"""Hybrid ML detector.

- IsolationForest (unsupervised) trained on benign traffic only -> catches UNKNOWN threats
- RandomForest (supervised) trained on labelled known attacks -> classifies threat type
Final verdict: supervised class if confident, else anomaly flag, else normal.
"""
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import StandardScaler

from data_gen import FEATURES


def _prep(df):
    X = df[FEATURES].copy()
    for c in ("bytes_out", "bytes_in", "packets", "conn_per_min"):
        X[c] = np.log1p(X[c])
    return X


class HybridDetector:
    def __init__(self, contamination=0.005, conf_threshold=0.6, seed=42):
        self.scaler = StandardScaler()
        self.iso = IsolationForest(n_estimators=200, contamination=contamination, random_state=seed)
        self.clf = RandomForestClassifier(n_estimators=200, random_state=seed, class_weight="balanced")
        self.conf_threshold = conf_threshold

    def fit(self, train_df):
        X = _prep(train_df)
        Xs = self.scaler.fit_transform(X)
        benign = Xs[(train_df["label"] == "normal").values]
        self.iso.fit(benign)
        self.clf.fit(Xs, train_df["label"])
        return self

    def predict(self, df):
        Xs = self.scaler.transform(_prep(df))
        proba = self.clf.predict_proba(Xs)
        classes = self.clf.classes_
        top = proba.argmax(axis=1)
        top_label = classes[top]
        top_conf = proba.max(axis=1)
        anomaly = self.iso.predict(Xs) == -1
        score = -self.iso.score_samples(Xs)

        verdict, kind = [], []
        for lab, conf, an in zip(top_label, top_conf, anomaly):
            if lab != "normal" and conf >= self.conf_threshold:
                verdict.append("threat"); kind.append(lab)
            elif an:
                verdict.append("threat"); kind.append("unknown_anomaly")
            else:
                verdict.append("normal"); kind.append("normal")
        out = df.copy()
        out["verdict"], out["threat_type"] = verdict, kind
        out["confidence"] = top_conf
        out["anomaly_score"] = score
        return out
