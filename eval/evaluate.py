"""
Evaluate the baseline scorer against the labelled answer key.
Reports category accuracy and per-priority precision/recall, and saves a
confusion summary. The agent (Week 4+) will be scored with this same script
so you can show whether the LLM beats the baseline.
"""
import csv
import sys
from collections import defaultdict

sys.path.insert(0, ".")
from triage.pipeline import load_alerts, triage_all


def load_labels(path: str) -> dict:
    return {r["alert_id"]: r for r in csv.DictReader(open(path))}


def precision_recall(tp, fp, fn):
    p = tp / (tp + fp) if (tp + fp) else 0.0
    r = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * p * r / (p + r) if (p + r) else 0.0
    return p, r, f1


def main(alerts_path="data/all_alerts.jsonl", labels_path="data/all_labels.csv"):
    df = triage_all(load_alerts(alerts_path))
    labels = load_labels(labels_path)

    cat_correct = 0
    prio_tp = defaultdict(int); prio_fp = defaultdict(int); prio_fn = defaultdict(int)

    for _, row in df.iterrows():
        truth = labels[row["alert_id"]]
        if row["category_guess"] == truth["label_category"]:
            cat_correct += 1
        pred_p, true_p = row["priority"], truth["label_priority"]
        for band in ("Critical", "High", "Medium", "Low"):
            if pred_p == band and true_p == band: prio_tp[band] += 1
            elif pred_p == band and true_p != band: prio_fp[band] += 1
            elif pred_p != band and true_p == band: prio_fn[band] += 1

    print(f"Category accuracy: {cat_correct}/{len(df)} = {cat_correct/len(df):.1%}\n")
    print(f"{'Priority':<10}{'Precision':>10}{'Recall':>10}{'F1':>8}")
    for band in ("Critical", "High", "Medium", "Low"):
        p, r, f1 = precision_recall(prio_tp[band], prio_fp[band], prio_fn[band])
        print(f"{band:<10}{p:>10.2f}{r:>10.2f}{f1:>8.2f}")

    # Recall on serious threats matters most in security
    serious_tp = prio_tp["Critical"] + prio_tp["High"]
    serious_fn = prio_fn["Critical"] + prio_fn["High"]
    sr = serious_tp / (serious_tp + serious_fn) if (serious_tp + serious_fn) else 0
    print(f"\nRecall on High+Critical (catch rate for real threats): {sr:.1%}")


if __name__ == "__main__":
    main()
