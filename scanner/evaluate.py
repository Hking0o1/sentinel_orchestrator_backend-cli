import json
from collections import defaultdict

SCAN_DATASET = "data/scans.jsonl"
GROUND_TRUTH_FILE = "data/ground_truth.json"

def load_jsonl(path):
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            yield json.loads(line)

def load_ground_truth(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def evaluate():
    ground_truth = load_ground_truth(GROUND_TRUTH_FILE)

    metrics = defaultdict(int)
    per_tool = defaultdict(lambda: defaultdict(int))

    for row in load_jsonl(SCAN_DATASET):
        rule_id = row.get("description")  # e.g. CKV_OPENAPI_4
        tool = row.get("tool_name", "unknown")

        if rule_id not in ground_truth:
            # Unknown rule → skip (cannot evaluate)
            continue

        expected = ground_truth[rule_id]["expected_vulnerable"]
        detected = True  # scanner produced this finding

        if expected and detected:
            metrics["TP"] += 1
            per_tool[tool]["TP"] += 1

        elif not expected and detected:
            metrics["FP"] += 1
            per_tool[tool]["FP"] += 1

    return metrics, per_tool

def compute_scores(m):
    tp, fp = m["TP"], m["FP"]
    precision = tp / (tp + fp) if (tp + fp) else 0
    return round(precision, 4)

def print_report(metrics, per_tool):
    print("\n=== BENCHMARK EVALUATION (RULE-BASED) ===\n")
    print(f"True Positives : {metrics['TP']}")
    print(f"False Positives: {metrics['FP']}")
    print(f"Precision     : {compute_scores(metrics)}\n")

    print("=== PER TOOL BREAKDOWN ===")
    for tool, m in per_tool.items():
        print(f"{tool}: TP={m['TP']} FP={m['FP']}")

if __name__ == "__main__":
    metrics, per_tool = evaluate()
    print_report(metrics, per_tool)
