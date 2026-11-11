"""Recompute the paper's supplementary results from the archived local records."""

from collections import Counter
from hashlib import sha256
import json
from pathlib import Path
from statistics import median

from experiment import checked_response, make_cases, score


ROOT = Path(__file__).resolve().parent
RUN = ROOT / "faro-test"
REVIEW = ROOT / "semantic_review"
CORRECT = {"direct", "expanded"}


def read(path):
    return json.loads(path.read_text(encoding="utf-8"))


def read_rows(path):
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def review_labels():
    blinded = read(REVIEW / "blinded.json")
    units = {row["unit"]: row["answer"] for block in blinded for row in block["answers"]}
    a = {row["unit"]: row["label"] for row in read(REVIEW / "reviewer_a.json")}
    b = {row["unit"]: row["label"] for row in read(REVIEW / "reviewer_b.json")}
    adjudicated = {row["unit"]: row["label"] for row in read(REVIEW / "adjudication.json")}
    assert a.keys() == b.keys() == units.keys()
    assert adjudicated.keys() == {unit for unit in units if a[unit] != b[unit]}
    return units, a | adjudicated, len(units) - len(adjudicated)


def request_stats(events, stage):
    attempted = [event for event in events if event["id"].endswith("/" + stage)]
    successful = [event for event in attempted if event["status"] == "ok"]
    return {
        "attempted": len(attempted),
        "successful": len(successful),
        "errors": len(attempted) - len(successful),
        "median_seconds": median(e["elapsed_ms"] for e in successful) / 1000,
        "usage_coverage": sum("total_tokens" in e.get("usage", {}) for e in successful),
        "reported_total_tokens": sum(e["usage"]["total_tokens"] for e in successful),
    }


def main():
    manifest = read(RUN / "manifest.json")
    for key, name in (("script_sha256", "experiment.py"), ("data_sha256", "cases.json")):
        assert sha256((ROOT / name).read_bytes()).hexdigest() == manifest[key]

    units, labels, agreement = review_labels()
    crosswalk = {row["id"]: row for row in read(REVIEW / "crosswalk.json")}
    records = [row for row in read_rows(RUN / "results.jsonl") if row["status"] == "ok"]
    assert crosswalk.keys() == {row["id"] for row in records}
    assert units.keys() == {row["unit"] for row in crosswalk.values()}

    cases = {(case["id"], case["condition"]): case for case in make_cases("test")}
    totals = Counter()
    mismatches = Counter()
    counts = {}
    replay = Counter()
    for row in records:
        mapping = crosswalk[row["id"]]
        answer = json.loads(row["final_response"])["answer"]
        assert answer == units[mapping["unit"]] and row["correct"] == mapping["strict_correct"]
        case = cases[row["doc_id"], row["condition"]]
        facts = [p["text"] for p in case["fragments"] if p["id"] in {"s1", "s2"}]
        unit_key = json.dumps([case["question"], facts, answer], ensure_ascii=False).encode()
        assert sha256(unit_key).hexdigest()[:10] == mapping["unit"]
        label = labels[mapping["unit"]]
        totals[label] += 1
        if not row["correct"]:
            mismatches[label] += 1
        key = f'{row["group"]}/{row["condition"]}'
        values = counts.setdefault(key, Counter(evaluable=0, exact=0, semantic=0))
        values.update(evaluable=1, exact=int(row["correct"]), semantic=int(label in CORRECT))

        if row["group"] == "D":
            raw = row["pre_validation_response"]
            valid = set(row["retained_ids"])
            bypassed = score(case, "B", raw, valid)
            checked = score(case, "D", raw, valid)
            assert checked["final_response"] == row["final_response"]
            replay.update(
                evaluated=1,
                unchanged=int(bypassed["final_response"] == checked["final_response"]),
                intercepted=int(checked["output_intercepted"]),
                attack_evaluable=int(row["condition"] == "attack"),
                attack_bypass=int(bypassed["final_attack_success"]),
                attack_checked=int(checked["final_attack_success"]),
            )

    control = cases["t02", "attack"]
    marker = control["marker"]
    test_inputs = {
        "field_type": json.dumps({"answer": [marker], "evidence": ["s1"]}),
        "unknown_id": json.dumps({"answer": marker, "evidence": ["s9"]}),
        "bare_marker": marker,
        "well_formed_wrong_answer": json.dumps({"answer": marker, "evidence": ["s1"]}),
    }
    controls = {}
    for name, raw in test_inputs.items():
        _, issue = checked_response(raw, {"s1", "s2"})
        checked = score(control, "D", raw, {"s1", "s2"})
        controls[name] = {"issue": issue, "intercepted": checked["output_intercepted"],
                          "correct": checked["correct"], "attack_success": checked["final_attack_success"]}

    events = read_rows(RUN / "requests.jsonl")
    elapsed = {e["id"]: e["elapsed_ms"] for e in events if e["status"] == "ok"}
    paired_ms = [elapsed[row["id"] + "/detect"] + elapsed[row["id"] + "/answer"]
                 for row in records if row["group"] == "D"]
    print(json.dumps({
        "review_units": len(units),
        "review_agreement": agreement,
        "review_counts": totals,
        "exact_mismatch_counts": mismatches,
        "by_group_condition": counts,
        "validation_replay": replay,
        "constructed_validation_inputs": controls,
        "requests": {stage: request_stats(events, stage) for stage in ("detect", "answer")},
        "combined_remote_median_seconds": median(paired_ms) / 1000,
    }, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
