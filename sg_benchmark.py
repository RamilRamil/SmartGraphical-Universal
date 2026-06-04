"""CLI: run the rule benchmark corpus and print precision/recall (feature 014).

Reports per-example and overall recall/precision over human-labeled findings,
plus missed (expected-not-found) and unexpected (emitted-but-unlabeled) findings.
The CI gate is the recall-guard test, not this CLI (it always exits 0).
"""
import argparse
import json
import os
import sys

from smartgraphical.benchmark import corpus
from smartgraphical.services import web_api

_HERE = os.path.dirname(os.path.abspath(__file__))


def _fmt(value):
    return "n/a" if value is None else f"{value:.0%}"


def main(argv=None):
    parser = argparse.ArgumentParser(description="Rule precision/recall benchmark")
    parser.add_argument(
        "--labels", default=os.path.join(_HERE, "tests", "benchmark", "labels")
    )
    parser.add_argument("--examples", default=os.path.join(_HERE, "examples"))
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    args = parser.parse_args(argv)

    result = corpus.run_corpus(args.labels, args.examples, web_api.analyze_all)

    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0

    print("Rule benchmark (precision/recall over labeled findings)")
    print("=" * 60)
    for name in sorted(result["examples"]):
        res = result["examples"][name]
        print(
            f"\n{name}: recall={_fmt(res['recall'])}  precision={_fmt(res['precision'])}"
            f"  (found {len(res['found'])}/{res['expected_total']}, "
            f"labeled-FP {len(res['labeled_fp'])}, unexpected {len(res['unexpected'])})"
        )
        for key in res["missed"]:
            print(f"  MISS  {key[0]} {key[1]}.{key[2]}")
        for key in res["unexpected"]:
            print(f"  ?     {key[0]} {key[1]}.{key[2]}  (unlabeled)")
    overall = result["overall"]
    print("\n" + "-" * 60)
    print(
        f"OVERALL: recall={_fmt(overall['recall'])}  precision={_fmt(overall['precision'])}"
        f"  (found {overall['found']}/{overall['expected_total']}, "
        f"labeled-FP {overall['labeled_fp']}, unexpected {overall['unexpected']})"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
