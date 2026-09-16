"""Generate PAACT-Core JSONL and evaluate all mechanism-level baselines."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from attack_corpus import (
    DEFAULT_SEED,
    evaluate_corpus,
    generate_corpus,
    write_corpus_jsonl,
)


def render_markdown(report: dict) -> str:
    manifest = report["manifest"]
    lines = [
        "# PAACT-Core v1 Results",
        "",
        f"- Seed: `{manifest['seed']}`",
        f"- Total cases: **{manifest['total_cases']}**",
        f"- Schema: `{manifest['schema_version']}`",
        "- All mechanism-level baselines consume the identical ordered corpus.",
        "",
        "## Overall baseline comparison",
        "",
        "| Mechanism profile | Attack block | 95% Wilson CI | Benign completion | False rejection |",
        "|---|---:|---:|---:|---:|",
    ]
    for baseline in report["baseline_results"]:
        metrics = baseline["overall"]
        low, high = metrics["attack_block_rate_wilson_95"]
        lines.append(
            f"| `{baseline['mode']}` | {metrics['attack_block_rate']:.2f}% "
            f"({metrics['blocked_attacks']}/{metrics['attacks']}) | "
            f"[{low:.2f}, {high:.2f}] | {metrics['benign_completion_rate']:.2f}% | "
            f"{metrics['false_rejection_rate']:.2f}% |"
        )

    lines.extend(
        [
            "",
            "## Attack block rate by mutation family",
            "",
        ]
    )
    baselines = report["baseline_results"]
    families = sorted(
        {
            family
            for baseline in baselines
            for family, values in baseline["by_family"].items()
            if values["attacks"]
        }
    )
    lines.append("| Family | " + " | ".join(f"`{item['mode']}`" for item in baselines) + " |")
    lines.append("|---|" + "---:|" * len(baselines))
    for family in families:
        cells = []
        for baseline in baselines:
            metrics = baseline["by_family"].get(family)
            cells.append("—" if not metrics or metrics["attack_block_rate"] is None else f"{metrics['attack_block_rate']:.2f}%")
        lines.append(f"| {family} | " + " | ".join(cells) + " |")

    lines.extend(
        [
            "",
            "## Interpretation boundary",
            "",
            *[f"- {item}" for item in report["interpretation_boundary"]],
            "",
        ]
    )
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    parser.add_argument(
        "--corpus",
        type=Path,
        default=Path(__file__).parent.parent / "fixtures" / "paact-core-v1.jsonl",
    )
    parser.add_argument(
        "--report-json",
        type=Path,
        default=Path(__file__).parent.parent / "docs" / "research-v3" / "paact-core-v1-results.json",
    )
    parser.add_argument(
        "--report-md",
        type=Path,
        default=Path(__file__).parent.parent / "docs" / "research-v3" / "paact-core-v1-results.md",
    )
    args = parser.parse_args()

    manifest, cases = generate_corpus(seed=args.seed)
    write_corpus_jsonl(args.corpus, manifest, cases)
    report = evaluate_corpus(manifest, cases)

    args.report_json.parent.mkdir(parents=True, exist_ok=True)
    args.report_json.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    args.report_md.parent.mkdir(parents=True, exist_ok=True)
    args.report_md.write_text(render_markdown(report), encoding="utf-8")

    print(json.dumps({
        "corpus": str(args.corpus),
        "report_json": str(args.report_json),
        "report_md": str(args.report_md),
        "total_cases": manifest.total_cases,
        "seed": manifest.seed,
    }, indent=2))


if __name__ == "__main__":
    main()
