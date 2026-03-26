import argparse
import csv
from collections import defaultdict
from pathlib import Path
from statistics import mean


def parse_args():
    parser = argparse.ArgumentParser(description="Compute signature bundle size differences")
    parser.add_argument("--input", default="sig_data_eval/sig_bundles.csv")
    parser.add_argument("--out-dir", default="sig_data_eval")
    parser.add_argument("--baseline-mode", default="a")
    parser.add_argument("--baseline-level", type=int, default=1)
    parser.add_argument("--package-kb", type=float, default=1807.53)
    return parser.parse_args()


def bundle_size_bytes(bundle_json_text):
    """UTF-8 byte size of serialized bundle JSON."""
    if not bundle_json_text:
        return 0
    return len(bundle_json_text.encode("utf-8"))


def main():
    args = parse_args()
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    grouped = defaultdict(list)
    with open(args.input, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            mode = (row.get("mode") or "").strip()
            level_raw = row.get("level")

            if not mode or level_raw in (None, ""):
                continue

            try:
                level = int(level_raw)
            except ValueError:
                continue

            size = bundle_size_bytes(row.get("bundle_json") or "")
            grouped[(mode, level)].append(size)

    baseline_key = (args.baseline_mode, args.baseline_level)
    baseline_sizes = grouped.get(baseline_key, [])
    baseline_bundle_size_bytes = mean(baseline_sizes) if baseline_sizes else None

    if baseline_bundle_size_bytes is None:
        raise ValueError(
            f"No baseline data found for mode='{args.baseline_mode}', "
            f"level={args.baseline_level}"
        )

    package_size_bytes = args.package_kb * 1024 if args.package_kb > 0 else None

    out_path = out_dir / "sig_overhead_summary.csv"
    with open(out_path, "w", newline="", encoding="utf-8") as f:
        fieldnames = [
            "mode",
            "level",
            "samples",
            "average_bundle_size_bytes",
            "baseline_mode",
            "baseline_level",
            "baseline_bundle_size_bytes",
            "size_difference_from_baseline_bytes",
            "percent_change_from_baseline",
            "bundle_size_as_percent_of_package_size",
            "size_difference_as_percent_of_package_size",
        ]
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()

        for (mode, level), sizes in sorted(grouped.items()):
            average_bundle_size_bytes = mean(sizes)

            size_difference_from_baseline_bytes = (
                average_bundle_size_bytes - baseline_bundle_size_bytes
            )

            percent_change_from_baseline = (
                ((average_bundle_size_bytes / baseline_bundle_size_bytes) - 1) * 100
                if baseline_bundle_size_bytes > 0
                else None
            )

            bundle_size_as_percent_of_package_size = (
                (average_bundle_size_bytes / package_size_bytes) * 100
                if package_size_bytes is not None and package_size_bytes > 0
                else None
            )

            size_difference_as_percent_of_package_size = (
                (size_difference_from_baseline_bytes / package_size_bytes) * 100
                if package_size_bytes is not None and package_size_bytes > 0
                else None
            )

            writer.writerow(
                {
                    "mode": mode,
                    "level": level,
                    "samples": len(sizes),
                    "average_bundle_size_bytes": round(average_bundle_size_bytes, 2),
                    "baseline_mode": args.baseline_mode,
                    "baseline_level": args.baseline_level,
                    "baseline_bundle_size_bytes": round(baseline_bundle_size_bytes, 2),
                    "size_difference_from_baseline_bytes": round(
                        size_difference_from_baseline_bytes, 2
                    ),
                    "percent_change_from_baseline": round(
                        percent_change_from_baseline, 4
                    )
                    if percent_change_from_baseline is not None
                    else None,
                    "bundle_size_as_percent_of_package_size": round(
                        bundle_size_as_percent_of_package_size, 6
                    )
                    if bundle_size_as_percent_of_package_size is not None
                    else None,
                    "size_difference_as_percent_of_package_size": round(
                        size_difference_as_percent_of_package_size, 6
                    )
                    if size_difference_as_percent_of_package_size is not None
                    else None,
                }
            )

    print(f"Wrote: {out_path}")
    print(
        "Using fixed baseline:",
        f"mode={args.baseline_mode},",
        f"level={args.baseline_level},",
        f"baseline_bundle_size_bytes={round(baseline_bundle_size_bytes, 2)}",
    )


if __name__ == "__main__":
    main()