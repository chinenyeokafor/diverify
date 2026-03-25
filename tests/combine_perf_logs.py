#!/usr/bin/env python3
import argparse
import json
import csv
from pathlib import Path


KEY_FIELDS = ("iteration", "level", "mode")


def read_jsonl_by_key(path):
    rows = {}

    with open(path, "r", encoding="utf-8") as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue

            row = json.loads(line)

            if not isinstance(row, dict):
                raise ValueError(f"{path}:{line_num} is not a JSON object")

            key = tuple(row[k] for k in KEY_FIELDS)

            if key in rows:
                raise ValueError(f"Duplicate key {key} in {path} at line {line_num}")

            rows[key] = row

    return rows


def merge_rows(client_row, daemon_row):
    merged = {}

    if client_row:
        merged.update(client_row)

    if daemon_row:
        for k, v in daemon_row.items():
            if k in KEY_FIELDS:
                continue
            if k == "timestamp" and "timestamp" in merged:
                continue
            if k not in merged or merged[k] in ("", None):
                merged[k] = v

    return merged


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--client", default="perf_log.jsonl")
    p.add_argument("--daemon", default="src/diverify/TEE/SGX/daemon_perf_log.jsonl")
    p.add_argument("--out_jsonl", default="combined_perf.jsonl")
    p.add_argument("--out_csv", default="sig_data_eval/combined_perf.csv")
    args = p.parse_args()

    client_rows = read_jsonl_by_key(args.client)
    daemon_rows = read_jsonl_by_key(args.daemon)

    all_keys = sorted(
        set(client_rows) | set(daemon_rows),
        key=lambda k: (k[2], k[1], k[0]),  # mode, level, iteration
    )

    merged_rows = []

    for key in all_keys:
        c = client_rows.get(key)
        d = daemon_rows.get(key)

        merged = merge_rows(c, d)
        merged["iteration"], merged["level"], merged["mode"] = key

        merged_rows.append(merged)

    # Write to JSONL
    jsonl_path = Path(args.out_jsonl)
    jsonl_path.parent.mkdir(parents=True, exist_ok=True)

    with jsonl_path.open("w", encoding="utf-8") as f:
        for row in merged_rows:
            json.dump(row, f)
            f.write("\n")

    # Write to csv
    csv_path = Path(args.out_csv)

    def short_name(k):
        return k.split(".")[-1]

    # Build fieldnames (shortened)
    fieldnames = []
    for row in merged_rows:
        for k in row.keys():
            k2 = k if k in KEY_FIELDS else short_name(k)
            if k2 not in fieldnames:
                fieldnames.append(k2)

    # Ensure ordering
    ordered_fields = list(KEY_FIELDS) + [
        f for f in fieldnames if f not in KEY_FIELDS
    ]

    with csv_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=ordered_fields)
        writer.writeheader()

        for row in merged_rows:
            new_row = {}
            for k, v in row.items():
                k2 = k if k in KEY_FIELDS else short_name(k)
                new_row[k2] = v
            writer.writerow(new_row)

    print(f"saved: {jsonl_path} ({len(merged_rows)} rows)")
    print(f"saved: {csv_path}")


if __name__ == "__main__":
    main()