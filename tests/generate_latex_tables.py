#!/usr/bin/env python3
"""Generate Overleaf-ready DiVerify tables from the summary CSV files."""

import argparse
import csv
from decimal import Decimal, ROUND_HALF_UP
from pathlib import Path


MODE_LABELS = {
    "a": "Legacy Compat.",
    "b": "Trusted Auth.",
    "c": "Core",
}
LEVELS = (1, 2, 3)


def read_rows(path: Path) -> dict[tuple[str, int], dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as csv_file:
        return {
            (row["mode"], int(row["level"])): row
            for row in csv.DictReader(csv_file)
        }


def perf_value(
    rows: dict[tuple[str, int], dict[str, str]],
    mode: str,
    level: int,
    field: str,
) -> str:
    value = rows[(mode, level)].get(field, "")
    if not value:
        return r"--"
    rounded = Decimal(value).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
    return f"{rounded:.2f}"


def generate_performance_table(
    rows: dict[tuple[str, int], dict[str, str]],
) -> str:
    def values(field_by_mode: dict[str, str]) -> str:
        cells = []
        for mode in MODE_LABELS:
            field = field_by_mode.get(mode)
            cells.extend(
                perf_value(rows, mode, level, field) if field else r"--"
                for level in LEVELS
            )
        return " & ".join(cells)

    return rf"""\begin{{table*}}[t]
\centering
\caption{{Average Signing \& Verification Overhead Introduced by DiVerify. L1--L3 denote trust levels determining the required signer scopes. Attestation cost is paid by CA (Trusted Authentication), by verifier (Core), or not (Legacy-Compatible).}}
\label{{tab:diverify-performance}}
\small
\resizebox{{\textwidth}}{{!}}{{%
\begin{{tabular}}{{llrrrrrrrrr}}
\toprule
& & \multicolumn{{3}}{{c}}{{Legacy Compat. (ms)}}
  & \multicolumn{{3}}{{c}}{{Trusted Auth. (ms)}}
  & \multicolumn{{3}}{{c}}{{Core (ms)}} \\
\cmidrule(lr){{3-5}} \cmidrule(lr){{6-8}} \cmidrule(lr){{9-11}}
& & L1 & L2 & L3 & L1 & L2 & L3 & L1 & L2 & L3 \\
\midrule
\multirow{{3}}{{*}}{{\textbf{{Signing}}}}
& Signing Time & {values({'a': 'sign', 'b': 'sign', 'c': 'sign'})} \\
& Quote Gen. & {values({'b': 'set_and_get_quote', 'c': 'set_and_get_quote'})} \\
& Fulcio & {values({'a': 'get_certificate', 'b': 'get_fulcio_cert'})} \\
\midrule
\multirow{{2}}{{*}}{{\textbf{{Verification}}}}
& Verify Time & {values({'a': 'verify_sig', 'b': 'verify_sig', 'c': 'verify_sig'})} \\
& Quote Verif. & {values({'c': '_verif_quote'})} \\
\bottomrule
\end{{tabular}}%
}}
\end{{table*}}"""


def generate_storage_table(
    rows: dict[tuple[str, int], dict[str, str]],
) -> str:
    body = []
    for mode, label in MODE_LABELS.items():
        for index, level in enumerate(LEVELS):
            row = rows[(mode, level)]
            size_kb = float(row["average_bundle_size_bytes"]) / 1000
            difference_kb = float(row["size_difference_from_baseline_bytes"]) / 1000
            package_percent = float(row["size_difference_as_percent_of_package_size"])
            difference = f"{difference_kb:+.1f}" if difference_kb else "0.0"
            mode_cell = rf"\multirow{{3}}{{*}}{{{label}}}" if index == 0 else ""
            body.append(
                f"{mode_cell} & {level} & {size_kb:.1f} & {difference} "
                f"& {package_percent:.2f} \\\\"
            )
        if mode != "c":
            body.append(r"\midrule")

    table_body = "\n".join(body)
    return rf"""\begin{{table}}[t]
\centering
\caption{{Storage overhead of DiVerify across modes. Compared to baseline, DiVerify adds approximately 0.5--28 KB, corresponding to approximately 0.03--1.5\% of the average package size on PyPI.}}
\label{{tab:diverify-storage}}
\small
\begin{{tabular}}{{lrrrr}}
\toprule
Config. & Level & Size (KB) & $\Delta$ (KB) & $\Delta$ / Pkg (\%) \\
\midrule
{table_body}
\bottomrule
\end{{tabular}}
\end{{table}}"""


def main() -> None:
    data_dir = Path(__file__).resolve().parents[1] / "sig_data_eval"
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--performance", type=Path, default=data_dir / "avg_perf.csv")
    parser.add_argument(
        "--storage", type=Path, default=data_dir / "sig_overhead_summary.csv"
    )
    parser.add_argument(
        "--output", type=Path, default=data_dir / "generated_tables.tex"
    )
    args = parser.parse_args()

    output = "\n\n".join(
        (
            generate_performance_table(read_rows(args.performance)),
            generate_storage_table(read_rows(args.storage)),
        )
    )
    args.output.write_text(output + "\n", encoding="utf-8")
    print(f"Wrote {args.output}")


if __name__ == "__main__":
    main()
