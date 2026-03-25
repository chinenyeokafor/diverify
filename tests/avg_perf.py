import pandas as pd

# Read your combined CSV
df = pd.read_csv("sig_data_eval/combined_perf.csv")

# Identify metric columns
metric_cols = [c for c in df.columns if c not in ["timestamp", "mode", "level", "iteration"]]

# Convert to numeric (handles empty cells)
df[metric_cols] = df[metric_cols].apply(pd.to_numeric, errors="coerce")

# Compute averages per (mode, level)
avg = df.groupby(["mode", "level"])[metric_cols].mean().reset_index()

# Save to file
avg.to_csv("sig_data_eval/avg_perf.csv", index=False)