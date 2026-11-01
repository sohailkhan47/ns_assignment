from collections import Counter
import os
import sys

# Set field size limit before loading CSVs
import csv

csv.field_size_limit(sys.maxsize)

import matplotlib.pyplot as plt
import pandas as pd
import seaborn as sns

# Define paths
HONEYTRAP_CSV = "data/honeytrap/honeytrap_master.csv"
SURICATA_CSV = "suricata_merged.csv"  # or 'data/honeytrap/suricata/suricata_merged.csv'
OUTPUT_DIR = "data/honeytrap"

# Ensure output directory exists
os.makedirs(OUTPUT_DIR, exist_ok=True)


def run_full_pipeline():
  print("=" * 70)
  print(" HONEYTRAP & SURICATA CORRELATION AND VISUALIZATION PIPELINE")
  print("=" * 70)

  # -------------------------------------------------------------------------
  # 1. LOAD DATASETS
  # -------------------------------------------------------------------------
  print("[1/5] Loading datasets...")

  # Load Honeytrap
  if not os.path.exists(HONEYTRAP_CSV):
    alt_ht = "honeytrap_master.csv"
    if os.path.exists(alt_ht):
      ht_path = alt_ht
    else:
      print(f"[-] Error: Could not find Honeytrap file at {HONEYTRAP_CSV}")
      return
  else:
    ht_path = HONEYTRAP_CSV

  ht_df = pd.read_csv(ht_path, low_memory=False)
  print(f"    - Honeytrap records loaded: {len(ht_df):,}")

  # Load Suricata
  if not os.path.exists(SURICATA_CSV):
    alt_sur = "data/honeytrap/suricata/suricata_merged.csv"
    if os.path.exists(alt_sur):
      sur_path = alt_sur
    else:
      print(f"[-] Error: Could not find Suricata file at {SURICATA_CSV}")
      return
  else:
    sur_path = SURICATA_CSV

  sur_df = pd.read_csv(sur_path, low_memory=False)
  print(f"    - Suricata records loaded: {len(sur_df):,}")

  # -------------------------------------------------------------------------
  # 2. STANDARDIZE COLUMN NAMES
  # -------------------------------------------------------------------------
  print("[2/5] Standardizing schema and port column names...")

  ht_port_col = (
      "DestPort (dest_port)"
      if "DestPort (dest_port)" in ht_df.columns
      else "dest_port"
  )
  sur_port_col = (
      "DestPort (dest_port)"
      if "DestPort (dest_port)" in sur_df.columns
      else "dest_port"
  )

  ht_df.rename(columns={ht_port_col: "target_port"}, inplace=True)
  sur_df.rename(columns={sur_port_col: "target_port"}, inplace=True)

  # -------------------------------------------------------------------------
  # 3. PRE-ANALYSIS: TOP 10 TARGET PORTS
  # -------------------------------------------------------------------------
  top_10_ports = ht_df["target_port"].value_counts().head(10).index.tolist()
  print(f"\n[+] Identified Top 10 Target Ports in Honeytrap: {top_10_ports}")

  # Filter Suricata for matching top ports
  sur_filtered = sur_df[sur_df["target_port"].isin(top_10_ports)].copy()
  print(
      f"[+] Suricata records filtered for top 10 ports: {len(sur_filtered):,}"
  )

  # -------------------------------------------------------------------------
  # 4. DATA-LEVEL CORRELATION (MERGE ON IP + PORT)
  # -------------------------------------------------------------------------
  print("\n[3/5] Correlating Honeytrap & Suricata logs (Inner Join)...")

  # Select key fields for clean joining
  ht_cols = [
      col
      for col in [
          "@timestamp",
          "src_ip",
          "target_port",
          "geoip.country_name",
          "geoip.as_org",
      ]
      if col in ht_df.columns
  ]
  sur_cols = [
      col
      for col in [
          "@timestamp",
          "src_ip",
          "target_port",
          "alert.signature",
          "alert.severity",
          "alert.cve_id",
          "app_proto",
      ]
      if col in sur_df.columns
  ]

  ht_sub = ht_df[ht_cols].copy()
  sur_sub = sur_filtered[sur_cols].copy()

  # Indexing for faster join
  ht_sub.set_index(["src_ip", "target_port"], inplace=True)
  sur_sub.set_index(["src_ip", "target_port"], inplace=True)

  correlated = ht_sub.join(
      sur_sub, how="inner", lsuffix="_honeytrap", rsuffix="_suricata"
  ).reset_index()

  print(
      f"    - Correlated dual-sensor event matches: {len(correlated):,} rows"
  )

  # Export correlated CSV
  output_csv_path = os.path.join(
      OUTPUT_DIR, "final_correlated_analysis_output.csv"
  )
  correlated.to_csv(output_csv_path, index=False)
  print(f"    - Saved correlated dataset to: {output_csv_path}")

  # -------------------------------------------------------------------------
  # 5. PRINT REPORT METRICS
  # -------------------------------------------------------------------------
  print("\n[4/5] Computing Assignment Report Metrics...")
  print("=" * 50)

  print("\n--- Top Attacker Source IPs ---")
  top_ips = ht_df["src_ip"].value_counts().head(5)
  for ip, count in top_ips.items():
    print(f"  * IP {ip}: {count:,} events")

  print("\n--- Geographic Breakdown (Honeytrap) ---")
  if "geoip.country_name" in ht_df.columns:
    countries = ht_df["geoip.country_name"].value_counts().head(5)
    for c, count in countries.items():
      pct = (count / len(ht_df)) * 100
      print(f"  * {c}: {count:,} ({pct:.2f}%)")

  print("\n--- Top IDS Signatures (Suricata) ---")
  if "alert.signature" in sur_filtered.columns:
    sigs = (
        sur_filtered[sur_filtered["alert.signature"] != "-"]["alert.signature"]
        .value_counts()
        .head(5)
    )
    for sig, count in sigs.items():
      print(f"  * [{count:,} hits] {sig}")

  # -------------------------------------------------------------------------
  # 6. GENERATE & SAVE VISUALIZATIONS
  # -------------------------------------------------------------------------
  print("\n[5/5] Generating Visualizations...")
  sns.set_theme(style="whitegrid")

  # Chart 1: Top 10 Destination Ports
  plt.figure(figsize=(10, 5))
  top_ports_series = ht_df["target_port"].value_counts().head(10)
  ax = sns.barplot(
      x=top_ports_series.index.astype(str),
      y=top_ports_series.values,
      palette="Blues_r",
  )
  plt.title("Top 10 Targeted Destination Ports (Honeytrap Baseline)")
  plt.xlabel("Destination Port")
  plt.ylabel("Event Count")
  plt.xticks(rotation=45)
  for p in ax.patches:
    ax.annotate(
        f"{int(p.get_height()):,}",
        (p.get_x() + p.get_width() / 2.0, p.get_height()),
        ha="center",
        va="bottom",
        fontsize=8,
        xytext=(0, 3),
        textcoords="offset points",
    )
  plt.tight_layout()
  fig1_path = os.path.join(OUTPUT_DIR, "top_ports_distribution.png")
  plt.savefig(fig1_path, dpi=300)
  plt.close()
  print(f"    - Saved: {fig1_path}")

  # Chart 2: Top IDS Alert Signatures
  if "alert.signature" in sur_filtered.columns:
    plt.figure(figsize=(11, 5))
    sigs_series = (
        sur_filtered[sur_filtered["alert.signature"] != "-"]["alert.signature"]
        .value_counts()
        .head(10)
    )
    sns.barplot(y=sigs_series.index, x=sigs_series.values, palette="Reds_r")
    plt.title("Top IDS Detection Signatures (Suricata)")
    plt.xlabel("Event Count")
    plt.ylabel("Signature Description")
    plt.tight_layout()
    fig2_path = os.path.join(OUTPUT_DIR, "top_signatures.png")
    plt.savefig(fig2_path, dpi=300)
    plt.close()
    print(f"    - Saved: {fig2_path}")

  print("\n[+] All tasks finished successfully!")


if __name__ == "__main__":
  run_full_pipeline()