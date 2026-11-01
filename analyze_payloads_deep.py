from collections import Counter
import csv
import os
import sys

csv.field_size_limit(sys.maxsize)
import pandas as pd

SURICATA_CSV = "data/honeytrap/suricata/suricata_merged.csv"
HONEYTRAP_CSV = "data/honeytrap/honeytrap_master.csv"


def run_deep_payload_analysis():
  print("=" * 70)
  print(" DEEP PAYLOAD & PROTOCOL BEHAVIOR ANALYSIS")
  print("=" * 70)

  # 1. Analyze Suricata Protocol & Flow Payloads
  if os.path.exists(SURICATA_CSV):
    sur_df = pd.read_csv(SURICATA_CSV, low_memory=False)
    print(
        f"\n[+] Loaded Suricata IDS Logs: {len(sur_df):,} records for protocol"
        " inspection"
    )

    # Inspect Application Protocols (app_proto)
    if "app_proto" in sur_df.columns:
      print(
          "\n--- Application Protocol Distribution (`app_proto`) ---"
      )
      app_counts = sur_df[sur_df["app_proto"] != "-"]["app_proto"].value_counts()
      print(
          app_counts
          if not app_counts.empty
          else "All records marked as unclassified/raw TCP streams ('-')."
      )

      # Breakdown of protocol usage
      total_classified = app_counts.sum()
      print(
          f"  * Classified Application Probes: {total_classified:,}"
          f" ({(total_classified/len(sur_df))*100:.2f}%)"
      )
      print(
          f"  * Unclassified / Raw Probes / Port Scans:"
          f" {len(sur_df) - total_classified:,}"
          f" ({((len(sur_df) - total_classified)/len(sur_df))*100:.2f}%)"
      )

    # Inspect CVE and Exploit payload references
    cve_cols = [c for c in sur_df.columns if "cve" in c.lower()]
    print(f"\n--- CVE & Vulnerability Payload Tags ({cve_cols}) ---")
    found_cves = False
    for col in cve_cols:
      cve_counts = sur_df[sur_df[col] != "-"][col].value_counts()
      if not cve_counts.empty:
        found_cves = True
        print(f"Found in column '{col}':")
        print(cve_counts)
    if not found_cves:
      print(
          "  * No explicit CVE exploit payloads tagged in Suricata metadata"
          " (indicates automated reconnaissance / scanning rather than known"
          " exploit payload delivery)."
      )

  # 2. Analyze Honeytrap Master / Payloads (if file exists locally)
  ht_path = (
      HONEYTRAP_CSV if os.path.exists(HONEYTRAP_CSV) else "honeytrap_master.csv"
  )
  if os.path.exists(ht_path):
    print(f"\n[+] Loading Honeytrap Master Dataset from {ht_path}...")
    ht_df = pd.read_csv(ht_path, low_memory=False)
    print(f"    - Total records: {len(ht_df):,}")

    payload_col = None
    for col in ht_df.columns:
      if "payload" in col.lower() or "data_hex" in col.lower():
        payload_col = col
        break

    if payload_col:
      print(f"    - Found payload column: '{payload_col}'")
      non_empty_payloads = ht_df[
          ht_df[payload_col].astype(str).str.strip() != ""
      ]
      non_empty_payloads = non_empty_payloads[
          non_empty_payloads[payload_col].astype(str) != "-"
      ]
      print(
          f"    - Records with Active Payloads: {len(non_empty_payloads):,}"
      )
      print(
          "    - Records with Zero-Length / Pure TCP Probes:"
          f" {len(ht_df) - len(non_empty_payloads):,}"
      )
    else:
      print(
          "    - Payload hex columns not directly exposed in master CSV header."
          " Inspecting connection/attack types..."
      )
  else:
    print(
        f"\n[-] Note: Honeytrap master CSV not found at '{ht_path}'. Running"
        " exclusively on Suricata log state."
    )

  print("\n[+] Deep payload analysis inspection complete.")


if __name__ == "__main__":
  run_deep_payload_analysis()