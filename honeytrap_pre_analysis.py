from collections import Counter
import csv
import sys

# Increase the CSV field size limit to handle large hex payloads
csv.field_size_limit(sys.maxsize)

HONEYTRAP_CSV = "data/honeypot/honeytrap_master.csv"

total_events = 0
port_counter = Counter()
ip_counter = Counter()
country_counter = Counter()

print(f"Running pre-analysis on {HONEYTRAP_CSV}...")

try:
  with open(HONEYTRAP_CSV, mode="r", encoding="utf-8", errors="ignore") as f:
    reader = csv.DictReader(f)
    for row in reader:
      total_events += 1

      # Capture destination port using the exact CSV header name you found
      port = (
          row.get("DestPort (dest_port)")
          or row.get("dest_port")
          or row.get("DestPort")
          or row.get("destport")
      )
      if port:
        port_counter[port] += 1

      # Capture source IP
      src_ip = row.get("src_ip")
      if src_ip:
        ip_counter[src_ip] += 1

      # Capture country
      country = row.get("geoip.country_name")
      if country and country != "-":
        country_counter[country] += 1
      else:
        country_counter["Unknown / Unresolved"] += 1

  # Print out the aggregated pre-analysis results
  print("\n" + "=" * 50)
  print(f" TOTAL HONEYTRAP EVENTS ANALYZED: {total_events:,}")
  print("=" * 50)

  print("\n--- Top 10 Most Frequently Targeted Ports ---")
  if port_counter:
    for port, count in port_counter.most_common(10):
      pct = (count / total_events) * 100 if total_events > 0 else 0
      print(f"Port {port}: {count:,} events ({pct:.2f}%)")
  else:
    print("No port data found. Please check column headers.")

  print("\n--- Top 5 Attacker Source IPs ---")
  for ip, count in ip_counter.most_common(5):
    print(f"IP {ip}: {count:,} events")

  print(f"Total Unique Source IPs: {len(ip_counter):,}")

  print("\n--- Top Countries ---")
  for country, count in country_counter.most_common(5):
    pct = (count / total_events) * 100 if total_events > 0 else 0
    print(f"{country}: {count:,} events ({pct:.2f}%)")

except Exception as e:
  print(f"Error reading dataset: {e}")