import pandas as pd

print("Loading datasets...")
heralding_df = pd.read_csv("data/heralding.csv")
suricata_df = pd.read_csv("data/suricata_heralding.csv")

# 1. Normalize timestamps and strip any timezone info to ensure matching dtypes
print("Normalizing and aligning timestamps...")
heralding_df["parsed_time"] = pd.to_datetime(
    heralding_df["@timestamp"], format="%b %d, %Y @ %H:%M:%S.%f", errors="coerce"
)
suricata_df["parsed_time"] = pd.to_datetime(
    suricata_df["@timestamp"], errors="coerce"
)

# Convert both to timezone-naive (drops any +00:00 offset so dtypes match)
if heralding_df["parsed_time"].dt.tz is not None:
    heralding_df["parsed_time"] = heralding_df["parsed_time"].dt.tz_localize(None)
if suricata_df["parsed_time"].dt.tz is not None:
    suricata_df["parsed_time"] = suricata_df["parsed_time"].dt.tz_localize(None)

# Drop NaTs and sort both dataframes by time (required for merge_asof)
heralding_df = heralding_df.dropna(subset=["parsed_time"]).sort_values(
    "parsed_time"
)
suricata_df = suricata_df.dropna(subset=["parsed_time"]).sort_values(
    "parsed_time"
)

# Rename columns to avoid collisions
heralding_df = heralding_df.rename(
    columns={"DestPort (dest_port)": "dest_port", "Type (type)": "heralding_type"}
)

print(
    f"Clean rows -> Heralding: {len(heralding_df):,}, Suricata: {len(suricata_df):,}"
)

# 2. Perform memory-safe temporal merge on src_ip with a 2-minute tolerance window
print("Performing memory-safe temporal merge on src_ip...")
merged_df = pd.merge_asof(
    heralding_df,
    suricata_df,
    on="parsed_time",
    by="src_ip",
    direction="nearest",
    tolerance=pd.Timedelta("2 minutes"),
)

print(f"Successfully merged down to {len(merged_df):,} correlated rows!")

# 3. Save output
output_file = "data/merged_attribution_analysis.csv"
merged_df.to_csv(output_file, index=False)
print(f"Saved result to {output_file}!")