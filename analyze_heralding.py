import matplotlib.pyplot as plt
import pandas as pd
import seaborn as sns

# Set style for professional charts
sns.set_theme(style="whitegrid")
plt.rcParams.update({"figure.autolayout": True})

print("Loading merged attribution dataset...")
df = pd.read_csv("data/merged_attribution_analysis.csv", low_memory=False)

# Ensure timestamp is parsed properly
df["parsed_time"] = pd.to_datetime(df["parsed_time"])

print(f"Dataset loaded with {len(df):,} rows and {len(df.columns)} columns.\n")

# ========================================================
# QUESTION 4: Credential Attack & Brute-Force Analysis
# ========================================================
print("--- [4] Credential Harvesting & Attack Pattern Analysis ---")

if "username" in df.columns and "password" in df.columns:
    # Filter out placeholder values like '-'
    valid_users = df[
        (df["username"].notnull()) & (df["username"] != "-")
    ]
    valid_passwords = df[
        (df["password"].notnull()) & (df["password"] != "-")
    ]

    print(
        f"Total credential attempts captured: {len(valid_users):,}"
    )

    top_users = valid_users["username"].value_counts().head(10)
    top_passwords = valid_passwords["password"].value_counts().head(10)

    print("\nTop 10 Attempted Usernames:")
    print(top_users)

    print("\nTop 10 Attempted Passwords:")
    print(top_passwords)

    # Plot Top Usernames
    plt.figure(figsize=(10, 5))
    sns.barplot(
        x=top_users.values,
        y=top_users.index,
        palette="viridis",
        hue=top_users.index,
        legend=False,
    )
    plt.title(
        "Top 10 Attempted Usernames (Heralding Honeypot)",
        fontsize=14,
        fontweight="bold",
    )
    plt.xlabel("Attempt Count", fontsize=12)
    plt.ylabel("Username", fontsize=12)
    plt.savefig("top_usernames.png", dpi=300)
    plt.close()
    print("Saved chart: top_usernames.png")
else:
    print("Username/Password columns not found in dataset.")

# ========================================================
# QUESTION 5: Single vs. Multiple Sources & Automation
# ========================================================
print(
    "\n--- [5] Source Attribution & Automation Characterization ---"
)

# 1. Single vs Multiple Sources
total_events = len(df)
unique_sources = df["src_ip"].nunique()
top_10_events = df["src_ip"].value_counts().head(10).sum()
top_10_share = (top_10_events / total_events) * 100

print(f"Total Unique Source IPs: {unique_sources:,}")
print(
    f"Traffic volume from Top 10 IPs: {top_10_events:,} events ({top_10_share:.2f}% of total)"
)

if unique_sources > 50:
    print(
        "-> Finding: Multi-source attack (indicates a botnet or distributed scanning campaign)."
    )
else:
    print(
        "-> Finding: Concentrated source attack (indicates targeted scanning from limited infrastructure)."
    )

# 2. Automation Check (Request Frequency per IP)
df = df.sort_values(by=["src_ip", "parsed_time"])
df["time_diff"] = df.groupby("src_ip")["parsed_time"].diff().dt.total_seconds()

# Calculate median inter-arrival time per IP
avg_intervals = df.groupby("src_ip")["time_diff"].median().dropna()

print(
    f"\nMedian inter-arrival time between requests per IP: {avg_intervals.median():.4f} seconds"
)
if avg_intervals.median() < 5.0:
    print(
        "-> Finding: Highly regular, sub-second or rapid timing confirms AUTOMATED script/bot activity rather than manual typing."
    )
else:
    print(
        "-> Finding: Slower intervals suggest potential manual interaction or rate-limited automated tooling."
    )

print(
    "\nAdvanced analysis complete! Credential tables and automation metrics generated."
)