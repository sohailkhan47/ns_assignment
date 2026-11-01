import pandas as pd
import glob
import os

# 1. Path to your files (assumes they are in your current working directory)
# This matches any file starting with 'h' followed by a number and ending in .csv
csv_files = glob.glob("data/honeytrap/suricata/h*.csv")

# Sort files naturally so h1, h2, h3 align chronologically instead of alphabetically
csv_files.sort(key=lambda f: int(''.join(filter(str.isdigit, f)) or 0))

print(f"Found {len(csv_files)} chunk files to merge.")

# 2. Loop through and read each CSV file into a list of DataFrames
dataframe_list = []
for file in csv_files:
    try:
        df = pd.read_csv(file)
        dataframe_list.append(df)
        print(f"Successfully loaded: {file} ({len(df):,} rows)")
    except Exception as e:
        print(f"⚠️ Error reading {file}: {e}")

# 3. Vertically concatenate all DataFrames into one master dataset
if dataframe_list:
    master_df = pd.concat(dataframe_list, ignore_index=True)
    
    print("\n------------------------------------------------")
    print(f"✅ Success! Combined Dataset Summary:")
    print(f"Total Rows Loaded: {len(master_df):,}")
    print(f"Total Columns: {len(master_df.columns)}")
    
    # 4. Save the combined master file
    output_filename = "data/honeytrap/suricata/suricata_merged.csv"
    master_df.to_csv(output_filename, index=False)
    print(f"Master file saved as: {output_filename}")
    print("------------------------------------------------")
else:
    print("❌ No valid CSV files were loaded. Check your file paths.")
