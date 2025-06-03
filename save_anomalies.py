import pandas as pd
import os

def save_anomalies_to_txt(csv_path='flows_with_labels.csv', output_file='detected_anomalies.txt'):
    if not os.path.exists(csv_path):
        print(f"[-] File not found: {csv_path}")
        return

    df = pd.read_csv(csv_path)

    # Filter only anomalies
    anomalies = df[df['anomaly'] == -1]

    if anomalies.empty:
        print("[-] No anomalies found to save.")
        return

    # Ensure output folder exists
    os.makedirs(os.path.dirname(output_file), exist_ok=True)

    # Save anomalies with UTF-8 encoding
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write("🚨 Detected Anomalies\n")
        f.write("="*50 + "\n\n")

        for idx, row in anomalies.iterrows():
            f.write(f"Flow #{idx}\n")
            f.write("-" * 30 + "\n")
            f.write(f"Source IP      : {row.get('src', 'N/A')}\n")
            f.write(f"Destination IP : {row.get('dst', 'N/A')}\n")
            f.write(f"Protocol       : {row.get('proto', 'N/A')}\n")
            f.write(f"Duration       : {row.get('duration', 'N/A'):.2f} sec\n")
            f.write(f"Packets        : {row.get('packet_count', 'N/A')}\n")
            f.write(f"Bytes          : {row.get('byte_count', 'N/A')}\n")
            f.write(f"Bytes/sec      : {row.get('bytes_per_sec', 'N/A'):.2f}\n\n")

    print(f"[+] Saved {len(anomalies)} anomalies to `{output_file}`")