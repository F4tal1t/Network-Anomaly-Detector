import os
import pandas as pd
from extract_features import generate_flow_dataset
from train_model import train_anomaly_model
from save_anomalies import save_anomalies_to_txt
from mitre_mapper import map_anomaly_to_mitre
from generate_report import generate_pdf_report


def get_pcap_filename():
    print("📁 Available PCAP files in current directory:")
    pcap_files = [f for f in os.listdir() if f.endswith(".pcap")]
    if not pcap_files:
        print("[-] No .pcap files found. Please place one in this folder.")
        exit()

    for i, f in enumerate(pcap_files):
        print(f"{i+1}. {f}")

    choice = int(input("\nEnter the number of the .pcap file you want to analyze: ")) - 1
    return pcap_files[choice]


def create_output_folder(pcap_name):
    folder_name = f"results_{pcap_name.split('.')[0]}"
    os.makedirs(folder_name, exist_ok=True)
    print(f"[+] Created output folder: {folder_name}")
    return folder_name


def run_full_pipeline():
    # Step 1: Get PCAP filename
    pcap_file = get_pcap_filename()
    pcap_name = pcap_file.replace(".pcap", "")
    output_folder = create_output_folder(pcap_file)

    # Define paths
    flows_path = os.path.join(output_folder, f"{pcap_name}_flows.csv")
    labeled_path = os.path.join(output_folder, f"{pcap_name}_flows_with_labels.csv")
    txt_path = os.path.join(output_folder, f"{pcap_name}_anomalies.txt")
    pdf_path = os.path.join(output_folder, f"{pcap_name}_report.pdf")

    # Step 2: Extract features from PCAP
    print("[*] Step 1: Extracting flow features...")
    df = generate_flow_dataset(pcap_file, flows_path)

    # Step 3: Train model & label anomalies
    print("[*] Step 2: Detecting anomalies...")
    train_anomaly_model(flows_path, model_path=None)  # Skip saving model

    # Step 4: Check if labeled CSV exists
    if not os.path.exists(labeled_path):
        print(f"[-] File not found: {labeled_path}")
        print("Make sure `train_model.py` is working correctly.")
        exit()

    df_labeled = pd.read_csv(labeled_path)
    print(f"[+] Loaded {len(df_labeled)} flows with anomaly labels")

    # Step 5: Save anomalies to TXT
    print("[*] Step 3: Saving detected anomalies to text file...")
    save_anomalies_to_txt(labeled_path, txt_path)

    # Step 6: Generate PDF Report
    print("[*] Step 4: Generating PDF report...")
    anomalies = df_labeled[df_labeled['anomaly'] == -1]
    generate_pdf_report(anomalies, pdf_path, labeled_path)

    print("\n✅ All files saved in:", output_folder)
    print("🎉 Done! You can now review your results.")


if __name__ == "__main__":
    run_full_pipeline()