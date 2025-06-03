import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt
import os

def generate_anomaly_plot(csv_path='flows_with_labels.csv', output_image='anomaly_plot.png'):
    """
    Generates and saves a visual plot of anomalies from CSV data
    """
    if not os.path.exists(csv_path):
        print(f"[-] File not found: {csv_path}")
        return None

    df = pd.read_csv(csv_path)

    # Plotting
    plt.figure(figsize=(10, 6))
    sns.scatterplot(data=df, x='duration', y='byte_count', hue='anomaly',
                    palette={1: 'blue', -1: 'red'}, alpha=0.8)
    plt.title("Network Flows: Normal vs Anomalous", fontsize=14)
    plt.xlabel("Flow Duration (s)", fontsize=12)
    plt.ylabel("Byte Count", fontsize=12)
    plt.legend(title="Anomaly", labels=["Normal", "Anomalous"])
    plt.tight_layout()
    plt.savefig(output_image, dpi=200, bbox_inches='tight')
    plt.close()

    print(f"[+] Saved visualization to `{output_image}`")
    return output_image