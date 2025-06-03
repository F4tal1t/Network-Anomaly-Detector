import pandas as pd
from sklearn.ensemble import IsolationForest
import joblib
import os

def train_anomaly_model(csv_path='flows.csv', model_path=None):
    if model_path is None:
        model_path = os.path.join(os.path.dirname(csv_path), "anomaly_model.pkl")

    df = pd.read_csv(csv_path)

    X = df[['duration', 'packet_count', 'byte_count', 'bytes_per_sec']]
    model = IsolationForest(n_estimators=100, contamination=0.05)
    model.fit(X)

    df['anomaly'] = model.predict(X)

    # Save output in same folder as input CSV
    labeled_path = csv_path.replace(".csv", "_with_labels.csv")
    df.to_csv(labeled_path, index=False)

    joblib.dump(model, model_path)

    print(f"[+] Anomalies saved to `{labeled_path}`")
    print(f"[+] Model saved to `{model_path}`")
    print(f"[+] Detected {sum(df['anomaly'] == -1)} anomalies")

    return model