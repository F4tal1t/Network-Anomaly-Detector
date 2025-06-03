import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Dense

def train_autoencoder(csv_path='flows.csv', model_path='autoencoder.h5'):
    df = pd.read_csv(csv_path)
    X = df[['duration', 'packet_count', 'byte_count', 'bytes_per_sec']].values

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    model = Sequential([
        Dense(16, activation='relu', input_shape=(X.shape[1],)),
        Dense(8, activation='relu'),
        Dense(16, activation='relu'),
        Dense(X.shape[1])
    ])

    model.compile(optimizer='adam', loss='mse')
    model.fit(X_scaled, X_scaled, epochs=50, batch_size=32, validation_split=0.1)

    # Predict reconstruction error
    reconstructions = model.predict(X_scaled)
    mse = np.mean(np.power(X_scaled - reconstructions, 2), axis=1)
    threshold = np.percentile(mse, 95)

    df['reconstruction_error'] = mse
    df['anomaly'] = mse > threshold

    df.to_csv('flows_with_errors.csv', index=False)
    model.save(model_path)

    print(f"[+] Autoencoder model saved to {model_path}")
    print(f"[+] Threshold: {threshold:.4f}")
    print(f"[+] Detected {sum(df['anomaly'])} anomalies")

    return model