from sklearn.ensemble import IsolationForest


def train_anomaly_model():
    """
    Train a simple anomaly detection model on normal system behavior.
    Features:
    [file_changes, file_deletions, event_rate]
    """

    normal_data = [
        [1, 0, 1],
        [2, 0, 2],
        [1, 1, 2],
        [3, 0, 3],
        [2, 1, 3],
        [1, 0, 2],
        [2, 0, 1],
        [3, 1, 4],
        [2, 1, 2],
        [1, 0, 1]
    ]

    model = IsolationForest(contamination=0.2, random_state=42)
    model.fit(normal_data)

    return model