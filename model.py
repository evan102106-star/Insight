from sklearn.ensemble import IsolationForest
import numpy as np

# ---------------- TRAIN DATA ----------------
# Represents normal user behavior
data = np.array([
    [9, 5, 2],
    [10, 4, 2],
    [11, 6, 3],
    [10, 5, 2],
    [9, 4, 1],
])

# ---------------- MODEL ----------------
model = IsolationForest(contamination=0.2)
model.fit(data)


# ---------------- PREDICTION FUNCTION ----------------
def predict_risk(user_input):
    """
    Predicts risk level and score based on user behavior

    Input:
        user_input = [login_hour, files, apps]

    Output:
        ("HIGH"/"LOW", score)
    """

    # Ensure numeric input
    user_input = list(map(int, user_input))

    # Model prediction
    pred = model.predict([user_input])[0]

    # Basic scoring logic
    if pred == -1:
        return "HIGH", 75
    else:
        return "LOW", 30
