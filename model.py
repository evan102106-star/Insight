from sklearn.ensemble import IsolationForest
import numpy as np

# Train model with dummy normal behavior
data = np.array([
    [9, 5, 2],
    [10, 4, 2],
    [11, 6, 3],
    [10, 5, 2],
    [9, 4, 1],
])

model = IsolationForest(contamination=0.2)
model.fit(data)

def predict_risk(user_input):
    pred = model.predict([user_input])[0]

    if pred == -1:
        return "HIGH"
    else:
        return "LOW"
🔌 2. BACKEND — API (app.py)
from flask import Flask, request, jsonify
from model import predict_risk

app = Flask(__name__)

@app.route("/analyze", methods=["POST"])
def analyze():
    data = request.json

    login_hour = data["login_hour"]
    files = data["files"]
    apps = data["apps"]

    risk, score = predict_risk([login_hour, files, apps])

    reason = []

    if login_hour < 6 or login_hour > 22:
        reason.append("Unusual login time")
    if files > 20:
        reason.append("High file access")
    if apps > 5:
        reason.append("Unusual app usage")

  return jsonify({
    "risk": risk,
    "score": score,
    "reason": reason
})

if __name__ == "__main__":
    app.run(debug=True)
