from sklearn.ensemble import IsolationForest
import numpy as np

data = np.array([
    [9, 5, 2],
    [10, 4, 2],
    [11, 6, 3],
    [10, 5, 2],
    [9, 4, 1],
    [12, 6, 3],
    [8, 3, 2],
    [9, 5, 3],
    [10, 4, 1],
    [11, 5, 2],
    [9, 6, 2],
    [10, 5, 3]
])

model = IsolationForest(contamination=0.1, random_state=42)
model.fit(data)


def predict_risk(user_input):
   
    login, files, apps = map(int, user_input)

    pred = model.predict([[login, files, apps]])[0]
    score_raw = model.decision_function([[login, files, apps]])[0]


    risk_score = int(50 - score_raw * 100)
    risk_score = max(0, min(100, risk_score))


    unusual_login = (login < 6 or login > 22)
    high_files = (files > 30)
    high_apps = (apps > 7)

    if unusual_login and high_files and high_apps:
        return "HIGH", 90


    if (unusual_login and high_files) or (high_files and high_apps):
        return "HIGH", 85

    if unusual_login and high_apps:
        return "HIGH", 80

  
    if unusual_login:
        return "HIGH", 75

    if high_files:
        return "HIGH", 80

    if high_apps:
        return "MEDIUM", 70  

    if pred == -1:
        return "MEDIUM", risk_score
    else:
        return "LOW", risk_score
