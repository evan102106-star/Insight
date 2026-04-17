from flask import Flask, request, jsonify, render_template, redirect, url_for
import pandas as pd
from sqlalchemy import create_engine, text, bindparam

app = Flask(__name__)

# ---------------- DB ----------------
engine = create_engine("mysql+mysqlconnector://asad:1234@localhost:3000/hack")


# ---------------- ANOMALY DETECTION ----------------
def detect_anomalies():

    sessions = pd.read_sql("SELECT * FROM sessions", engine)
    files = pd.read_sql("SELECT * FROM file_activity", engine)

    if sessions.empty:
        return []

    # LOGIN TIME
    sessions['login_hour'] = pd.to_datetime(sessions['login_time']).dt.hour
    mean_login = sessions['login_hour'].mean()
    std_login = sessions['login_hour'].std()

    sessions['login_anomaly'] = abs(sessions['login_hour'] - mean_login) > std_login

    # SESSION DURATION
    sessions['login_time'] = pd.to_datetime(sessions['login_time'])
    sessions['logout_time'] = pd.to_datetime(sessions['logout_time'])

    sessions['duration'] = (
        sessions['logout_time'] - sessions['login_time']
    ).dt.total_seconds().fillna(0)

    mean_dur = sessions['duration'].mean()
    std_dur = sessions['duration'].std()

    sessions['duration_anomaly'] = abs(sessions['duration'] - mean_dur) > std_dur

    # FILE ACTIVITY
    if not files.empty:
        file_counts = files.groupby('session_id').size().reset_index(name='file_count')

        mean_files = file_counts['file_count'].mean()
        std_files = file_counts['file_count'].std()

        file_counts['file_anomaly'] = file_counts['file_count'] > mean_files + std_files

        sessions = sessions.merge(
            file_counts,
            left_on='id',
            right_on='session_id',
            how='left'
        )
    else:
        sessions['file_anomaly'] = False

    # FINAL SCORE
    sessions['risk_score'] = (
        sessions['login_anomaly'].astype(int) +
        sessions['duration_anomaly'].astype(int) +
        sessions['file_anomaly'].fillna(False).astype(int)
    )

    suspicious = sessions[sessions['risk_score'] >= 2]

    return suspicious.to_dict(orient='records')


# ---------------- HOME ----------------
@app.route('/')
def dashboard():
    suspicious = detect_anomalies()
    return render_template("index.html", suspicious=suspicious)


# ---------------- USER DETAIL ----------------
@app.route('/user/<username>')
def user_detail(username):

    with engine.connect() as conn:

        sessions = pd.read_sql(
            text("SELECT * FROM sessions WHERE username=:u"),
            conn,
            params={"u": username}
        )

        if sessions.empty:
            return render_template("index.html", suspicious=[], error="User not found")

        session_ids = sessions['id'].tolist()

        if not session_ids:
            return render_template("index.html", suspicious=[], error="No sessions found")

        # -------- FIXED IN QUERY --------
        files = pd.read_sql(
            text("SELECT * FROM file_activity WHERE session_id IN :ids")
            .bindparams(bindparam("ids", expanding=True)),
            conn,
            params={"ids": session_ids}
        )

        network = pd.read_sql(
            text("SELECT * FROM network_activity WHERE session_id IN :ids")
            .bindparams(bindparam("ids", expanding=True)),
            conn,
            params={"ids": session_ids}
        )

        usb = pd.read_sql(
            text("SELECT * FROM usb_usage WHERE session_id IN :ids")
            .bindparams(bindparam("ids", expanding=True)),
            conn,
            params={"ids": session_ids}
        )

        apps = pd.read_sql(
            text("SELECT * FROM app_usage WHERE session_id IN :ids")
            .bindparams(bindparam("ids", expanding=True)),
            conn,
            params={"ids": session_ids}
        )

    return render_template(
        "user.html",
        username=username,
        sessions=sessions.to_dict(orient="records"),
        files=files.to_dict(orient="records"),
        network=network.to_dict(orient="records"),
        usb=usb.to_dict(orient="records"),
        apps=apps.to_dict(orient="records")
    )


# ---------------- SEARCH ----------------
@app.route('/search', methods=['POST'])
def search_user():
    username = request.form.get('username')

    if not username:
        return redirect(url_for('dashboard'))

    return redirect(url_for('user_detail', username=username))


# ---------------- API ROUTES ----------------
@app.route('/start_session', methods=['POST'])
def start_session():
    data = request.json

    with engine.begin() as conn:
        result = conn.execute(
            text("INSERT INTO sessions (username, system_id, login_time) VALUES (:u, :s, NOW())"),
            {"u": data['username'], "s": data['system_id']}
        )
        session_id = result.lastrowid

    return jsonify({"session_id": session_id})


@app.route('/end_session', methods=['POST'])
def end_session():
    data = request.json

    with engine.begin() as conn:
        conn.execute(
            text("UPDATE sessions SET logout_time = NOW() WHERE id=:id"),
            {"id": data['session_id']}
        )

    return jsonify({"status": "ended"})


@app.route('/app_usage', methods=['POST'])
def app_usage():
    data = request.json

    with engine.begin() as conn:
        conn.execute(
            text("INSERT INTO app_usage (session_id, app_name, usage_time) VALUES (:sid, :app, :time)"),
            {"sid": data['session_id'], "app": data['app_name'], "time": data['usage_time']}
        )

    return jsonify({"status": "ok"})


@app.route('/usb_usage', methods=['POST'])
def usb_usage():
    data = request.json

    with engine.begin() as conn:
        conn.execute(
            text("""INSERT INTO usb_usage 
            (session_id, device_name, start_time, end_time, duration)
            VALUES (:sid, :dev, :start, :end, :dur)"""),
            {
                "sid": data['session_id'],
                "dev": data['device_name'],
                "start": data['start_time'],
                "end": data['end_time'],
                "dur": data['duration']
            }
        )

    return jsonify({"status": "ok"})


@app.route('/network_activity', methods=['POST'])
def network_activity():
    data = request.json

    with engine.begin() as conn:
        conn.execute(
            text("""INSERT INTO network_activity 
            (session_id, bytes_sent, bytes_received, connections, timestamp)
            VALUES (:sid, :s, :r, :c, NOW())"""),
            {
                "sid": data['session_id'],
                "s": data['bytes_sent'],
                "r": data['bytes_received'],
                "c": data['connections']
            }
        )

    return jsonify({"status": "ok"})


@app.route('/file_activity', methods=['POST'])
def file_activity():
    data = request.json

    with engine.begin() as conn:
        conn.execute(
            text("""INSERT INTO file_activity 
            (session_id, file_path, file_size, event_type, timestamp)
            VALUES (:sid, :path, :size, :type, NOW())"""),
            {
                "sid": data['session_id'],
                "path": data['file_path'],
                "size": data['file_size'],
                "type": data['event_type']
            }
        )

    return jsonify({"status": "ok"})


# ---------------- RUN ----------------
if __name__ == "__main__":
    app.run(debug=True)