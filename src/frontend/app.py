import logging
from flask import (
    Flask, render_template, request, redirect, url_for, flash, jsonify, session
)
from flask_httpauth import HTTPBasicAuth
from werkzeug.security import generate_password_hash, check_password_hash
import requests
from datetime import timedelta
from pymongo import MongoClient

from bountyforge.config import settings
from bountyforge.utils import init_logging

logger = logging.getLogger('web')
init_logging(logger)

app = Flask(__name__)
app.secret_key = settings.frontend.session_secret_key
app.config['PERMANENT_SESSION_LIFETIME'] =\
    timedelta(hours=settings.backend.session_lifetime)
app.config['SESSION_REFRESH_EACH_REQUEST'] = True

auth = HTTPBasicAuth()
users = {
    settings.frontend.auth_user: generate_password_hash(settings.frontend.auth_pass)  # noqa
}

BACKEND_URL = f"http://{settings.backend.host}:{settings.backend.port}"
if settings.backend.host == "0.0.0.0":
    BACKEND_URL = f"http://127.0.0.1:{settings.backend.port}"
INTERNAL_BACKEND_URL = f"http://{settings.frontend.backend_host}:{settings.backend.port}"  # noqa


@auth.verify_password
def verify_password(username, password):
    if (
        username in users
        and check_password_hash(users.get(username), password)
    ):
        return username


# @app.route("/login", methods=["GET", "POST"])
# def login():
#     if request.method == "POST":
#         username = request.form.get("username")
#         password = request.form.get("password")
#         if verify_password(username, password):
#             session["user"] = username
#             flash("Logged in successfully!", "success")
#             return redirect(url_for("dashboard"))
#         else:
#             flash("Invalid credentials", "danger")
#     return render_template("login.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        if not verify_password(username, password):
            flash("Invalid credentials", "danger")
            return redirect(url_for("login"))

        try:
            auth_response = requests.post(
                f"{INTERNAL_BACKEND_URL}/api/login",
                json={"username": username, "password": password},
                timeout=5
            )

            if auth_response.status_code == 200:
                session.permanent = True
                session["user"] = username
                session['jwt_token'] = auth_response.json()['access_token']
                flash("Logged in successfully!", "success")
                return redirect(url_for("dashboard"))

            flash("Backend authentication failed", "danger")

        except Exception as e:
            logger.error(f"Backend login error: {e}")
            flash("Backend login error, check logs", "danger")

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.pop("user", None)
    flash("Logged out", "info")
    return redirect(url_for("login"))


def login_required(f):
    from functools import wraps

    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user" not in session:
            flash("Please login first", "warning")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated_function


@app.context_processor
def inject_version():
    return {
        "project_version": settings.backend.project_version
    }


@app.route("/")
@login_required
def dashboard():
    return render_template(
        "dashboard.html",
        api_check_modules_url=f"{BACKEND_URL}/api/check_modules",
        api_start_scan_url=f"{BACKEND_URL}/api/start_scan",
        api_hosts_url=f"{BACKEND_URL}/api/hosts",
        api_last_scan_url=f"{BACKEND_URL}/api/scan/last",
        api_stats_url=f"{BACKEND_URL}/api/scan/stats"
    )


@app.route("/scan_settings", methods=["GET", "POST"])
@login_required
def scan_settings():
    return render_template(
        "scan_settings.html",
        api_get_config_url=f"{BACKEND_URL}/api/get_config",
        api_save_config_url=f"{BACKEND_URL}/api/save_config",
        api_update_nuclei_url=f"{BACKEND_URL}/api/update_nuclei",
        api_update_templates_url=f"{BACKEND_URL}/api/update_templates",
    )


# @app.route("/scan_history")
# @login_required
# def scan_history():
#     dummy_history = [
#         {"target": "example.com", "tool": "nmap", "result": "200 ports found", "timestamp": "2025-04-01 12:00"},  # noqa
#         {"target": "test.com", "tool": "httpx", "result": "HTTP 200", "timestamp": "2025-04-02 15:30"}  # noqa
#     ]
#     return render_template("scan_history.html", history=dummy_history)

@app.route("/scan_history")
@login_required
def scan_history():
    mongo = MongoClient(settings.backend.mongo_url)
    db = mongo.get_default_database()
    docs = db.scan_jobs\
             .find({"initiator": session["user"]}, {"_id": 0})\
             .sort("timestamp", -1)
    history = list(docs)
    return render_template("scan_history.html", history=history)


@app.route("/reports")
@login_required
def reports():
    dummy_reports = [
        {"report_id": 1, "title": "Report for 1", "date": "2025-04-01"},
        {"report_id": 2, "title": "Report for test.com", "date": "2025-04-02"}
    ]
    return render_template("reports.html", reports=dummy_reports)


@app.route('/scan/<scan_id>')
@login_required
def scan_details(scan_id):
    resp = requests.get(
        f"{INTERNAL_BACKEND_URL}/api/scan/{scan_id}",
        headers={"Authorization": "Bearer " + session['jwt_token']},
        timeout=15
    )
    if resp.status_code == 404:
        flash("Scan not found", "danger")
        return redirect(url_for("scan_history"))
    job = resp.json()

    # stream_url = f"{BACKEND_URL}/{job.get('stream_url')}"
    # print(job)
    # print(stream_url)

    return render_template(
        'scan_details.html',
        scan_id=scan_id,
        status=job.get("status", "unknown"),
        targets=job.get("targets", []),
        initiated=job.get("timestamp"),
        api_scan_meta_url=f"{BACKEND_URL}/api/scan/{scan_id}",
        api_scan_results_url=f"{BACKEND_URL}/api/scan_results/{scan_id}",
        stream_url=f"{BACKEND_URL}/api/scan/stream/{scan_id}",
    )


@app.route("/launch_scan")
@login_required
def launch_scan():
    return render_template("launch_scan.html")


@app.route('/upload_targets', methods=['POST'])
@login_required
def upload_targets():
    """
    Принимает файл с именем 'target_file', разбивает по строкам
    и возвращает JSON: { "targets": [ ... ] }
    """
    if 'target_file' not in request.files:
        return jsonify({'error': 'No file part'}), 400

    f = request.files['target_file']
    if f.filename == '':
        return jsonify({'error': 'No file selected'}), 400

    if not f.filename.lower().endswith('.txt'):
        return jsonify({'error': 'Only .txt files allowed'}), 400

    if not f.mimetype.startswith('text/'):
        return jsonify({'error': 'Invalid file type'}), 400

    MAX_FILE_SIZE = 3 * 1024 * 1024

    content_length = request.content_length
    if content_length and content_length > MAX_FILE_SIZE:
        return jsonify(
            {"error": f"File size exceeds the limit of {MAX_FILE_SIZE / (1024 * 1024)}MB"}  # noqa
        ), 400

    content = f.read().decode('utf-8', errors='ignore')
    lines = [line.strip() for line in content.splitlines() if line.strip()]
    return jsonify({'targets': lines}), 200


def create_app() -> Flask:
    """
    Create flask app
    """

    return app


if __name__ == "__main__":
    logger.info(
        f"Starting frontend server on: "
        f"{settings.frontend.host}:{settings.frontend.port}"
    )
    app.run(
        host=settings.frontend.host,
        port=settings.frontend.port,
        debug=settings.frontend.is_debug
    )
