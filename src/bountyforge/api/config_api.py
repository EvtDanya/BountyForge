import logging
import shutil
import datetime
from flask import Blueprint, jsonify, request
from werkzeug.security import generate_password_hash, check_password_hash
from bountyforge.config import settings, Config
from flask_jwt_extended import (
  JWTManager, create_access_token, jwt_required
)

logger = logging.getLogger(__name__)

config_api = Blueprint('config_api', __name__)
jwt = JWTManager()

users = {
    settings.frontend.auth_user: generate_password_hash(settings.frontend.auth_pass)  # noqa
}


def verify_password(username, password):
    if (
        username in users
        and check_password_hash(users.get(username), password)
    ):
        return username


@config_api.route('/api/login', methods=['POST'])
def api_login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not verify_password(username, password):
        return jsonify({"error": "Invalid credentials"}), 401
    access_token = create_access_token(
        identity=username,
        expires_delta=datetime.timedelta(
            hours=settings.backend.session_lifetime
        )
    )
    print(f"Access token: {access_token}")
    return jsonify(access_token=access_token), 200


@config_api.route('/api/get_config', methods=['GET'])
@jwt_required()
def get_config():
    """
    Return the current configuration as JSON
    """
    # current_user = get_jwt_identity()
    try:
        return jsonify(settings), 200
    except Exception as ex:
        logger.exception(f"Error getting config: {ex}")
        return jsonify({"error": str(ex)}), 500


@config_api.route('/api/save_config', methods=['POST'])
@jwt_required()
def save_config():
    """
    Save the configuration to YAML file and update the global settings object
    """
    # current_user = get_jwt_identity()
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "No data provided"}), 400

        if "scanners" in data:
            settings.scanners =\
                Config(**{"scanners": data["scanners"]}).scanners

        settings.save()

        return jsonify({"message": "Configuration saved successfully"}), 200
    except Exception as ex:
        logger.exception(f"Error saving config: {ex}")
        return jsonify({"error": str(ex)}), 500


@config_api.route('/api/start_scan', methods=['POST'])
@jwt_required()
def start_scan():
    """
    Endpoint for starting a scan
    """
    # data = request.get_json()
    # task = run_scan_task.delay(data)  # Запуск задачи в фоне
    return jsonify({"message": "\"><img src=x onerror=alert()>"}), 202


@config_api.route('/api/check_modules', methods=['GET'])
@jwt_required()  # или @login_required
def check_modules():
    # Здесь логика проброса по всем модулям: вызываете ping() или dry‑run
    # statuses = {
    #     'nmap':   engine.check('nmap'),
    #     'subfinder': engine.check('subfinder'),
    #     'httpx': engine.check('httpx'),
    #     # ... остальные модули ...
    # }
    return jsonify(
        {"test": False, "test2": True, "test3": False}
    ), 200


@config_api.route('/api/hosts', methods=['GET'])
@jwt_required()
def get_hosts():
    try:
        with open('/etc/hosts', 'r') as f:
            content = f.read()
        return jsonify({"hosts": content}), 200
    except Exception as ex:
        logger.exception("Error reading /etc/hosts")
        return jsonify({"error": str(ex)}), 500


@config_api.route('/api/hosts', methods=['POST'])
@jwt_required()
def save_hosts():
    data = request.get_json()
    new_content = data.get('hosts')
    if new_content is None:
        return jsonify({"error": "No hosts content provided"}), 400
    try:
        # create backup of the original /etc/hosts file
        shutil.copy('/etc/hosts', '/etc/hosts.bak')

        with open('/etc/hosts', 'w') as f:
            f.write(new_content)
        return jsonify({"message": "Hosts updated successfully"}), 200
    except Exception as ex:
        logger.exception("Error writing /etc/hosts")
        return jsonify({"error": str(ex)}), 500
