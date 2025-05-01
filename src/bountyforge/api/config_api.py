import logging
import shutil
import datetime
import validators
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


def is_valid_target(entry: str) -> bool:
    """
    Validate that entry is one of:
      - a valid IPv4 address
      - a valid domain name
      - a valid URL
    """
    if not isinstance(entry, str) or not entry:
        return False

    return (
        validators.ipv4(entry) or
        validators.domain(entry) or
        validators.url(entry)
    )


def filter_valid(entries):
    """
    Filter a list of strings through is_valid_target(),
    returning (valid_list, skipped_list)
    """
    valid, skipped = [], []
    for e in entries:
        if is_valid_target(e):
            valid.append(e)
        else:
            skipped.append(e)
    return valid, skipped


# @config_api.route('/api/start_scan', methods=['POST'])
# @jwt_required()
# def start_scan():
#     """
#     Endpoint for starting a scan
#     """
#     data = request.get_json()
#     logger.info(data)
#     if not data:
#         return jsonify({"error": "No data provided"}), 400

#     target = data.get("target", [])
#     if not isinstance(target, list) or not target:
#         return jsonify({"error": "Invalid hosts for scanning"}), 400
#     # if not check_hosts_for_scan(data.get("target", [])):
#     #     return jsonify({"error": "Invalid hosts for scanning"}), 400

#     filtered_hosts = list(filter(validators.domain, target))
#     not_hosts = list(set(target) - set(filtered_hosts))
#     if not filtered_hosts:
#         logger.warning(f"No valid hosts provided: {not_hosts}")
#         return jsonify({"error": "No valid hosts provided"}), 400

#     if not_hosts:
#         logger.warning(f"Invalid hosts: {not_hosts}")

#     # task = run_scan_task.delay(data)  # Запуск задачи в фоне
#     return jsonify({"message": "OK"}), 202


@config_api.route('/api/start_scan', methods=['POST'])
@jwt_required()
def start_scan():
    """
    Endpoint for starting a scan
    """
    data = request.get_json() or {}
    logger.info(f"Received scan request: {data}")

    raw = data.get("target")
    if not isinstance(raw, list) or not raw:
        return jsonify({"error": "Invalid or empty 'target' list"}), 400

    valid = []
    invalid = []
    for entry in raw:
        if is_valid_target(entry):
            valid.append(entry)
        else:
            invalid.append(entry)

    if not valid:
        logger.warning(
            f"No valid targets provided, all invalid: {invalid}"
        )
        return jsonify({"error": "No valid targets provided"}), 400

    if invalid:
        logger.warning(
            f"Some targets are invalid and will be skipped: {invalid}"
        )

    # Здесь запускается фоновая задача, передаём только valid
    # task = run_scan_task.delay({ **data, "target": valid })

    return jsonify({
        "message": "Scan job queued",
        "valid_targets": valid,
        "skipped_targets": invalid
    }), 202


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
    statuses = {
        "nmap": True,
        "subfinder": True,
        "httpx": False,
        # ...
    }

    return jsonify(statuses), 200


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
