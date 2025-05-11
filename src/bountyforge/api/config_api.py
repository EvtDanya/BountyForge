import logging
import shutil
import datetime
import redis
import validators
import json
from dataclasses import asdict
from flask import (
    Blueprint, jsonify, request, Response, url_for, stream_with_context
)
from werkzeug.security import generate_password_hash, check_password_hash
from bountyforge.config import settings
from flask_jwt_extended import (
  JWTManager, create_access_token, jwt_required, get_jwt_identity
)
from pymongo import MongoClient
from bountyforge.core import module_manager
from bountyforge.core import run_scan_task


logger = logging.getLogger(__name__)

config_api = Blueprint('config_api', __name__)
jwt = JWTManager()

users = {
    settings.frontend.auth_user: generate_password_hash(settings.frontend.auth_pass)  # noqa
}

redis_client = redis.Redis.from_url(settings.backend.celery_broker_url)


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
    try:
        cfg = asdict(settings)
        return jsonify(cfg), 200
    except Exception as ex:
        logger.exception(f"Error getting config: {ex}")
        return jsonify({"error": str(ex)}), 500


def update_dict(target, new_data):
    for key, value in new_data.items():
        if isinstance(value, dict):
            if key in target and isinstance(target.get(key), dict):
                update_dict(target[key], value)
            else:
                target[key] = value
        else:
            target[key] = value


@config_api.route('/api/save_config', methods=['POST'])
@jwt_required()
def save_config():
    """
    Save the configuration to YAML file and update the global settings object
    """
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "No data provided"}), 400

        if data.get("backend"):
            for key, val in data["backend"].items():
                if hasattr(settings.backend, key):
                    setattr(settings.backend, key, val)

        if data.get("scanners"):
            update_dict(settings.scanners.__dict__, data["scanners"])

        settings.save()
        logger.info(f"new settings: {settings}")

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


@config_api.route('/api/start_scan', methods=['POST'])
@jwt_required()
def start_scan():
    """
    Endpoint for starting a scan
    """
    data = request.get_json() or {}
    # headers = data.get('headers', {})
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

    #! TODO: exclude validation + usage
    # Здесь запускается фоновая задача, передаём только valid
    # task = run_scan_task.delay({ **data, "target": valid })

    job = run_scan_task.delay({**data, "target": valid})
    mongo = MongoClient(settings.backend.mongo_url)
    db = mongo.get_default_database()
    db.scan_jobs.insert_one({
        "job_id": job.id,
        "targets": valid,
        "exclude": invalid,
        "initiator": get_jwt_identity(),
        "timestamp": datetime.datetime.now(),
        "status": "queued"
    })

    stream_url = url_for(
        "config_api.scan_stream",
        job_id=job.id,
        _external=True
    )
    logger.info(f"Enqueued scan task: {job.id}")

    return jsonify({
        "message": "Scan job queued",
        "job_id": job.id,
        "stream_url": stream_url,
        "valid_targets": valid,
        "skipped_targets": invalid
    }), 202


@config_api.route('/api/scan/<job_id>', methods=['GET'])
@jwt_required()
def get_scan(job_id):
    """
    Вернёт мета-данные по скану: статус, targets, инициатор и т.п.
    """
    mongo = MongoClient(settings.backend.mongo_url)
    db = mongo.get_default_database()
    job = db.scan_jobs.find_one({"job_id": job_id}, {"_id": 0})
    if not job:
        return jsonify({"error": "Scan not found"}), 404

    logger.info(f"scan job: {job}")
    return jsonify({
        **job
        # "stream_url": url_for(
        #     "config_api.scan_stream",
        #     job_id=job_id
        # )
    }), 200


@config_api.route('/api/scan_results/<job_id>', methods=['GET'])
@jwt_required()
def get_scan_results(job_id):
    """
    Возвращает все записи из scan_results с этим job_id
    """
    client = MongoClient(settings.backend.mongo_url)
    db = client.get_default_database()
    cursor = db.scan_results.find(
        {"job_id": job_id},
        sort=[("timestamp", 1)],  # по времени, от старых к новым
        projection={"_id": 0}
    )
    results = list(cursor)
    return jsonify(results), 200


@config_api.route("/api/scan/stream/<job_id>")
# @jwt_required()
def scan_stream(job_id):
    channel = f"scan:{job_id}"

    def event_stream():
        pubsub = redis_client.pubsub()
        pubsub.subscribe(channel)
        try:
            for msg in pubsub.listen():
                if msg['type'] != 'message':
                    continue
                data = msg['data'].decode('utf-8')
                yield f"data: {data}\n\n"
                obj = json.loads(data)
                if obj.get("event") == "finished":
                    break
        finally:
            pubsub.close()

    return Response(
        stream_with_context(event_stream()),
        mimetype='text/event-stream'
    )


@config_api.route('/api/scan/last', methods=['GET'])
@jwt_required()
def get_last_scan():
    """
    Return metadata for the most recent scan of the current user
    """
    db = MongoClient(settings.backend.mongo_url).get_default_database()
    user = get_jwt_identity()
    job = db.scan_jobs.find_one(
        {"initiator": user},
        sort=[("timestamp", -1)]
    )
    if not job:
        return jsonify({}), 200

    cnt = db.scan_results.count_documents({"job_id": job["job_id"]})
    return jsonify({
        "job_id": job["job_id"],
        "targets": job["targets"],
        "timestamp": job["timestamp"].isoformat(),
        "status": job["status"],
        "result_count": cnt
    }), 200


@config_api.route('/api/scan/stats', methods=['GET'])
@jwt_required()
def get_stats():
    """
    Return scan statistics for the current user for the last 7 days
    """
    db = MongoClient(settings.backend.mongo_url).get_default_database()
    user = get_jwt_identity()
    now = datetime.datetime.now()
    week_ago = now - datetime.timedelta(days=7)

    scans_today = db.scan_jobs.count_documents({
        "initiator": user,
        "timestamp": {"$gte": week_ago}
    })

    total_targets = 0
    for job in db.scan_jobs.find({
        "initiator": user,
        "timestamp": {"$gte": week_ago}
    }, {"targets": 1}):
        total_targets += len(job.get("targets", []))

    return jsonify({
        "scans_last_7_days":   scans_today,
        "targets_last_7_days": total_targets
    }), 200


@config_api.route('/api/check_modules', methods=['GET'])
@jwt_required()
def check_modules():
    statuses = module_manager.check_availability()
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


@config_api.route('/api/update_nuclei', methods=['POST'])
@jwt_required()
def update_nuclei():
    try:
        module = module_manager.get_module("nuclei")  # NucleiModule
        module.update_nuclei()
        return jsonify({"message": "Nuclei updated"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@config_api.route('/api/update_templates', methods=['POST'])
@jwt_required()
def update_templates():
    try:
        module = module_manager.get_module("nuclei")  # NucleiModule
        module.update_templates()
        return jsonify({"message": "Templates updated"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500
