# from flask import Blueprint, request, jsonify
# from bountyforge.tasks import run_scan_task

# scan_api = Blueprint('scan_api', __name__)


# @scan_api.route('/api/start_scan', methods=['POST'])
# def start_scan():
#     """
#     Endpoint for starting a scan
#     """
#     data = request.get_json()
#     task = run_scan_task.delay(data)  # Запуск задачи в фоне
#     return jsonify({"message": "Scan started", "task_id": task.id}), 202
