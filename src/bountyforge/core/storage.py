import datetime
from pymongo import MongoClient
from bountyforge.config import settings


class ResultStorage:
    def __init__(self):
        self.client = MongoClient(settings.mongo_url)
        self.db = self.client.bountyforge

    def save_scan_result(self, task_id, results):
        self.db.scans.insert_one({
            "task_id": task_id,
            "status": "completed",
            "results": results,
            "timestamp": datetime.now()
        })

    def get_scan_result(self, task_id):
        return self.db.scans.find_one({"task_id": task_id})