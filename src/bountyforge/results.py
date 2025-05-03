import os
from pymongo import MongoClient
import pandas as pd
from bountyforge.config import settings


def fetch_all_results():
    # Берём URL из переменной окружения или из настроек
    mongo_url = "mongodb://admin:admin@localhost:27017/bountyforge"
    # Добавляем authSource для аутентификации в админ-базе
    if "authSource" not in mongo_url:
        sep = "&" if "?" in mongo_url else "?"
        mongo_url = f"{mongo_url}{sep}authSource=admin"
    print("→ connecting to", mongo_url)

    client = MongoClient(mongo_url)
    # Явно берём базу "bountyforge"
    db = client["bountyforge"]

    cursor = db.scan_results.find().sort("timestamp", 1)
    docs = list(cursor)
    if not docs:
        print("No scan results found.")
        return

    # Убираем _id, если не нужен
    for d in docs:
        d.pop("_id", None)

    df = pd.DataFrame(docs)
    print(df)

if __name__ == "__main__":
    fetch_all_results()
