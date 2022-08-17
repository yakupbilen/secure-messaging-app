import sqlite3
import os.path

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
db_path = os.path.join(BASE_DIR, "../users.db")

connection = sqlite3.connect(db_path)

cursor = connection.cursor()