import psycopg2
import os
from psycopg2.extras import RealDictCursor

DB_CONFIG = {
    "dbname": "forensics_llm",
    "user": "postgres",
    "password": os.getenv("DB_PASSWORD", "root"),
    "host": "localhost",
    "port": "5432"
}

def get_connection():
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        return conn
    except Exception as e:
        print(f" Erreur connexion DB : {e}")
        raise

def get_cursor(conn):
    return conn.cursor(cursor_factory=RealDictCursor)