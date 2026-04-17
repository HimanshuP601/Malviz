import sqlite3
import os
import json
import datetime

DB_PATH = os.path.join(os.path.dirname(__file__), "threats.db")

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS suspected_processes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            pid INTEGER,
            name TEXT,
            path TEXT,
            username TEXT,
            parent_pid INTEGER,
            parent_name TEXT,
            timestamp TEXT,
            threat_severity TEXT,
            reasons TEXT,
            network_connections TEXT
        )
    """)
    conn.commit()
    conn.close()

def log_threat(threat_data):
    """
    threat_data should be a dict containing:
    pid, name, path, username, parent_pid, parent_name, threat_severity, reasons (list), network_connections (list)
    """
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    timestamp = datetime.datetime.now().isoformat()
    cursor.execute("""
        INSERT INTO suspected_processes 
        (pid, name, path, username, parent_pid, parent_name, timestamp, threat_severity, reasons, network_connections)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        threat_data.get('pid'),
        threat_data.get('name'),
        threat_data.get('path'),
        threat_data.get('username'),
        threat_data.get('parent_pid'),
        threat_data.get('parent_name'),
        timestamp,
        threat_data.get('threat_severity'),
        json.dumps(threat_data.get('reasons', [])),
        json.dumps(threat_data.get('network_connections', []))
    ))
    conn.commit()
    conn.close()

def get_history():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM suspected_processes ORDER BY timestamp DESC LIMIT 100")
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]

if __name__ == '__main__':
    init_db()
