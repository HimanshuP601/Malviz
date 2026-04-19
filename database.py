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
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS daily_escalations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source TEXT,
            target TEXT,
            method TEXT,
            privilege TEXT,
            timestamp TEXT
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

def log_escalation(escalation_data):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    timestamp = datetime.datetime.now().isoformat()
    
    # Insert new escalation
    cursor.execute("""
        INSERT INTO daily_escalations (source, target, method, privilege, timestamp)
        VALUES (?, ?, ?, ?, ?)
    """, (
        escalation_data.get('source'),
        escalation_data.get('target'),
        escalation_data.get('method'),
        escalation_data.get('privilege'),
        timestamp
    ))
    
    # Delete old escalations (older than 24 hours)
    one_day_ago = (datetime.datetime.now() - datetime.timedelta(days=1)).isoformat()
    cursor.execute("DELETE FROM daily_escalations WHERE timestamp < ?", (one_day_ago,))
    conn.commit()
    conn.close()

def get_recent_escalations():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    # Ensure we only fetch last 24 hours, even if deletion somehow failed
    one_day_ago = (datetime.datetime.now() - datetime.timedelta(days=1)).isoformat()
    cursor.execute("SELECT * FROM daily_escalations WHERE timestamp >= ? ORDER BY timestamp DESC", (one_day_ago,))
    rows = cursor.fetchall()
    conn.close()
    
    # Format backward to match frontend expectations
    results = []
    for row in rows:
        d = dict(row)
        # Parse timestamp back to HH:MM:SS for the UI
        try:
            d['time'] = datetime.datetime.fromisoformat(d['timestamp']).strftime("%H:%M:%S")
        except:
            d['time'] = d['timestamp']
        results.append(d)
        
    return results

if __name__ == '__main__':
    init_db()
