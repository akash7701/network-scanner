import sqlite3

def init_db():
    conn = sqlite3.connect('scans.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS scan_results (
            id INTEGER PRIMARY KEY,
            ip TEXT,
            port INTEGER,
            banner TEXT,
            cve_count INTEGER
        )
    ''')
    conn.commit()
    conn.close()

def store_scan_result(ip, port, banner, cve_count):
    conn = sqlite3.connect('scans.db')
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO scan_results (ip, port, banner, cve_count)
        VALUES (?, ?, ?, ?)
    ''', (ip, port, banner, cve_count))
    conn.commit()
    conn.close()

def query_scan_results():
    conn = sqlite3.connect('scans.db')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM scan_results')
    results = cursor.fetchall()
    conn.close()
    return results
