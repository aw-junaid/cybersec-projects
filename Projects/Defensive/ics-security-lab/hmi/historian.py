#!/usr/bin/env python3
"""
Mock Historian for ICS Security Lab
Stores telemetry data in SQLite for analysis
"""

import sqlite3
import json
import time
import os
from datetime import datetime

class LabHistorian:
    """Safe telemetry historian for lab environment"""
    
    def __init__(self, db_path=":memory:"):
        self.db_path = db_path
        self.init_database()
    
    def init_database(self):
        """Initialize database schema"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS telemetry (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                source_ip TEXT,
                tag_name TEXT,
                value REAL,
                quality INTEGER
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS security_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                event_type TEXT,
                source_ip TEXT,
                description TEXT,
                severity TEXT
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def record_telemetry(self, source_ip, tag_name, value, quality=192):
        """Record telemetry data point"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO telemetry (timestamp, source_ip, tag_name, value, quality)
            VALUES (?, ?, ?, ?, ?)
        ''', (datetime.now(), source_ip, tag_name, value, quality))
        
        conn.commit()
        conn.close()
    
    def record_security_event(self, event_type, source_ip, description, severity="medium"):
        """Record security event"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO security_events (timestamp, event_type, source_ip, description, severity)
            VALUES (?, ?, ?, ?, ?)
        ''', (datetime.now(), event_type, source_ip, description, severity))
        
        conn.commit()
        conn.close()
    
    def export_data(self, output_file):
        """Export all data to JSON file"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Export telemetry
        cursor.execute('SELECT * FROM telemetry')
        telemetry_data = [dict(zip([col[0] for col in cursor.description], row)) 
                         for row in cursor.fetchall()]
        
        # Export security events
        cursor.execute('SELECT * FROM security_events')
        security_data = [dict(zip([col[0] for col in cursor.description], row)) 
                        for row in cursor.fetchall()]
        
        export = {
            'telemetry': telemetry_data,
            'security_events': security_data,
            'export_time': datetime.now().isoformat()
        }
        
        with open(output_file, 'w') as f:
            json.dump(export, f, indent=2)
        
        conn.close()

def main():
    """Demo the historian"""
    historian = LabHistorian("lab_historian.db")
    
    # Record some sample data
    historian.record_telemetry("172.20.0.10", "Temperature", 75.5)
    historian.record_telemetry("172.20.0.10", "Pressure", 250.2)
    historian.record_security_event("unusual_write", "172.20.0.100", 
                                  "Write to protected register", "high")
    
    # Export data
    historian.export_data("historian_export.json")
    print("Historian data exported")

if __name__ == "__main__":
    main()
