"""
SQLite database manager for storing scan results and findings
"""

import sqlite3
import logging
from typing import List, Dict, Any
from datetime import datetime


class SQLiteManager:
    """SQLite database manager for CSPM"""
    
    def __init__(self, db_path: str = "cspm_results.db"):
        self.db_path = db_path
        self.logger = logging.getLogger(__name__)
        self.init_database()
    
    def init_database(self):
        """Initialize database schema"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Create scans table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS scans (
                        scan_id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                        providers TEXT,
                        total_findings INTEGER,
                        overall_risk_score REAL,
                        duration_seconds REAL
                    )
                ''')
                
                # Create findings table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS findings (
                        finding_id INTEGER PRIMARY KEY AUTOINCREMENT,
                        scan_id INTEGER,
                        provider TEXT,
                        resource_type TEXT,
                        resource_id TEXT,
                        finding_type TEXT,
                        title TEXT,
                        description TEXT,
                        severity TEXT,
                        category TEXT,
                        risk_score REAL,
                        details TEXT,
                        first_observed DATETIME,
                        last_observed DATETIME,
                        status TEXT DEFAULT 'OPEN',
                        FOREIGN KEY (scan_id) REFERENCES scans (scan_id)
                    )
                ''')
                
                # Create indexes for better performance
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings(scan_id)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status)')
                
                conn.commit()
                
        except sqlite3.Error as e:
            self.logger.error(f"Database initialization failed: {str(e)}")
            raise
    
    def store_scan_results(self, scan_metadata: Dict[str, Any], findings: List[Dict[str, Any]]):
        """Store scan results in database"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Insert scan metadata
                cursor.execute('''
                    INSERT INTO scans (providers, total_findings, overall_risk_score, duration_seconds)
                    VALUES (?, ?, ?, ?)
                ''', (
                    ','.join(scan_metadata.get('providers', [])),
                    scan_metadata.get('total_findings', 0),
                    scan_metadata.get('overall_risk_score', 0.0),
                    scan_metadata.get('duration_seconds', 0)
                ))
                
                scan_id = cursor.lastrowid
                
                # Insert findings
                for finding in findings:
                    cursor.execute('''
                        INSERT INTO findings (
                            scan_id, provider, resource_type, resource_id, finding_type,
                            title, description, severity, category, risk_score, details,
                            first_observed, last_observed
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        scan_id,
                        finding.get('provider'),
                        finding.get('resource_type'),
                        finding.get('resource_id'),
                        finding.get('finding_type'),
                        finding.get('title'),
                        finding.get('description'),
                        finding.get('severity'),
                        finding.get('category'),
                        finding.get('risk_score'),
                        str(finding.get('details', {})),
                        datetime.now(),
                        datetime.now()
                    ))
                
                conn.commit()
                self.logger.info(f"Stored {len(findings)} findings for scan {scan_id}")
                
        except sqlite3.Error as e:
            self.logger.error(f"Failed to store scan results: {str(e)}")
            raise
    
    def get_recent_scans(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get recent scan results"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                
                cursor.execute('''
                    SELECT * FROM scans 
                    ORDER BY timestamp DESC 
                    LIMIT ?
                ''', (limit,))
                
                return [dict(row) for row in cursor.fetchall()]
                
        except sqlite3.Error as e:
            self.logger.error(f"Failed to get recent scans: {str(e)}")
            return []
    
    def get_findings_by_severity(self, severity: str, limit: int = 100) -> List[Dict[str, Any]]:
        """Get findings by severity level"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                
                cursor.execute('''
                    SELECT f.*, s.timestamp as scan_timestamp
                    FROM findings f
                    JOIN scans s ON f.scan_id = s.scan_id
                    WHERE f.severity = ?
                    ORDER BY f.risk_score DESC
                    LIMIT ?
                ''', (severity, limit))
                
                return [dict(row) for row in cursor.fetchall()]
                
        except sqlite3.Error as e:
            self.logger.error(f"Failed to get findings by severity: {str(e)}")
            return []
    
    def update_finding_status(self, finding_id: int, status: str):
        """Update finding status (OPEN, IN_PROGRESS, RESOLVED, etc.)"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute('''
                    UPDATE findings 
                    SET status = ?, last_observed = ?
                    WHERE finding_id = ?
                ''', (status, datetime.now(), finding_id))
                
                conn.commit()
                self.logger.info(f"Updated finding {finding_id} status to {status}")
                
        except sqlite3.Error as e:
            self.logger.error(f"Failed to update finding status: {str(e)}")
            raise
