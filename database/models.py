from flask_sqlalchemy import SQLAlchemy
import json

db = SQLAlchemy()

class ScanResult(db.Model):
    """
    Model for storing scan results permanently in database
    """
    id = db.Column(db.String(20), primary_key=True)  # Using timestamp-based ID
    url = db.Column(db.String(255), nullable=False)
    scan_type = db.Column(db.Integer, nullable=False)
    scan_depth = db.Column(db.Integer, nullable=False)
    is_wordpress = db.Column(db.Boolean, default=False)
    status = db.Column(db.String(20), nullable=False)
    start_time = db.Column(db.String(30), nullable=False)
    end_time = db.Column(db.String(30), nullable=True)
    results_data = db.Column(db.Text, nullable=True)  # Store JSON data

    def __init__(self, scan_info):
        self.id = scan_info['id']
        self.url = scan_info['url']
        self.scan_type = scan_info['scan_type']
        self.scan_depth = scan_info['scan_depth']
        self.is_wordpress = scan_info.get('is_wordpress', False)
        self.status = scan_info['status']
        self.start_time = scan_info['start_time']
        self.end_time = scan_info.get('end_time')
        
        # Store results as JSON if available
        if 'results' in scan_info and scan_info['results']:
            self.results_data = json.dumps(scan_info['results'])
            
    def to_dict(self):
        """Convert model to dictionary for easy use in templates"""
        data = {
            'id': self.id,
            'url': self.url,
            'scan_type': self.scan_type,
            'scan_depth': self.scan_depth,
            'is_wordpress': self.is_wordpress,
            'status': self.status,
            'start_time': self.start_time,
            'end_time': self.end_time
        }
        
        if self.results_data:
            data['results'] = json.loads(self.results_data)
            
        return data