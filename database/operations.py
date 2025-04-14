from datetime import datetime
import json
from database.models import db, ScanResult

def create_scan(scan_info):
    new_scan = ScanResult(scan_info)
    db.session.add(new_scan)
    db.session.commit()
    return new_scan
    # Creates a new scan record in the database

def get_scan_by_id(scan_id):
    # Retrieves a scan by ID, returns dict or None if not found
    scan = ScanResult.query.get(scan_id)
    if scan:
        return scan.to_dict()
    return None
    

def update_scan_status(scan_id, status, end_time=None):
    scan = ScanResult.query.get(scan_id)
    if not scan:
        print(f"Error: Scan {scan_id} not found in database")
        return False
    
    try:
        scan.status = status
        if end_time:
            scan.end_time = end_time
        
        db.session.commit()
        print(f"Successfully updated scan {scan_id} status to {status}")
        return True
    except Exception as e:
        import traceback
        print(f"Error updating scan status: {str(e)}")
        print(traceback.format_exc())
        db.session.rollback()
        return False
    # Updates scan status, returns success boolean

def update_scan_results(scan_id, results):
    scan = ScanResult.query.get(scan_id)
    if not scan:
        print(f"Error: Scan {scan_id} not found in database")
        return False
    
    try:
        results_json = json.dumps(results)
        
        scan.results_data = results_json
        scan.status = 'completed'
        scan.end_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        db.session.commit()
        
        print(f"Successfully updated scan {scan_id} in database with {len(results_json)} bytes of data")
        return True
    except Exception as e:
        import traceback
        print(f"Error updating scan results: {str(e)}")
        print(traceback.format_exc())
        db.session.rollback()
        return False
    

def get_scan_history():
    return ScanResult.query.order_by(ScanResult.start_time.desc()).all()
    # Gets all scan records ordered by start time (newest first)

def delete_scan(scan_id):
    scan = ScanResult.query.get(scan_id)
    if not scan:
        return False
    
    db.session.delete(scan)
    db.session.commit()
    return True
    # Deletes a scan, returns success boolean