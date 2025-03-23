from datetime import datetime
import json
from database.models import db, ScanResult

def create_scan(scan_info):
    """
    Create a new scan record in the database
    
    Args:
        scan_info (dict): Dictionary containing scan information
        
    Returns:
        ScanResult: The created scan record
    """
    new_scan = ScanResult(scan_info)
    db.session.add(new_scan)
    db.session.commit()
    return new_scan

def get_scan_by_id(scan_id):
    """
    Retrieve a scan by its ID
    
    Args:
        scan_id (str): The ID of the scan to retrieve
        
    Returns:
        dict: The scan information as a dictionary, or None if not found
    """
    scan = ScanResult.query.get(scan_id)
    if scan:
        return scan.to_dict()
    return None
def update_scan_status(scan_id, status, end_time=None):
    """
    Update only the status of a scan
    
    Args:
        scan_id (str): The ID of the scan to update
        status (str): The new status ('pending', 'running', 'completed', 'failed')
        end_time (str, optional): The end time for completed scans
        
    Returns:
        bool: True if the update was successful, False otherwise
    """
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


def update_scan_results(scan_id, results):
    """
    Update the scan results
    
    Args:
        scan_id (str): The ID of the scan to update
        results (dict): The scan results data
        
    Returns:
        bool: True if the update was successful, False otherwise
    """
    scan = ScanResult.query.get(scan_id)
    if not scan:
        print(f"Error: Scan {scan_id} not found in database")
        return False
    
    try:
        # Try to serialize the results to ensure they're JSON-compatible
        results_json = json.dumps(results)
        
        # Store the serialized data
        scan.results_data = results_json
        scan.status = 'completed'
        scan.end_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Commit the changes
        db.session.commit()
        
        print(f"Successfully updated scan {scan_id} in database with {len(results_json)} bytes of data")
        return True
    except Exception as e:
        # Log the error and roll back any changes
        import traceback
        print(f"Error updating scan results: {str(e)}")
        print(traceback.format_exc())
        db.session.rollback()
        return False

def get_scan_history():
    """
    Get all scan records ordered by start time (newest first)
    
    Returns:
        list: List of ScanResult objects
    """
    return ScanResult.query.order_by(ScanResult.start_time.desc()).all()

def delete_scan(scan_id):
    """
    Delete a scan from the database
    
    Args:
        scan_id (str): The ID of the scan to delete
        
    Returns:
        bool: True if the deletion was successful, False otherwise
    """
    scan = ScanResult.query.get(scan_id)
    if not scan:
        return False
    
    db.session.delete(scan)
    db.session.commit()
    return True