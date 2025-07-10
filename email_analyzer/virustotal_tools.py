"""
VirusTotal API Integration Tools
Provides URL, file hash, and IP address scanning capabilities
"""

import os
import hashlib
import requests
import time
import logging
from typing import Dict, Any, List, Optional
from google.adk.tools import FunctionTool

logger = logging.getLogger(__name__)

# VirusTotal API configuration
VT_API_BASE = "https://www.virustotal.com/api/v3"
VT_API_KEY = os.getenv('VIRUSTOTAL_API_KEY')

def check_virustotal_config() -> bool:
    """Check if VirusTotal API key is configured."""
    return VT_API_KEY is not None and VT_API_KEY.strip() != ""

def _make_vt_request(endpoint: str, method: str = "GET", data: Dict = None) -> Dict[str, Any]:
    """Make a request to VirusTotal API with proper error handling."""
    if not check_virustotal_config():
        return {"error": "VirusTotal API key not configured. Set VIRUSTOTAL_API_KEY environment variable."}
    
    headers = {
        "X-Apikey": VT_API_KEY,
        "Content-Type": "application/json"
    }
    
    url = f"{VT_API_BASE}/{endpoint}"
    
    try:
        if method == "GET":
            response = requests.get(url, headers=headers, timeout=30)
        elif method == "POST":
            response = requests.post(url, headers=headers, json=data, timeout=30)
        else:
            return {"error": f"Unsupported HTTP method: {method}"}
        
        if response.status_code == 200:
            return response.json()
        elif response.status_code == 404:
            return {"error": "Resource not found in VirusTotal database"}
        elif response.status_code == 429:
            return {"error": "VirusTotal API rate limit exceeded. Please try again later."}
        elif response.status_code == 401:
            return {"error": "Invalid VirusTotal API key"}
        else:
            return {"error": f"VirusTotal API error: {response.status_code} - {response.text}"}
    
    except requests.exceptions.Timeout:
        return {"error": "VirusTotal API request timed out"}
    except requests.exceptions.RequestException as e:
        return {"error": f"VirusTotal API request failed: {str(e)}"}


def scan_url_with_virustotal(url: str) -> Dict[str, Any]:
    """
    Scan a URL with VirusTotal and return threat analysis.
    
    Args:
        url: URL to scan
        
    Returns:
        Dictionary with VirusTotal scan results and analysis
    """
    try:
        if not url or not url.strip():
            return {"error": "URL cannot be empty"}
        
        # Clean the URL
        url = url.strip()
        
        # First, try to get existing analysis
        import base64
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        
        # Get URL analysis
        result = _make_vt_request(f"urls/{url_id}")
        
        if "error" in result:
            # If not found, submit URL for scanning
            if "not found" in result["error"].lower():
                logger.info(f"URL not in VT database, submitting for scan: {url}")
                submit_result = _make_vt_request("urls", "POST", {"url": url})
                
                if "error" in submit_result:
                    return submit_result
                
                # Wait a moment for analysis to start
                time.sleep(2)
                
                # Try to get results again
                result = _make_vt_request(f"urls/{url_id}")
                
                if "error" in result:
                    return {
                        "url": url,
                        "status": "submitted",
                        "message": "URL submitted to VirusTotal for analysis. Results may take a few minutes.",
                        "scan_id": submit_result.get("data", {}).get("id", "unknown")
                    }
            else:
                return result
        
        # Parse the results
        data = result.get("data", {})
        attributes = data.get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})
        
        # Calculate threat score
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)
        undetected = stats.get("undetected", 0)
        total_engines = malicious + suspicious + harmless + undetected
        
        threat_level = "CLEAN"
        if malicious > 0:
            threat_level = "MALICIOUS"
        elif suspicious > 0:
            threat_level = "SUSPICIOUS"
        
        # Get detailed results
        scan_results = attributes.get("last_analysis_results", {})
        detections = []
        
        for engine, result_data in scan_results.items():
            if result_data.get("category") in ["malicious", "suspicious"]:
                detections.append({
                    "engine": engine,
                    "category": result_data.get("category"),
                    "result": result_data.get("result", "Unknown")
                })
        
        return {
            "url": url,
            "threat_level": threat_level,
            "scan_stats": {
                "malicious": malicious,
                "suspicious": suspicious,
                "harmless": harmless,
                "undetected": undetected,
                "total_engines": total_engines
            },
            "detections": detections,
            "scan_date": attributes.get("last_analysis_date"),
            "reputation": attributes.get("reputation", 0),
            "times_submitted": attributes.get("times_submitted", 0),
            "categories": attributes.get("categories", {}),
            "analysis_id": data.get("id", "unknown")
        }
        
    except Exception as e:
        logger.error(f"Error scanning URL with VirusTotal: {e}")
        return {"error": f"Failed to scan URL: {str(e)}"}


def scan_file_hash_with_virustotal(file_hash: str) -> Dict[str, Any]:
    """
    Scan a file hash with VirusTotal.
    
    Args:
        file_hash: SHA256, SHA1, or MD5 hash of the file
        
    Returns:
        Dictionary with VirusTotal scan results
    """
    try:
        if not file_hash or not file_hash.strip():
            return {"error": "File hash cannot be empty"}
        
        file_hash = file_hash.strip().lower()
        
        # Validate hash format
        if len(file_hash) not in [32, 40, 64]:  # MD5, SHA1, SHA256
            return {"error": "Invalid hash format. Provide MD5, SHA1, or SHA256 hash."}
        
        # Get file analysis
        result = _make_vt_request(f"files/{file_hash}")
        
        if "error" in result:
            return result
        
        # Parse the results
        data = result.get("data", {})
        attributes = data.get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})
        
        # Calculate threat score
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)
        undetected = stats.get("undetected", 0)
        total_engines = malicious + suspicious + harmless + undetected
        
        threat_level = "CLEAN"
        if malicious > 0:
            threat_level = "MALICIOUS"
        elif suspicious > 0:
            threat_level = "SUSPICIOUS"
        
        # Get detailed results
        scan_results = attributes.get("last_analysis_results", {})
        detections = []
        
        for engine, result_data in scan_results.items():
            if result_data.get("category") in ["malicious", "suspicious"]:
                detections.append({
                    "engine": engine,
                    "category": result_data.get("category"),
                    "result": result_data.get("result", "Unknown")
                })
        
        return {
            "file_hash": file_hash,
            "threat_level": threat_level,
            "scan_stats": {
                "malicious": malicious,
                "suspicious": suspicious,
                "harmless": harmless,
                "undetected": undetected,
                "total_engines": total_engines
            },
            "detections": detections,
            "file_info": {
                "size": attributes.get("size"),
                "type": attributes.get("type_description"),
                "names": attributes.get("names", []),
                "magic": attributes.get("magic"),
                "md5": attributes.get("md5"),
                "sha1": attributes.get("sha1"),
                "sha256": attributes.get("sha256")
            },
            "scan_date": attributes.get("last_analysis_date"),
            "times_submitted": attributes.get("times_submitted", 0),
            "analysis_id": data.get("id", "unknown")
        }
        
    except Exception as e:
        logger.error(f"Error scanning file hash with VirusTotal: {e}")
        return {"error": f"Failed to scan file hash: {str(e)}"}


def scan_ip_with_virustotal(ip_address: str) -> Dict[str, Any]:
    """
    Scan an IP address with VirusTotal.
    
    Args:
        ip_address: IP address to scan
        
    Returns:
        Dictionary with VirusTotal IP analysis results
    """
    try:
        if not ip_address or not ip_address.strip():
            return {"error": "IP address cannot be empty"}
        
        ip_address = ip_address.strip()
        
        # Basic IP validation
        import ipaddress
        try:
            ipaddress.ip_address(ip_address)
        except ValueError:
            return {"error": f"Invalid IP address format: {ip_address}"}
        
        # Get IP analysis
        result = _make_vt_request(f"ip_addresses/{ip_address}")
        
        if "error" in result:
            return result
        
        # Parse the results
        data = result.get("data", {})
        attributes = data.get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})
        
        # Calculate threat score
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)
        undetected = stats.get("undetected", 0)
        total_engines = malicious + suspicious + harmless + undetected
        
        threat_level = "CLEAN"
        if malicious > 0:
            threat_level = "MALICIOUS"
        elif suspicious > 0:
            threat_level = "SUSPICIOUS"
        
        # Get detailed results
        scan_results = attributes.get("last_analysis_results", {})
        detections = []
        
        for engine, result_data in scan_results.items():
            if result_data.get("category") in ["malicious", "suspicious"]:
                detections.append({
                    "engine": engine,
                    "category": result_data.get("category"),
                    "result": result_data.get("result", "Unknown")
                })
        
        return {
            "ip_address": ip_address,
            "threat_level": threat_level,
            "scan_stats": {
                "malicious": malicious,
                "suspicious": suspicious,
                "harmless": harmless,
                "undetected": undetected,
                "total_engines": total_engines
            },
            "detections": detections,
            "network_info": {
                "country": attributes.get("country"),
                "asn": attributes.get("asn"),
                "as_owner": attributes.get("as_owner"),
                "network": attributes.get("network")
            },
            "reputation": attributes.get("reputation", 0),
            "analysis_id": data.get("id", "unknown")
        }
        
    except Exception as e:
        logger.error(f"Error scanning IP with VirusTotal: {e}")
        return {"error": f"Failed to scan IP address: {str(e)}"}


def get_virustotal_api_status() -> Dict[str, Any]:
    """
    Check VirusTotal API status and quota information.
    
    Returns:
        Dictionary with API status and quota information
    """
    try:
        if not check_virustotal_config():
            return {
                "status": "not_configured",
                "message": "VirusTotal API key not configured",
                "instructions": "Set VIRUSTOTAL_API_KEY environment variable with your API key"
            }
        
        # Get API user info to check quota
        result = _make_vt_request("users/current")
        
        if "error" in result:
            return {
                "status": "error",
                "message": result["error"]
            }
        
        data = result.get("data", {})
        attributes = data.get("attributes", {})
        quotas = attributes.get("quotas", {})
        
        return {
            "status": "active",
            "user_id": data.get("id"),
            "api_calls_monthly": quotas.get("api_calls_monthly", {}),
            "api_calls_daily": quotas.get("api_calls_daily", {}),
            "api_calls_hourly": quotas.get("api_calls_hourly", {}),
            "user_type": attributes.get("user_type", "unknown")
        }
        
    except Exception as e:
        return {
            "status": "error",
            "message": f"Failed to check API status: {str(e)}"
        }


# Create FunctionTool instances
vt_scan_url_tool = FunctionTool(scan_url_with_virustotal)
vt_scan_file_hash_tool = FunctionTool(scan_file_hash_with_virustotal)
vt_scan_ip_tool = FunctionTool(scan_ip_with_virustotal)
vt_api_status_tool = FunctionTool(get_virustotal_api_status)

# Export VirusTotal tools
VIRUSTOTAL_TOOLS = [
    vt_scan_url_tool,
    vt_scan_file_hash_tool,
    vt_scan_ip_tool,
    vt_api_status_tool
] 