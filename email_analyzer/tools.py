"""
Email Analysis Tools - Comprehensive email security analysis toolkit
"""

import os
import re
import json
import base64
import hashlib
import logging
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime
from urllib.parse import urlparse, unquote
from email import message_from_string
from email.header import decode_header
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

import dns.resolver
import requests
from PIL import Image
import pyzbar.pyzbar as pyzbar
from bs4 import BeautifulSoup
from google.adk.tools import FunctionTool

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def read_eml_file(file_path: str) -> Dict[str, Any]:
    """
    Read and return the content of an .eml file as text.
    
    Args:
        file_path: Path to the .eml file
        
    Returns:
        Dictionary with file content and metadata
    """
    try:
        if not os.path.exists(file_path):
            return {"error": f"File not found: {file_path}"}
        
        if not file_path.lower().endswith('.eml'):
            return {"error": "File must have .eml extension"}
        
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        
        return {
            "file_path": file_path,
            "file_size": len(content),
            "content": content,
            "status": "success",
            "message": f"Successfully read {len(content)} characters from {file_path}"
        }
        
    except Exception as e:
        logger.error(f"Error reading .eml file: {e}")
        return {"error": f"Failed to read file: {str(e)}"}


def parse_email_headers(raw_email: str) -> Dict[str, Any]:
    """
    Parse and analyze email headers for authentication and routing information.
    
    Args:
        raw_email: Raw email content as string
        
    Returns:
        Dictionary containing parsed header information and security analysis
    """
    try:
        msg = message_from_string(raw_email)
        headers = {}
        
        # Extract basic headers
        basic_headers = ['From', 'To', 'Subject', 'Date', 'Message-ID', 'Reply-To']
        for header in basic_headers:
            if msg.get(header):
                headers[header.lower()] = _decode_header_value(msg.get(header))
        
        # Extract authentication headers
        auth_headers = ['Authentication-Results', 'Received-SPF', 'DKIM-Signature', 'ARC-Authentication-Results']
        for header in auth_headers:
            if msg.get(header):
                headers[header.lower()] = msg.get(header)
        
        # Parse Received headers (email routing path)
        received_headers = msg.get_all('Received') or []
        headers['received_path'] = []
        for received in received_headers:
            headers['received_path'].append(_parse_received_header(received))
        
        # Security analysis
        security_analysis = _analyze_header_security(headers)
        
        return {
            'headers': headers,
            'security_analysis': security_analysis,
            'parsed_timestamp': datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error parsing email headers: {e}")
        return {'error': str(e)}


def extract_links_from_email(raw_email: str) -> Dict[str, Any]:
    """
    Extract and analyze all links from email content.
    
    Args:
        raw_email: Raw email content as string
        
    Returns:
        Dictionary containing extracted links and their risk assessment
    """
    try:
        msg = message_from_string(raw_email)
        links = []
        
        # Extract from HTML content
        for part in msg.walk():
            if part.get_content_type() == 'text/html':
                html_content = part.get_payload(decode=True).decode('utf-8', errors='ignore')
                soup = BeautifulSoup(html_content, 'html.parser')
                
                # Extract href links
                for link in soup.find_all('a', href=True):
                    url = link['href']
                    text = link.get_text(strip=True)
                    links.append({
                        'url': url,
                        'display_text': text,
                        'type': 'href'
                    })
        
        # Extract from plain text using regex
        for part in msg.walk():
            if part.get_content_type() == 'text/plain':
                text_content = part.get_payload(decode=True).decode('utf-8', errors='ignore')
                url_pattern = r'https?://[^\s<>"\']*'
                text_urls = re.findall(url_pattern, text_content)
                for url in text_urls:
                    links.append({
                        'url': url,
                        'display_text': url,
                        'type': 'plain_text'
                    })
        
        # Analyze each link
        analyzed_links = []
        for link in links:
            analysis = _analyze_link_security(link['url'])
            analyzed_links.append({
                **link,
                'security_analysis': analysis
            })
        
        return {
            'total_links': len(analyzed_links),
            'links': analyzed_links,
            'high_risk_count': sum(1 for link in analyzed_links if link['security_analysis']['risk_level'] == 'HIGH'),
            'analyzed_timestamp': datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error extracting links: {e}")
        return {'error': str(e)}


def extract_attachments_info(raw_email: str) -> Dict[str, Any]:
    """
    Extract and analyze attachment information from email.
    
    Args:
        raw_email: Raw email content as string
        
    Returns:
        Dictionary containing attachment information and security analysis
    """
    try:
        msg = message_from_string(raw_email)
        attachments = []
        
        for part in msg.walk():
            if part.get_content_disposition() == 'attachment':
                filename = part.get_filename()
                if filename:
                    filename = _decode_header_value(filename)
                    content_type = part.get_content_type()
                    size = len(part.get_payload(decode=True))
                    
                    # Calculate hash of attachment
                    attachment_data = part.get_payload(decode=True)
                    file_hash = hashlib.sha256(attachment_data).hexdigest()
                    
                    # Security analysis
                    security_analysis = _analyze_attachment_security(filename, content_type, size, attachment_data)
                    
                    attachments.append({
                        'filename': filename,
                        'content_type': content_type,
                        'size_bytes': size,
                        'sha256_hash': file_hash,
                        'security_analysis': security_analysis
                    })
        
        return {
            'total_attachments': len(attachments),
            'attachments': attachments,
            'high_risk_count': sum(1 for att in attachments if att['security_analysis']['risk_level'] == 'HIGH'),
            'analyzed_timestamp': datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error extracting attachments: {e}")
        return {'error': str(e)}


def detect_qr_codes_in_images(raw_email: str) -> Dict[str, Any]:
    """
    Detect and analyze QR codes in email images.
    
    Args:
        raw_email: Raw email content as string
        
    Returns:
        Dictionary containing QR code information and security analysis
    """
    try:
        msg = message_from_string(raw_email)
        qr_codes = []
        
        for part in msg.walk():
            if part.get_content_type().startswith('image/'):
                try:
                    image_data = part.get_payload(decode=True)
                    
                    # Create PIL Image
                    from io import BytesIO
                    image = Image.open(BytesIO(image_data))
                    
                    # Detect QR codes
                    detected_codes = pyzbar.decode(image)
                    
                    for code in detected_codes:
                        qr_data = code.data.decode('utf-8')
                        qr_type = code.type
                        
                        # Security analysis of QR code content
                        security_analysis = _analyze_qr_code_security(qr_data)
                        
                        qr_codes.append({
                            'data': qr_data,
                            'type': qr_type,
                            'security_analysis': security_analysis
                        })
                        
                except Exception as e:
                    logger.warning(f"Could not process image for QR codes: {e}")
                    continue
        
        return {
            'total_qr_codes': len(qr_codes),
            'qr_codes': qr_codes,
            'high_risk_count': sum(1 for qr in qr_codes if qr['security_analysis']['risk_level'] == 'HIGH'),
            'analyzed_timestamp': datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error detecting QR codes: {e}")
        return {'error': str(e)}


def extract_email_content(raw_email: str) -> Dict[str, Any]:
    """
    Extract and clean email content for analysis.
    
    Args:
        raw_email: Raw email content as string
        
    Returns:
        Dictionary containing extracted content and metadata
    """
    try:
        msg = message_from_string(raw_email)
        content = {
            'plain_text': '',
            'html_content': '',
            'cleaned_text': ''
        }
        
        # Extract content from different parts
        for part in msg.walk():
            if part.get_content_type() == 'text/plain':
                content['plain_text'] = part.get_payload(decode=True).decode('utf-8', errors='ignore')
            elif part.get_content_type() == 'text/html':
                content['html_content'] = part.get_payload(decode=True).decode('utf-8', errors='ignore')
        
        # Clean HTML content to text
        if content['html_content']:
            soup = BeautifulSoup(content['html_content'], 'html.parser')
            content['cleaned_text'] = soup.get_text(separator=' ', strip=True)
        else:
            content['cleaned_text'] = content['plain_text']
        
        # Content analysis
        word_count = len(content['cleaned_text'].split())
        char_count = len(content['cleaned_text'])
        
        return {
            'content': content,
            'metadata': {
                'word_count': word_count,
                'character_count': char_count,
                'has_html': bool(content['html_content']),
                'has_plain_text': bool(content['plain_text'])
            },
            'extracted_timestamp': datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error extracting email content: {e}")
        return {'error': str(e)}


def analyze_email_security(raw_email: str) -> Dict[str, Any]:
    """
    Perform comprehensive security analysis of the email.
    
    Args:
        raw_email: Raw email content as string
        
    Returns:
        Dictionary containing comprehensive security analysis
    """
    try:
        # Run all analysis tools
        header_analysis = parse_email_headers(raw_email)
        link_analysis = extract_links_from_email(raw_email)
        attachment_analysis = extract_attachments_info(raw_email)
        qr_analysis = detect_qr_codes_in_images(raw_email)
        content_analysis = extract_email_content(raw_email)
        
        # Calculate overall risk score
        risk_factors = []
        
        # Header-based risks
        if 'security_analysis' in header_analysis:
            risk_factors.extend(header_analysis['security_analysis'].get('risk_factors', []))
        
        # Link-based risks
        if link_analysis.get('high_risk_count', 0) > 0:
            risk_factors.append('High-risk links detected')
        
        # Attachment-based risks
        if attachment_analysis.get('high_risk_count', 0) > 0:
            risk_factors.append('High-risk attachments detected')
        
        # QR code risks
        if qr_analysis.get('high_risk_count', 0) > 0:
            risk_factors.append('High-risk QR codes detected')
        
        # Content-based risks
        if content_analysis.get('content', {}).get('cleaned_text'):
            content_risks = _analyze_content_risks(content_analysis['content']['cleaned_text'])
            risk_factors.extend(content_risks)
        
        # Calculate overall risk level
        overall_risk = 'LOW'
        if len(risk_factors) > 5:
            overall_risk = 'HIGH'
        elif len(risk_factors) > 2:
            overall_risk = 'MEDIUM'
        
        return {
            'overall_risk_level': overall_risk,
            'risk_factors': risk_factors,
            'detailed_analysis': {
                'headers': header_analysis,
                'links': link_analysis,
                'attachments': attachment_analysis,
                'qr_codes': qr_analysis,
                'content': content_analysis
            },
            'recommendations': _generate_security_recommendations(risk_factors),
            'analysis_timestamp': datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error in security analysis: {e}")
        return {'error': str(e)}


# Helper functions

def _decode_header_value(header_value: str) -> str:
    """Decode email header value."""
    try:
        decoded_parts = decode_header(header_value)
        decoded_string = ''
        for part, encoding in decoded_parts:
            if isinstance(part, bytes):
                decoded_string += part.decode(encoding or 'utf-8', errors='ignore')
            else:
                decoded_string += part
        return decoded_string
    except Exception:
        return header_value


def _parse_received_header(received: str) -> Dict[str, str]:
    """Parse a Received header to extract routing information."""
    # Simple parsing - can be enhanced
    return {
        'raw': received,
        'parsed_timestamp': datetime.now().isoformat()
    }


def _analyze_header_security(headers: Dict[str, Any]) -> Dict[str, Any]:
    """Analyze email headers for security indicators."""
    risk_factors = []
    
    # Check for missing authentication
    if 'authentication-results' not in headers:
        risk_factors.append('Missing authentication results')
    
    # Check for suspicious reply-to
    if 'reply-to' in headers and 'from' in headers:
        if headers['reply-to'] != headers['from']:
            risk_factors.append('Reply-to differs from sender')
    
    # Check for suspicious routing
    if len(headers.get('received_path', [])) > 10:
        risk_factors.append('Suspicious routing path')
    
    return {
        'risk_factors': risk_factors,
        'risk_level': 'HIGH' if len(risk_factors) > 2 else 'MEDIUM' if risk_factors else 'LOW'
    }


def _analyze_link_security(url: str) -> Dict[str, Any]:
    """Analyze a single link for security risks."""
    risk_factors = []
    
    try:
        parsed = urlparse(url)
        
        # Check for suspicious domains
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf']
        if any(parsed.netloc.endswith(tld) for tld in suspicious_tlds):
            risk_factors.append('Suspicious TLD')
        
        # Check for URL shorteners
        shorteners = ['bit.ly', 'tinyurl.com', 't.co', 'short.link']
        if any(shortener in parsed.netloc for shortener in shorteners):
            risk_factors.append('URL shortener detected')
        
        # Check for suspicious patterns
        if len(parsed.netloc) > 50:
            risk_factors.append('Unusually long domain')
        
        if parsed.netloc.count('-') > 4:
            risk_factors.append('Suspicious domain structure')
        
    except Exception:
        risk_factors.append('Malformed URL')
    
    return {
        'risk_factors': risk_factors,
        'risk_level': 'HIGH' if len(risk_factors) > 1 else 'MEDIUM' if risk_factors else 'LOW'
    }


def _analyze_attachment_security(filename: str, content_type: str, size: int, data: bytes) -> Dict[str, Any]:
    """Analyze attachment for security risks."""
    risk_factors = []
    
    # Check for dangerous file extensions
    dangerous_extensions = ['.exe', '.scr', '.bat', '.cmd', '.com', '.pif', '.vbs', '.js']
    if any(filename.lower().endswith(ext) for ext in dangerous_extensions):
        risk_factors.append('Dangerous file extension')
    
    # Check for double extensions
    if filename.count('.') > 1:
        risk_factors.append('Multiple file extensions')
    
    # Check for suspicious size
    if size > 10 * 1024 * 1024:  # 10MB
        risk_factors.append('Large file size')
    
    # Check for password-protected archives (basic detection)
    if content_type in ['application/zip', 'application/x-rar-compressed']:
        risk_factors.append('Archive file - potential password protection')
    
    return {
        'risk_factors': risk_factors,
        'risk_level': 'HIGH' if len(risk_factors) > 1 else 'MEDIUM' if risk_factors else 'LOW'
    }


def _analyze_qr_code_security(qr_data: str) -> Dict[str, Any]:
    """Analyze QR code content for security risks."""
    risk_factors = []
    
    # Check if QR contains URL
    if qr_data.startswith(('http://', 'https://')):
        link_analysis = _analyze_link_security(qr_data)
        risk_factors.extend(link_analysis['risk_factors'])
    
    # Check for suspicious patterns
    if 'download' in qr_data.lower():
        risk_factors.append('Contains download reference')
    
    if 'login' in qr_data.lower():
        risk_factors.append('Contains login reference')
    
    return {
        'risk_factors': risk_factors,
        'risk_level': 'HIGH' if len(risk_factors) > 1 else 'MEDIUM' if risk_factors else 'LOW'
    }


def _analyze_content_risks(content: str) -> List[str]:
    """Analyze email content for risk indicators."""
    risk_factors = []
    
    # Check for urgent/pressure keywords
    urgent_keywords = ['urgent', 'immediate', 'expire', 'suspend', 'verify now', 'act now']
    if any(keyword in content.lower() for keyword in urgent_keywords):
        risk_factors.append('Urgent language detected')
    
    # Check for financial keywords
    financial_keywords = ['payment', 'refund', 'invoice', 'transaction', 'account', 'credit card']
    if any(keyword in content.lower() for keyword in financial_keywords):
        risk_factors.append('Financial content detected')
    
    # Check for credential harvesting
    cred_keywords = ['password', 'username', 'login', 'sign in', 'verify account']
    if any(keyword in content.lower() for keyword in cred_keywords):
        risk_factors.append('Credential harvesting indicators')
    
    return risk_factors


def _generate_security_recommendations(risk_factors: List[str]) -> List[str]:
    """Generate security recommendations based on risk factors."""
    recommendations = []
    
    if not risk_factors:
        recommendations.append('Email appears to be safe based on analysis')
        return recommendations
    
    if 'High-risk links detected' in risk_factors:
        recommendations.append('Do not click on any links - verify URLs independently')
    
    if 'High-risk attachments detected' in risk_factors:
        recommendations.append('Do not open attachments - scan with antivirus first')
    
    if 'High-risk QR codes detected' in risk_factors:
        recommendations.append('Do not scan QR codes - they may lead to malicious content')
    
    if any('authentication' in factor.lower() for factor in risk_factors):
        recommendations.append('Verify sender identity through alternative communication')
    
    if any('urgent' in factor.lower() for factor in risk_factors):
        recommendations.append('Be cautious of urgent requests - verify independently')
    
    recommendations.append('Report this email to your IT security team')
    
    return recommendations


# Create FunctionTool instances
read_eml_file_tool = FunctionTool(read_eml_file)
parse_email_headers_tool = FunctionTool(parse_email_headers)
extract_links_tool = FunctionTool(extract_links_from_email)
extract_attachments_tool = FunctionTool(extract_attachments_info)
detect_qr_codes_tool = FunctionTool(detect_qr_codes_in_images)
extract_content_tool = FunctionTool(extract_email_content)
analyze_security_tool = FunctionTool(analyze_email_security)

# Export all tools
ALL_TOOLS = [
    read_eml_file_tool,
    parse_email_headers_tool,
    extract_links_tool,
    extract_attachments_tool,
    detect_qr_codes_tool,
    extract_content_tool,
    analyze_security_tool
]