"""
Email Analyzer Agent Package

A comprehensive email security analysis toolkit that provides:
- Email header parsing and authentication analysis
- Link extraction and security assessment
- Attachment analysis and threat detection
- QR code detection and analysis
- Content extraction and risk assessment
- Comprehensive security analysis and recommendations

This package is designed to work with Google ADK agents for automated
email security analysis and threat detection.
"""

from .agent import root_agent
from .tools import (
    parse_email_headers,
    extract_links_from_email,
    extract_attachments_info,
    detect_qr_codes_in_images,
    extract_email_content,
    analyze_email_security,
    ALL_TOOLS
)

__version__ = "1.0.0"
__author__ = "Email Security Team"
__description__ = "Comprehensive email security analysis toolkit"

# Export main components
__all__ = [
    'root_agent',
    'parse_email_headers',
    'extract_links_from_email',
    'extract_attachments_info',
    'detect_qr_codes_in_images',
    'extract_email_content',
    'analyze_email_security',
    'ALL_TOOLS'
]

# Package metadata
PACKAGE_INFO = {
    'name': 'email-analyzer-agent',
    'version': __version__,
    'description': __description__,
    'author': __author__,
    'tools_count': len(ALL_TOOLS),
    'capabilities': [
        'Email header analysis',
        'Link extraction and security assessment',
        'Attachment threat detection',
        'QR code analysis',
        'Content extraction and cleaning',
        'Comprehensive security analysis',
        'Risk assessment and recommendations'
    ],
    'dependencies': [
        'google-adk',
        'dnspython',
        'requests',
        'Pillow',
        'pyzbar',
        'beautifulsoup4',
        'yara-python'
    ]
}


def get_package_info():
    """Return package information."""
    return PACKAGE_INFO


def list_available_tools():
    """List all available email analysis tools."""
    return [tool.__name__ for tool in ALL_TOOLS]


def get_tool_info(tool_name: str):
    """Get information about a specific tool."""
    for tool in ALL_TOOLS:
        if tool.__name__ == tool_name:
            return {
                'name': tool.__name__,
                'description': tool.__doc__,
                'module': tool.__module__
            }
    return None