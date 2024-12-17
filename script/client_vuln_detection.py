# Passive Scan Rule Script
# This script analyzes client-side JavaScript to detect potential vulnerabilities.

import re
import traceback

def scan(ps, msg, src):
    try:
        # Only process HTTP 200 responses with content type 'text/html'
        if (msg.getResponseHeader().getStatusCode() == 200 and
            msg.getResponseHeader().getHeader('Content-Type') and
            'text/html' in msg.getResponseHeader().getHeader('Content-Type').lower()):

            # Get the response body
            response_body = msg.getResponseBody().toString()

            # Analyze for Insecure Client-Side Storage
            analyze_insecure_storage(ps, msg, response_body)

            # Analyze for Exposed Sensitive Information
            analyze_sensitive_info(ps, msg, response_body)
    except Exception as e:
        print('An exception occurred in scan(): {}'.format(e))
        traceback.print_exc()

def analyze_insecure_storage(ps, msg, response_body):
    try:
        storage_pattern = r'(localStorage|sessionStorage)\.setItem\s*\(\s*[\'"]([^\'"]+)[\'"]\s*,'
        storage_matches = re.finditer(storage_pattern, response_body, re.IGNORECASE)
        for match in storage_matches:
            storage_type = match.group(1)
            key_name = match.group(2)
            alert_name = 'Insecure Client-Side Storage'
            alert_desc = 'Data stored in {} with key: {}'.format(storage_type, key_name)
            evidence = match.group(0)
            cwe_id = 922  # CWE-922: Insecure Storage of Sensitive Information
            wasc_id = 15   # WASC-15: Application Misconfiguration
            raise_alert(ps, msg, 2, alert_name, alert_desc, evidence, cwe_id, wasc_id)
    except Exception as e:
        print('An exception occurred in analyze_insecure_storage(): {}'.format(e))
        traceback.print_exc()

def analyze_sensitive_info(ps, msg, response_body):
    try:
        sensitive_patterns = [
            r'api[_-]?key\s*[:=]\s*[\'"]?[a-zA-Z0-9\-_]+[\'"]?',     # API key patterns
            r'secret\s*[:=]\s*[\'"]?[^\'"\s]+[\'"]?',                # Secret patterns
            r'password\s*[:=]\s*[\'"]?[^\'"\s]+[\'"]?',              # Password patterns
            r'token\s*[:=]\s*[\'"]?[^\'"\s]+[\'"]?',                 # Token patterns
            r'endpoint\s*[:=]\s*[\'"]?(https?:\/\/[^\s\'"]+)[\'"]?', # API endpoints patterns
            r'(https?:\/\/[^\s\'"]*api[^\s\'"]*)',                   # API endpoints patterns
            r'\b(?:\d[ -]*?){13,19}\b',                              # Credit card number
            r'-----BEGIN (RSA|EC|DSA|PRIVATE) KEY-----[\s\S]*?-----END \1 KEY-----',  # Credit card number
            r'private[_-]?key\s*[:=]\s*[\'"]?[a-zA-Z0-9+/=]{32,}[\'"]?',   # Private key
            r'<!--.*?(api[_-]?key|password|secret|token|api[_-]?endpoint|endpoint|private[_-]?key).*?-->', # Sensitive data in comments
            r'console\.log\s*\(.*?(password|secret|api[_-]?key|token|endpoint|private[_-]?key).*?\)'  # Sensitive data in console.log
        ]
        for pattern in sensitive_patterns:
            matches = re.finditer(pattern, response_body, re.IGNORECASE)
            for match in matches:
                alert_name = 'Exposed Sensitive Information'
                alert_desc = 'Potential sensitive data found in client-side script.'
                evidence = match.group(0)
                cwe_id = 532  # CWE-532: Information Exposure
                wasc_id = 13   # WASC-13: Information Leakage
                raise_alert(ps, msg, 3, alert_name, alert_desc, evidence, cwe_id, wasc_id)
    except Exception as e:
        print('An exception occurred in analyze_sensitive_info(): {}'.format(e))
        traceback.print_exc()

def raise_alert(ps, msg, alert_risk, alert_name, alert_desc, evidence, cwe_id, wasc_id):
    try:
        ps.raiseAlert(
            alert_risk,      # Risk: 0: info, 1: low, 2: medium, 3: high
            2,      # Confidence: 0: false positive, 1: low, 2: medium, 3: high
            alert_name,    # Alert name
            alert_desc,    # Alert description
            msg.getRequestHeader().getURI().toString(),  # URI
            '',     # Param
            '',     # Attack
            '',     # Other info
            'Review the client-side code and remove any sensitive data. '
            'Ensure that dangerous functions are used securely.',  # Solution
            evidence,      # Evidence
            cwe_id,        # CWE ID
            wasc_id,       # WASC ID
            msg            # HTTP Message
        )
    except Exception as e:
        print('An exception occurred in raise_alert(): {}'.format(e))
        traceback.print_exc()