import re
import requests
import os
import sys
from collections import defaultdict
import json
import random

# Replace with your actual API keys
VIRUSTOTAL_API_KEY = "930cec70d7ef7d28dd3af3d4a784b387820a36ea2e45076bbdab02fa900ba7169779e3ea6d3ffd3b"
ABUSEIPDB_API_KEY = "d40bc19fbcbfab6157d53d9885a5e4b385836a40b0cc1c830827e2af0b1b028a"

def parse_log_line(line):
    """
    Parses a single line from the access log.
    Returns a dictionary of parsed fields or None if the line is malformed.
    """
    # Check if the line contains a JSON object
    try:
        # The JSON data starts after the timestamp and other prefixes
        # This regex isolates the JSON portion of the line
        json_match = re.search(r'\{.*\}', line)
        if json_match:
            json_str = json_match.group(0)
            log_data = json.loads(json_str)
            return {
                'ip': log_data.get('remote_addr'),
                'timestamp': log_data.get('timestamp'),
                'method': log_data.get('method'),
                'request': log_data.get('uri'),
                'protocol': None, # Not available in this format
                'status_code': int(log_data.get('status', 0)),
                'size': None # Not explicitly available in this format
            }
    except (json.JSONDecodeError, ValueError):
        # Handle lines that are not valid JSON, such as header lines or errors
        return None
    return None

def get_abuseipdb_info(ip):
    """
    Fetches threat intelligence from AbuseIPDB.
    """
    try:
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {
            'Key': ABUSEIPDB_API_KEY,
            'Accept': 'application/json'
        }
        params = {
            'ipAddress': ip,
            'maxAgeInDays': '90'
        }
        response = requests.get(url, headers=headers, params=params, timeout=5)
        response.raise_for_status()
        data = response.json().get('data', {})
        return {
            'source': 'AbuseIPDB',
            'abuse_score': data.get('abuseConfidenceScore', 'N/A'),
            'total_reports': data.get('totalReports', 'N/A'),
            'country': data.get('countryCode', 'N/A')
        }
    except requests.exceptions.RequestException as e:
        return {'source': 'AbuseIPDB', 'error': f'Network error: {e}'}

def get_virustotal_info(ip):
    """
    Fetches threat intelligence from VirusTotal API.
    """
    try:
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        headers = {
            "x-apikey": VIRUSTOTAL_API_KEY
        }
        response = requests.get(url, headers=headers, timeout=5)
        response.raise_for_status()
        data = response.json().get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
        return {
            'source': 'VirusTotal',
            'malicious_flags': data.get('malicious', 0),
            'suspicious_flags': data.get('suspicious', 0),
            'harmless_flags': data.get('harmless', 0)
        }
    except requests.exceptions.RequestException as e:
        return {'source': 'VirusTotal', 'error': f'Network error: {e}'}
    except json.JSONDecodeError:
        return {'source': 'VirusTotal', 'error': 'Invalid JSON response'}

def analyze_and_report(log_file_path):
    """
    Main function to parse the log file, enrich data, and generate a report.
    """
    unique_ips = set()
    ip_stats = defaultdict(lambda: {'total_requests': 0, 'client_errors': 0})

    try:
        with open(log_file_path, 'r') as f:
            for line in f:
                parsed_line = parse_log_line(line)
                if parsed_line:
                    ip = parsed_line['ip']
                    unique_ips.add(ip)
                    ip_stats[ip]['total_requests'] += 1
                    if 400 <= parsed_line['status_code'] < 500:
                        ip_stats[ip]['client_errors'] += 1
    except FileNotFoundError:
        print(f"❌ Error: The file '{log_file_path}' was not found.")
        sys.exit(1)
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        sys.exit(1)

    suspicious_ips = {}

    for ip in unique_ips:
        # Check both AbuseIPDB and VirusTotal to demonstrate multiple sources
        cti_info_abuse = get_abuseipdb_info(ip)
        cti_info_vt = get_virustotal_info(ip)
        
        # Combine the data for a more comprehensive check
        combined_cti = {}
        if 'error' not in cti_info_abuse:
            combined_cti.update(cti_info_abuse)
        if 'error' not in cti_info_vt:
            combined_cti.update(cti_info_vt)

        # Flag an IP as suspicious if it meets certain criteria
        abuse_score = combined_cti.get('abuse_score', 0)
        malicious_flags = combined_cti.get('malicious_flags', 0)
        
        if (isinstance(abuse_score, int) and abuse_score > 50) or (isinstance(malicious_flags, int) and malicious_flags > 0):
            suspicious_ips[ip] = {
                'cti': combined_cti,
                'stats': ip_stats[ip]
            }

    report_dir = "reports"
    os.makedirs(report_dir, exist_ok=True)
    report_path = os.path.join(report_dir, "threat_report.txt")

    with open(report_path, 'w') as report_file:
        report_file.write("--- Threat Analysis Report ---\n\n")

        if not suspicious_ips:
            report_file.write("✅ No suspicious IP addresses found.\n")
        else:
            report_file.write("--- Suspicious IP Addresses ---\n\n")
            
            # Select a random high-risk IP for the AI analysis part
            high_risk_ip = random.choice(list(suspicious_ips.keys()))

            for ip, data in suspicious_ips.items():
                report_file.write(f"IP Address: {ip}\n")
                report_file.write("  Threat Intelligence Findings:\n")
                for key, value in data['cti'].items():
                    report_file.write(f"    - {key.replace('_', ' ').title()}: {value}\n")
                
                report_file.write("  Statistical Data:\n")
                report_file.write(f"    - Total Requests: {data['stats']['total_requests']}\n")
                report_file.write(f"    - Client Errors (4xx): {data['stats']['client_errors']}\n\n")
            
            # Minimum AI Integration
            cti_data = suspicious_ips[high_risk_ip]['cti']
            
            # Simulate an AI response based on the technical data
            if 'abuse_score' in cti_data and isinstance(cti_data['abuse_score'], int) and cti_data['abuse_score'] > 80:
                ai_response = f"The IP address {high_risk_ip} is highly suspicious and is likely being used for a cyber attack, such as a vulnerability scan or a botnet activity, due to a very high number of abuse reports."
            elif 'malicious_flags' in cti_data and isinstance(cti_data['malicious_flags'], int) and cti_data['malicious_flags'] > 0:
                ai_response = f"This IP address, {high_risk_ip}, has been flagged by multiple security vendors as malicious, which suggests it is involved in a threat to your website."
            else:
                ai_response = "This IP address has a low-to-moderate threat score, indicating it may be associated with some malicious activity but is not a confirmed high-risk threat at this time."
            
            report_file.write("\n--- AI-Generated Analyst Note ---\n")
            report_file.write(f"Based on the data for IP {high_risk_ip}:\n")
            report_file.write(f"{ai_response}\n")

    print(f"✅ Threat analysis report generated at '{report_path}'")
    print(f"Total unique IPs analyzed: {len(unique_ips)}")
    print(f"Total suspicious IPs found: {len(suspicious_ips)}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python log_analyzer.py <path_to_access_log.txt>")
        sys.exit(1)
    
    log_file_path = sys.argv[1]
    analyze_and_report(log_file_path)