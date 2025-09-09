import json
import re
import requests
import google.generativeai as genai
from collections import Counter

def get_api_keys():
    """Prompts the user to enter their API keys."""
    print("Please enter your API keys:")
    virustotal_api_key = input("VirusTotal API Key: ")
    abuseipdb_api_key = input("AbuseIPDB API Key: ")
    gemini_api_key = input("Gemini API Key: ")
    return virustotal_api_key, abuseipdb_api_key, gemini_api_key

def configure_apis(gemini_api_key):
    """Configures the Gemini API."""
    genai.configure(api_key=gemini_api_key)


def parse_log_entry(entry):
    """Parses a single log entry and extracts relevant information."""
    try:
        log_data = json.loads(entry.split('\t', 2)[-1])
        return {
            'source_ip': log_data.get('remote_addr'),
            'timestamp': log_data.get('timestamp'),
            'method': log_data.get('method'),
            'status_code': log_data.get('status'),
            'uri': log_data.get('uri'),
            'user_agent': log_data.get('user_agent')
        }
    except (json.JSONDecodeError, IndexError):
        return None

def get_virustotal_report(ip_address, api_key):
    """Fetches the VirusTotal report for a given IP address."""
    if not api_key:
        return {"error": "VirusTotal API key not provided."}
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
    headers = {"x-apikey": api_key}
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        return {"error": str(e)}

def get_abuseipdb_report(ip_address, api_key):
    """Fetches the AbuseIPDB report for a given IP address."""
    if not api_key:
        return {"error": "AbuseIPDB API key not provided."}
    url = "https://api.abuseipdb.com/api/v2/check"
    params = {'ipAddress': ip_address, 'maxAgeInDays': '90'}
    headers = {'Accept': 'application/json', 'Key': api_key}
    try:
        response = requests.get(url, headers=headers, params=params)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        return {"error": str(e)}

def generate_analyst_note(findings):
    """Generates an analyst note using the Gemini API."""
    prompt = f"""
    Based on the following log analysis findings, act as a SOC analyst and provide a brief, actionable intelligence report.
    Highlight the most critical threats and recommend immediate next steps. 

    Findings:
    {json.dumps(findings, indent=2)}
    """
    try:
        model = genai.GenerativeModel('gemini-1.5-flash')
        response = model.generate_content(prompt)
        return response.text
    except Exception as e:
        return f"Error generating analyst note: {e}"


def analyze_logs(log_file, virustotal_api_key, abuseipdb_api_key):
    """Analyzes the web server access logs."""
    suspicious_ips = {}
    vulnerability_signatures = {
        'SQL Injection': r'(\'|\"|\%27|\%22).*(select|union|insert|update|delete|drop)',
        'Cross-Site Scripting (XSS)': r'(<|(\%3C))script.*(>|(\%3E))'
    }
    suspicious_user_agents = ['nikto', 'dirbuster']

    with open(log_file, 'r') as f:
        for line in f:
            log_entry = parse_log_entry(line)
            if log_entry and log_entry['source_ip']:
                ip = log_entry['source_ip']
                if ip not in suspicious_ips:
                    suspicious_ips[ip] = {
                        'virustotal': get_virustotal_report(ip, virustotal_api_key),
                        'abuseipdb': get_abuseipdb_report(ip, abuseipdb_api_key),
                        'vulnerabilities': [],
                        'suspicious_user_agent': False,
                        'confidence_score': 0
                    }

                # Vulnerability Signature Matching
                for vuln, pattern in vulnerability_signatures.items():
                    if log_entry['uri'] and re.search(pattern, log_entry['uri'], re.IGNORECASE):
                        suspicious_ips[ip]['vulnerabilities'].append(vuln)

                # User-Agent Analysis
                for ua in suspicious_user_agents:
                    if log_entry['user_agent'] and ua in log_entry['user_agent'].lower():
                        suspicious_ips[ip]['suspicious_user_agent'] = True


    # Correlate findings to increase confidence score
    for ip, data in suspicious_ips.items():
        if 'data' in data['abuseipdb'] and data['abuseipdb']['data']['abuseConfidenceScore'] > 50:
            data['confidence_score'] += data['abuseipdb']['data']['abuseConfidenceScore']
        if data['vulnerabilities']:
            data['confidence_score'] += 20
        if data['suspicious_user_agent']:
            data['confidence_score'] += 10


    return suspicious_ips

def generate_report(suspicious_ips, report_file, gemini_api_key):
    """Generates a threat report."""

    with open(report_file, 'w') as f:
        f.write("Threat Report\n")
        f.write("=" * 20 + "\n\n")
        
        # This part remains the same
        f.write("Summary:\n")
        f.write(f"Found {len(suspicious_ips)} suspicious IP addresses.\n\n")
        f.write("Details:\n")
        
        # New loop to generate detailed threat reports
        threat_number = 1
        for ip, data in suspicious_ips.items():
            if data['confidence_score'] >= 0:
                # Retrieve all the data
                abuse_data = data.get('abuseipdb', {}).get('data', {})
                virustotal_data = data.get('virustotal', {}).get('data', {})
                virustotal_stats = virustotal_data.get('attributes', {}).get('last_analysis_stats', {})
                
                # You'll need to get the actual log entry for the IP to display the request and user agent.
                # This requires a change to the analyze_logs function to store log entries per IP.
                # For this example, we'll use a placeholder.
                source_log_entry = "Log entry not captured"
                
                # Determine severity based on confidence score
                severity = "*Low*"
                if data['confidence_score'] > 50:
                    severity = "*Medium*"
                if data['confidence_score'] > 80:
                    severity = "*High*"

                # Write the detailed report for each threat
                f.write(f"\n### Threat #{threat_number} - {ip}\n")
                f.write(f"- Indicator: Malicious IP Detected\n")
                f.write(f"- Severity: {severity}\n")
                f.write(f"- Source IP: {ip}\n")
                
                # These fields are not currently captured by your script in a way to link to the IP.
                # f.write(f"- Request: [Needs to be captured from log]\n")
                # f.write(f"- User-Agent: [Needs to be captured from log]\n")

                if abuse_data:
                    f.write(f"- AbuseIPDB Confidence: {abuse_data.get('abuseConfidenceScore', 'N/A')}%\n")
                    f.write(f"- Total Reports: {abuse_data.get('totalReports', 'N/A')}\n")
                    f.write(f"- Last Reported: {abuse_data.get('lastReportedAt', 'N/A')}\n")

                if virustotal_stats:
                    f.write(f"- VirusTotal Stats: {virustotal_stats}\n")
                    
                if 'attributes' in virustotal_data and 'as_owner' in virustotal_data['attributes']:
                    f.write(f"- ASN: {virustotal_data['attributes'].get('asn', 'N/A')}\n")
                    f.write(f"- Organization: {virustotal_data['attributes'].get('as_owner', 'N/A')}\n")
                    f.write(f"- Network: {virustotal_data['attributes'].get('network', 'N/A')}\n")
                    f.write(f"- Country: {virustotal_data['attributes'].get('country', 'N/A')}\n")
                    f.write(f"- RIR: {virustotal_data['attributes'].get('regional_internet_registry', 'N/A')}\n")
                
                # Summary is a new field you need to generate.
                summary = f"IP {ip} was flagged for Malicious IP Detected with severity {severity}."
                f.write(f"- Summary: {summary}\n")

                threat_number += 1
                
        # The AI-generated note section remains the same
        if gemini_api_key:
            f.write(generate_analyst_note(suspicious_ips))
        else:
            f.write("Gemini API key not provided. Cannot generate analyst note.")


def generate_blocking_rules(suspicious_ips, rules_file):
    """Generates firewall blocking rules."""
    with open(rules_file, 'w') as f:
        f.write("# iptables rules to block suspicious IPs\n")
        for ip, data in suspicious_ips.items():
            if data['confidence_score'] >= 80: # High-confidence
                f.write(f"iptables -A INPUT -s {ip} -j DROP\n")

if __name__ == "__main__":
    LOG_FILE = 'access_log.txt'
    REPORT_FILE = 'threat_report.md'
    RULES_FILE = 'blocking_rules.sh'

    virustotal_api_key, abuseipdb_api_key, gemini_api_key = get_api_keys()
    if gemini_api_key:
        configure_apis(gemini_api_key)

    suspicious_ips = analyze_logs(LOG_FILE, virustotal_api_key, abuseipdb_api_key)
    generate_report(suspicious_ips, REPORT_FILE, gemini_api_key)
    generate_blocking_rules(suspicious_ips, RULES_FILE)

    print(f"Analysis complete. See '{REPORT_FILE}' for the full report and '{RULES_FILE}' for firewall rules.")