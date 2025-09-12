import json
import re
import requests
import google.generativeai as genai
from collections import Counter
import datetime
import os

def get_api_keys():
    """Returns the API keys."""
    abuseipdb_api_key = "0c0f69b1dd11ed1b9c50a3ce8faad2acc596b4a5a39076d757fa3c4ddd6f3438c8208228784ab0db"
    virustotal_api_key = "1b5a7f7d84a7eda7afa4612eddedde7c04cfcd11b3a4d5a7f889e2687c7f7023"
    gemini_api_key = "AIzaSyCgYR4ZMnSm8YLwkXeX6EV07kzwOg2zChc"
    return abuseipdb_api_key, virustotal_api_key, gemini_api_key

def configure_apis(gemini_api_key):
    """Configures the Gemini API."""
    genai.configure(api_key=gemini_api_key)

def parse_log_entry(entry):
    """Parses a single log entry and extracts relevant information."""
    try:
        if "{" in entry:
            parts = entry.split('\t', 2)
            if len(parts) < 3:
                return None
            log_data = json.loads(parts[-1])
            return {
                'source_ip': log_data.get('remote_addr'),
                'timestamp': log_data.get('timestamp'),
                'method': log_data.get('method'),
                'status': log_data.get('status'),
                'uri': log_data.get('uri'),
                'user_agent': log_data.get('user_agent')
            }
    except (json.JSONDecodeError, IndexError) as e:
        print(f"Parse error on line: {entry[:100]}... Error: {e}")
        return None
    return None

def get_virustotal_report(ip_address, api_key):
    """Fetches the VirusTotal report for a given IP address."""
    if not api_key:
        return {"error": "VirusTotal API key not provided."}
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
    headers = {"x-apikey": api_key}
    try:
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"VirusTotal error for {ip_address}: {e}")
        return {"error": str(e)}

def get_cisco_talos_report(ip_address):
    """Fetches the Cisco Talos report for a given IP address."""
    url = f"https://talosintelligence.com/reputation_center/lookup?search={ip_address}"
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Referer': 'https://talosintelligence.com/reputation_center',
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1'
    }
    for attempt in range(3):  # Retry up to 3 times
        try:
            response = requests.get(url, headers=headers, timeout=15)
            response.raise_for_status()
            html_content = response.text
            reputation_match = re.search(r'Web Reputation: <b class="(.*?)">(.*?)</b>', html_content)
            owner_match = re.search(r'Owner: <b>(.*?)</b>', html_content)
            reputation = reputation_match.group(2).strip() if reputation_match else 'N/A'
            owner = owner_match.group(1).strip() if owner_match else 'N/A'
            return {"reputation": reputation, "owner": owner, "url": url}
        except requests.exceptions.RequestException as e:
            print(f"Talos attempt {attempt+1} failed for {ip_address}: {e}")
            if attempt < 2:
                import time; time.sleep(2)  # Wait 2s before retry
            else:
                return {"error": str(e), "reputation": "N/A", "owner": "N/A"}

def get_abuseipdb_report(ip_address, api_key):
    """Fetches the AbuseIPDB report for a given IP address using the API."""
    url = f"https://api.abuseipdb.com/api/v2/check"
    params = {
        'ipAddress': ip_address,
        'maxAgeInDays': 90
    }
    headers = {
        'Key': api_key,
        'Accept': 'application/json'
    }
    try:
        response = requests.get(url, headers=headers, params=params, timeout=10)
        response.raise_for_status()
        data = response.json()
        if data.get('data'):
            return {
                'score': str(data['data'].get('abuseConfidenceScore', 'N/A')) + '%',
                'reports': str(data['data'].get('totalReports', 'N/A')),
                'country': data['data'].get('countryName', 'N/A')
            }
        return {'score': 'N/A%', 'reports': 'N/A', 'country': 'N/A'}
    except requests.exceptions.RequestException as e:
        print(f"AbuseIPDB API error for {ip_address}: {e}")
        return {'score': 'N/A%', 'reports': 'N/A', 'country': 'N/A'}

def get_ip_geo(ip_address):
    """Fetches basic geolocation data for an IP address."""
    url = f"https://ipapi.co/{ip_address}/json/"
    try:
        response = requests.get(url, timeout=10)
        data = response.json()
        return {
            'country': data.get('country_name', 'N/A'),
            'asn': data.get('asn', 'N/A'),
            'owner': data.get('org', 'N/A'),
            'rir': data.get('regional_internet_registry', 'N/A')
        }
    except:
        return {'country': 'N/A', 'asn': 'N/A', 'owner': 'N/A', 'rir': 'N/A'}

def generate_analyst_note(findings):
    """Generates an analyst note using the Gemini API in HTML format."""
    findings_serializable = {
        'stats': {
            'total_requests': findings['stats']['total_requests'],
            'unique_ips': list(findings['stats']['unique_ips']),
            'ip_requests': dict(findings['stats']['ip_requests']),
            'ip_errors': dict(findings['stats']['ip_errors']),
            'user_agents': dict(findings['stats']['user_agents']),
            'error_ratio': findings['stats']['error_ratio'],
            'unique_ips_count': findings['stats']['unique_ips_count'],
            'top_user_agents': findings['stats']['top_user_agents'],
        },
        'ips': {ip: {k: v for k, v in data.items() if k not in ['virustotal']} for ip, data in findings['ips'].items()}
    }
    prompt = f"""
    Based on the following log analysis and CTI findings:

    {json.dumps(findings_serializable, indent=2)}

    Act as a SOC analyst and provide an actionable intelligence report.
    Highlight the most critical threats, anomalous patterns, and recommend immediate next steps.
    Output only the HTML content for the report section (do not include <html>, <head>, or <body> tags).
    Use Tailwind CSS classes for a clean, professional design inspired by VirusTotal (light theme, blue accents, use colors like text-blue-600, bg-white, etc).
    Structure it with sections like Executive Summary, Key Threats, Anomalous Patterns, Recommendations.
    Make it visually appealing with headings, lists, and perhaps badges for severity.
    """
    try:
        model = genai.GenerativeModel('gemini-1.5-flash')
        response = model.generate_content(prompt)
        return response.text
    except Exception as e:
        print(f"Gemini error: {e}")
        return "<p>Analyst note generation failed. Check API key and quota.</p>"

def analyze_logs(log_file, abuseipdb_api_key, virustotal_api_key, max_lines=None):
    """Analyzes the web server access logs."""
    suspicious_ips = {}
    stats = {
        'total_requests': 0,
        'unique_ips': set(),
        'ip_requests': Counter(),
        'ip_errors': Counter(),
        'user_agents': Counter()
    }
    vulnerability_signatures = {
        'SQL Injection': r'(\'|\"|\%27|\%22).*(select|union|insert|update|delete|drop)',
        'Cross-Site Scripting (XSS)': r'(<|(\%3C))script.*(>|(\%3E))'
    }
    suspicious_user_agents = ['nikto', 'dirbuster', 'sqlmap', 'nmap', 'hydra']

    line_count = 0
    try:
        with open(log_file, 'r') as f:
            for line in f:
                if max_lines and line_count >= max_lines:
                    print(f"Stopping at {max_lines} lines for testing.")
                    break
                log_entry = parse_log_entry(line)
                if log_entry and log_entry['source_ip']:
                    stats['total_requests'] += 1
                    ip = log_entry['source_ip']
                    stats['unique_ips'].add(ip)
                    stats['ip_requests'][ip] += 1
                    status = int(log_entry['status'])
                    if 400 <= status < 500:
                        stats['ip_errors'][ip] += 1
                    ua = log_entry['user_agent']
                    if ua:
                        stats['user_agents'][ua] += 1

                    if ip not in suspicious_ips:
                        print(f"Fetching CTI for new IP: {ip} (total unique: {len(suspicious_ips) + 1})")
                        geo = get_ip_geo(ip)
                        suspicious_ips[ip] = {
                            'virustotal': get_virustotal_report(ip, virustotal_api_key),
                            'cisco_talos': get_cisco_talos_report(ip),
                            'abuseipdb': get_abuseipdb_report(ip, abuseipdb_api_key),
                            'vulnerabilities': [],
                            'suspicious_user_agent': False,
                            'confidence_score': 0,
                            'requests': 0,
                            'errors_4xx': 0,
                            'severity': 'Harmless'  # Initialize severity
                        }
                        suspicious_ips[ip].update(geo)  # Merge geolocation data
                    suspicious_ips[ip]['requests'] += 1
                    if 400 <= status < 500:
                        suspicious_ips[ip]['errors_4xx'] += 1

                    for vuln, pattern in vulnerability_signatures.items():
                        if log_entry['uri'] and re.search(pattern, log_entry['uri'], re.IGNORECASE):
                            if vuln not in suspicious_ips[ip]['vulnerabilities']:
                                suspicious_ips[ip]['vulnerabilities'].append(vuln)

                    for susp_ua in suspicious_user_agents:
                        if ua and susp_ua in ua.lower():
                            suspicious_ips[ip]['suspicious_user_agent'] = True
                            break
                line_count += 1
                if line_count % 100 == 0:
                    print(f"Processed {line_count} lines...")
    except FileNotFoundError:
        print(f"Error: Log file '{log_file}' not found.")
        return {}, stats
    except Exception as e:
        print(f"Error processing log: {e}")
        return {}, stats

    stats['error_ratio'] = sum(stats['ip_errors'].values()) / stats['total_requests'] if stats['total_requests'] else 0
    stats['unique_ips_count'] = len(stats['unique_ips'])
    stats['top_user_agents'] = stats['user_agents'].most_common(5)
    print(f"Stats calculated: {stats['total_requests']} requests, {stats['unique_ips_count']} unique IPs.")

    for ip, data in suspicious_ips.items():
        # Determine severity from individual CTI sources
        talos_reputation = data.get('cisco_talos', {}).get('reputation', 'N/A')
        abuse_score = data.get('abuseipdb', {}).get('score', 'N/A').rstrip('%')
        vt_stats = data.get('virustotal', {}).get('data', {}).get('attributes', {}).get('last_analysis_stats', {})

        # Severity logic: Highest severity wins
        if talos_reputation == "Untrusted" or (abuse_score != 'N/A' and int(abuse_score) > 50) or vt_stats.get('malicious', 0) > 0:
            data['severity'] = 'Malicious'
        elif talos_reputation == "Questionable" or (abuse_score != 'N/A' and 20 <= int(abuse_score) <= 50):
            data['severity'] = 'Suspicious'
        else:
            data['severity'] = 'Harmless'

        # Optional: Keep confidence_score for additional weighting (can be removed if unused)
        if talos_reputation == "Untrusted":
            data['confidence_score'] += 60
        elif talos_reputation == "Questionable":
            data['confidence_score'] += 30

        if abuse_score != 'N/A':
            try:
                score_val = int(abuse_score)
                if score_val > 50:
                    data['confidence_score'] += 40
                elif score_val > 20:
                    data['confidence_score'] += 20
            except ValueError:
                pass

        malicious = vt_stats.get('malicious', 0)
        if malicious > 0:
            data['confidence_score'] += 30 * malicious

        if data['vulnerabilities']:
            data['confidence_score'] += 20 * len(data['vulnerabilities'])
        if data['suspicious_user_agent']:
            data['confidence_score'] += 30

        data['confidence_score'] = min(data['confidence_score'], 100)

    print("Confidence scores and severities calculated.")
    return suspicious_ips, stats

def generate_report(suspicious_ips, stats, report_file, gemini_api_key):
    """Generates a threat report in HTML format."""
    html_template = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Cybersecurity Threat Analysis Report</title>
        <script src="https://cdn.tailwindcss.com"></script>
        <style>
            body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; }}
        </style>
    </head>
    <body class="bg-white text-gray-800 p-6 sm:p-10">
        <div class="max-w-7xl mx-auto bg-white rounded-lg shadow-md p-8 sm:p-12">
            <header class="text-center mb-10">
                <h1 class="text-3xl sm:text-4xl font-bold text-blue-600 mb-2">Log Analysis & CTI Report</h1>
                <p class="text-sm text-gray-500">Report Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            </header>

            <section class="mb-10">
                <h2 class="text-2xl font-semibold text-blue-500 mb-4">General Statistics</h2>
                <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
                    <div class="bg-blue-50 p-4 rounded-lg">
                        <p class="font-bold">Total Requests</p>
                        <p class="text-2xl">{stats['total_requests']}</p>
                    </div>
                    <div class="bg-blue-50 p-4 rounded-lg">
                        <p class="font-bold">Unique IPs</p>
                        <p class="text-2xl">{stats.get('unique_ips_count', 0)}</p>
                    </div>
                    <div class="bg-blue-50 p-4 rounded-lg">
                        <p class="font-bold">Suspicious IPs</p>
                        <p class="text-2xl">{len([ip for ip, d in suspicious_ips.items() if d['severity'] in ['Suspicious', 'Malicious']])}</p>
                    </div>
                    <div class="bg-blue-50 p-4 rounded-lg">
                        <p class="font-bold">4xx Error Ratio</p>
                        <p class="text-2xl">{stats['error_ratio']:.2%}</p>
                    </div>
                </div>
            </section>

            <section class="mb-10">
                <h2 class="text-2xl font-semibold text-blue-500 mb-4">IP Details</h2>
                <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
    """
    for ip, data in suspicious_ips.items():
        vt_data = data.get('virustotal', {}).get('data', {}).get('attributes', {})
        vt_stats = vt_data.get('last_analysis_stats', {})
        talos_data = data.get('cisco_talos', {})
        abuse_data = data.get('abuseipdb', {})
        
        severity_color = "text-green-600" if data['severity'] == 'Harmless' else "text-yellow-600" if data['severity'] == 'Suspicious' else "text-red-600"
        
        info_list = [
            f"IP Address: {ip}",
            f"Country: {data.get('country', 'N/A')}",
            f"ASN: {data.get('asn', 'N/A')}",
            f"Owner: {data.get('owner', 'N/A')}",
            f"RIR: {data.get('rir', 'N/A')}",
            f"Talos Reputation: {talos_data.get('reputation', 'N/A')}",
            f"Abuse Score: {abuse_data.get('score', 'N/A')}",
            f"Abuse Reports: {abuse_data.get('reports', 'N/A')}",
            f"VT Malicious: {vt_stats.get('malicious', 'N/A')}",
            f"VT Suspicious: {vt_stats.get('suspicious', 'N/A')}",
            f"VT Harmless: {vt_stats.get('harmless', 'N/A')}",
            f"Requests Made: {data['requests']}",
            f"4xx Errors: {data['errors_4xx']}",
            f"Vulnerabilities: {', '.join(data['vulnerabilities']) if data['vulnerabilities'] else 'None'}",
            f"Suspicious UA: {'Yes' if data['suspicious_user_agent'] else 'No'}"
        ]
        
        while len(info_list) < 15:
            info_list.append("N/A")
        
        html_template += f"""
                    <div class="bg-blue-50 p-6 rounded-lg shadow">
                        <h3 class="text-xl font-bold text-gray-800 mb-2">{ip}</h3>
                        <p class="mb-4">Severity: <span class="{severity_color} font-semibold">{data['severity']}</span></p>
                        <ul class="space-y-1 text-sm">
                            {''.join(f'<li>{info}</li>' for info in info_list[:15])}
                        </ul>
                    </div>
        """
    
    html_template += """
                </div>
            </section>

            <section>
                <h2 class="text-2xl font-semibold text-blue-500 mb-4">AI Analyst Report</h2>
                <div class="bg-blue-50 p-6 rounded-lg">
    """
    if gemini_api_key:
        print("Generating AI note...")
        try:
            analyst_note = generate_analyst_note({'stats': stats, 'ips': suspicious_ips})
            analyst_note = analyst_note.replace('```html', '').replace('```', '').strip()
            html_template += analyst_note
        except Exception as e:
            print(f"Gemini error: {e}")
            html_template += "<p>AI analyst note generation failed due to API issue. See stats and IP details above for manual analysis.</p>"
        print("AI note generated or fallback used.")
    else:
        html_template += "<p>Gemini API key not provided. Cannot generate analyst note.</p>"
        
    html_template += """
                </div>
            </section>
        </div>
    </body>
    </html>
    """
    
    with open(report_file, 'w', encoding='utf-8') as f:
        f.write(html_template)
    print(f"Report saved to {report_file}")