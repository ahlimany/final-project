import json
import re
import os
import sys
import argparse
import requests
from bs4 import BeautifulSoup
import google.generativeai as genai
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.table import Table
from rich.panel import Panel
from rich.markdown import Markdown
from rich.layout import Layout
from rich.text import Text
from rich.box import ROUNDED
from rich.columns import Columns
from datetime import datetime
import markdown as md_converter

# API Keys
ABUSEIPDB_API_KEY = '0c0f69b1dd11ed1b9c50a3ce8faad2acc596b4a5a39076d757fa3c4ddd6f3438c8208228784ab0db'
VIRUSTOTAL_API_KEY = '1b5a7f7d84a7eda7afa4612eddedde7c04cfcd11b3a4d5a7f889e2687c7f7023'
GEMINI_API_KEY = 'AIzaSyAaVwSTjO-89oRQBqROQpfK37vk2E5ZzoQ'

# Configure Gemini
genai.configure(api_key=GEMINI_API_KEY)
model = genai.GenerativeModel('gemini-1.5-flash')

console = Console()

# Malicious User-Agents patterns
MALICIOUS_UA_PATTERNS = [
    re.compile(r'sqlmap', re.IGNORECASE),
    re.compile(r'nmap', re.IGNORECASE),
    re.compile(r'hydra', re.IGNORECASE),
    re.compile(r'nikto', re.IGNORECASE),
    re.compile(r'nessus', re.IGNORECASE),
    re.compile(r'acunetix', re.IGNORECASE),
]

# ASCII Art for Branding
AZERBAIJAN_CYBER_LOGO = """
[blue]
____  _       _      ____  _        _    
/ ___|| |     / \\    |  _ \\| |      / \\   
| |    | |    / _ \\   | | | | |     / _ \\  
 | |___ | |___/ ___ \\  | |_| | |___ / ___ \\ 
   \\____||____/_/   \\_\\ |____/|_____/_/   \\_\\
[white]   MADE BY AHLIMAN ABBASOV
"""

def parse_log_file(log_path):
    logs = []
    try:
        with open(log_path, 'r', encoding='utf-8') as f:
            for line in f:
                try:
                    json_str = re.search(r'\{.*\}', line)
                    if json_str:
                        log_entry = json.loads(json_str.group(0))
                        logs.append(log_entry)
                except json.JSONDecodeError:
                    console.print("[yellow]Warning: Malformed log line skipped.[/yellow]")
    except FileNotFoundError:
        console.print("[red]Error: Log file not found.[/red]")
        sys.exit(1)
    return logs

def get_unique_ips(logs):
    return set(log['remote_addr'] for log in logs if 'remote_addr' in log)

def check_abuseipdb(ip):
    try:
        url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}"
        headers = {'Key': ABUSEIPDB_API_KEY, 'Accept': 'application/json'}
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        data = response.json()['data']
        return {
            'abuse_score': data.get('abuseConfidenceScore', 'N/A'),
            'total_reports': data.get('totalReports', 'N/A'),
            'country': data.get('countryCode', 'N/A'),
            'isp': data.get('isp', 'N/A'),
            'usage_type': data.get('usageType', 'N/A'),
            'domain': data.get('domain', 'N/A'),
            'is_tor': data.get('isTor', 'N/A'),
            'last_reported_at': data.get('lastReportedAt', 'N/A'),
            'num_distinct_users': data.get('numDistinctUsers', 'N/A'),
        }
    except requests.RequestException:
        console.print(f"[yellow]Warning: Network error checking AbuseIPDB for {ip}.[/yellow]")
        return {}

def check_talos(ip):
    try:
        url = f"https://talosintelligence.com/reputation_center/lookup?search={ip}"
        response = requests.get(url)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')
        reputation_elem = soup.find(string=re.compile(r'Reputation', re.I))
        web_reputation = reputation_elem.find_next('span').text.strip() if reputation_elem else 'N/A'
        owner_elem = soup.find(string=re.compile(r'Owner', re.I))
        owner = owner_elem.find_next('span').text.strip() if owner_elem else 'N/A'
        email_rep_elem = soup.find(string=re.compile(r'Email Reputation', re.I))
        email_reputation = email_rep_elem.find_next('span').text.strip() if email_rep_elem else 'N/A'
        spam_level_elem = soup.find(string=re.compile(r'Spam Level', re.I))
        spam_level = spam_level_elem.find_next('span').text.strip() if spam_level_elem else 'N/A'
        return {
            'web_reputation': web_reputation,
            'owner': owner,
            'email_reputation': email_reputation,
            'spam_level': spam_level,
        }
    except requests.RequestException:
        console.print(f"[yellow]Warning: Network error checking Talos for {ip}.[/yellow]")
        return {}

def check_virustotal(ip):
    try:
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        headers = {'x-apikey': VIRUSTOTAL_API_KEY}
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        data = response.json()['data']['attributes']
        return {
            'malicious_count': data['last_analysis_stats'].get('malicious', 'N/A'),
            'suspicious_count': data['last_analysis_stats'].get('suspicious', 'N/A'),
            'harmless_count': data['last_analysis_stats'].get('harmless', 'N/A'),
            'undetected_count': data['last_analysis_stats'].get('undetected', 'N/A'),
            'asn': data.get('asn', 'N/A'),
            'as_owner': data.get('as_owner', 'N/A'),
            'country': data.get('country', 'N/A'),
            'network': data.get('network', 'N/A'),
            'rir': data.get('regional_internet_registry', 'N/A'),
            'reputation': data.get('reputation', 'N/A'),
            'tags': data.get('tags', []),
        }
    except requests.RequestException:
        console.print(f"[yellow]Warning: Network error checking VirusTotal for {ip}.[/yellow]")
        return {}

def enrich_ip(ip):
    cti = {}
    abuse = check_abuseipdb(ip)
    if abuse:
        cti['abuseipdb'] = abuse
    talos = check_talos(ip)
    if talos:
        cti['talos'] = talos
    vt = check_virustotal(ip)
    if vt:
        cti['virustotal'] = vt
    return cti

def is_suspicious(cti):
    if not cti:
        return False
    abuse = cti.get('abuseipdb', {})
    talos = cti.get('talos', {})
    vt = cti.get('virustotal', {})
    if abuse.get('abuse_score', 0) > 50:
        return True
    if talos.get('web_reputation', '').lower() in ['untrusted', 'questionable']:
        return True
    if vt.get('malicious_count', 0) > 0:
        return True
    return False

def determine_severity(cti):
    abuse_score = cti.get('abuseipdb', {}).get('abuse_score', 0)
    malicious_count = cti.get('virustotal', {}).get('malicious_count', 0)
    if abuse_score > 80 or malicious_count > 5:
        return 'Malicious'
    elif abuse_score > 50 or malicious_count > 0:
        return 'Suspicious'
    else:
        return 'Harmless'

def analyze_user_agent(ua):
    for pattern in MALICIOUS_UA_PATTERNS:
        if pattern.search(ua):
            return True
    return False

def get_ip_stats(logs, ip):
    ip_logs = [log for log in logs if log.get('remote_addr') == ip]
    total_requests = len(ip_logs)
    client_errors = sum(1 for log in ip_logs if 400 <= log.get('status', 0) < 500)
    malicious_ua = any(analyze_user_agent(log.get('user_agent', '')) for log in ip_logs)
    return {
        'total_requests': total_requests,
        'client_errors': client_errors,
        'malicious_ua': malicious_ua
    }

def get_log_summary(logs):
    total_requests = len(logs)
    unique_ips = len(get_unique_ips(logs))
    status_404 = sum(1 for log in logs if log.get('status') == 404)
    status_200 = sum(1 for log in logs if log.get('status') == 200)
    ratio_404_200 = status_404 / status_200 if status_200 > 0 else 0
    total_client_errors = sum(1 for log in logs if 400 <= log.get('status', 0) < 500)
    error_ratio = total_client_errors / total_requests if total_requests > 0 else 0
    return {
        'total_requests': total_requests,
        'unique_ips': unique_ips,
        '404_ratio': ratio_404_200,
        'total_client_errors': total_client_errors,
        'error_ratio': error_ratio,
    }

def get_ip_attributes(ip, cti, stats):
    abuse = cti.get('abuseipdb', {})
    vt = cti.get('virustotal', {})
    talos = cti.get('talos', {})
    attributes = [
        f"IP Address: {ip}",
        f"Country: {abuse.get('country', vt.get('country', 'N/A'))}",
        f"ISP: {abuse.get('isp', 'N/A')}",
        f"Usage Type: {abuse.get('usage_type', 'N/A')}",
        f"Domain: {abuse.get('domain', 'N/A')}",
        f"ASN: {vt.get('asn', 'N/A')}",
        f"AS Owner: {vt.get('as_owner', 'N/A')}",
        f"RIR: {vt.get('rir', 'N/A')}",
        f"Abuse Score: {abuse.get('abuse_score', 'N/A')}",
        f"Abuse Reports: {abuse.get('total_reports', 'N/A')}",
        f"Last Reported At: {abuse.get('last_reported_at', 'N/A')}",
        f"Talos Web Reputation: {talos.get('web_reputation', 'N/A')}",
        f"Talos Owner: {talos.get('owner', 'N/A')}",
        f"VT Malicious: {vt.get('malicious_count', 'N/A')}",
        f"VT Suspicious: {vt.get('suspicious_count', 'N/A')}",
    ]
    # Trim to 15
    attributes = attributes[:15]
    return attributes

def ai_explain_threat(cti, stats):
    prompt = f"Explain this threat in one plain-English sentence for a non-technical person: IP with CTI {cti} and stats {stats}."
    try:
        response = model.generate_content(prompt)
        return response.text.strip()
    except Exception as e:
        console.print(f"[yellow]Warning: AI error - {e}[/yellow]")
        return "AI explanation unavailable."

def ai_analyst_report(findings):
    prompt = f"""
Based on the following log analysis and CTI findings:

{json.dumps(findings, indent=2)}

Act as an expert SOC analyst and generate a highly detailed, actionable intelligence report with a strong emphasis on solving security issues. The AI-generated content is the core of this report, so provide in-depth analysis and insights. Structure the report with the following sections, each with comprehensive content:
- Executive Summary: Offer a concise yet thorough overview, including total requests, unique IPs, overall threat level, and key takeaways for decision-makers.
- Threat Assessment: Provide an exhaustive analysis of critical threats, listing all IP addresses with severity levels (Malicious, Suspicious, Harmless), detailed CTI data (e.g., abuse scores, malicious counts, geographic origins), and potential impact on the system.
- Anomalous Patterns: Identify and explain unusual activity patterns (e.g., high 404 ratios, malicious user agents) with specific examples from the data, hypothesize root causes, and correlate with CTI findings.
- Problem-Solving Approach: Deliver a robust strategy to address threats, including root cause analysis, specific mitigation tactics (e.g., IP blocking scripts, firewall rule updates, intrusion detection configurations), and sample configurations or code snippets where applicable.
- Recommendations: Present a prioritized action plan with clear, actionable steps, estimated timelines (e.g., immediate, within 24 hours, within 1 week), and suggested responsible teams or roles (e.g., network admins, security team).
- Additional Insights: Provide advanced observations (e.g., ISP trends, regional threat clusters, historical context) to enhance long-term security posture and prevent recurrence.
Output only the HTML content for the report section (do not include <html>, <head>, or <body> tags).
Use Tailwind CSS classes for a professional design inspired by VirusTotal (light theme, blue accents like text-blue-600, bg-white), with h2 for main sections, h3 for subsections, detailed lists, tables for data comparison, and severity badges (e.g., bg-red-100 text-red-800 for Malicious, bg-yellow-100 text-yellow-800 for Suspicious).
Ensure the AI content is the highlight, offering deep insights, practical solutions, and a clear narrative to guide security responses.
"""
    try:
        response = model.generate_content(prompt)
        return response.text.strip()
    except Exception as e:
        console.print(f"[yellow]Warning: AI error - {e}[/yellow]")
        return "<p>AI analyst report unavailable.</p>"

def generate_html_report(suspicious_ips, log_summary, ai_report_html, timestamp):
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
                <p class="text-sm text-gray-500">Report Generated: {timestamp}</p>
            </header>

            <section class="mb-10">
                <h2 class="text-2xl font-semibold text-blue-500 mb-4">General Statistics</h2>
                <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
                    <div class="bg-blue-50 p-4 rounded-lg">
                        <p class="font-bold">Total Requests</p>
                        <p class="text-2xl">{log_summary['total_requests']}</p>
                    </div>
                    <div class="bg-blue-50 p-4 rounded-lg">
                        <p class="font-bold">Unique IPs</p>
                        <p class="text-2xl">{log_summary['unique_ips']}</p>
                    </div>
                    <div class="bg-blue-50 p-4 rounded-lg">
                        <p class="font-bold">Suspicious IPs</p>
                        <p class="text-2xl">{len(suspicious_ips)}</p>
                    </div>
                    <div class="bg-blue-50 p-4 rounded-lg">
                        <p class="font-bold">4xx Error Ratio</p>
                        <p class="text-2xl">{log_summary['error_ratio']:.2%}</p>
                    </div>
                </div>
            </section>

            <section class="mb-10">
                <h2 class="text-2xl font-semibold text-blue-500 mb-4">IP Details</h2>
                <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
    """
    for ip, data in suspicious_ips.items():
        vt = data['cti'].get('virustotal', {})
        talos = data['cti'].get('talos', {})
        abuse = data['cti'].get('abuseipdb', {})
        severity = data['severity']
        severity_color = "text-green-600" if severity == 'Harmless' else "text-yellow-600" if severity == 'Suspicious' else "text-red-600"
        info_list = data['attributes']
        vulnerabilities = ', '.join(vt.get('tags', [])) or 'None'
        suspicious_ua = 'Yes' if data['stats']['malicious_ua'] else 'No'
        # Ensure 15 items
        while len(info_list) < 15:
            info_list.append('N/A')
        html_template += f"""
                    <div class="bg-blue-50 p-6 rounded-lg shadow">
                        <h3 class="text-xl font-bold text-gray-800 mb-2">{ip}</h3>
                        <p class="mb-4">Severity: <span class="{severity_color} font-semibold">{severity}</span></p>
                        <ul class="space-y-1 text-sm">
                            {''.join(f'<li>{info}</li>' for info in info_list)}
                        </ul>
                    </div>
        """

    html_template += """
                </div>
            </section>

            <section>
                <h2 class="text-2xl font-semibold text-blue-500 mb-4">AI Analyst Report</h2>
    """
    html_template += ai_report_html
    html_template += """
            </section>
        </div>
    </body>
    </html>
    """
    return html_template

def display_dashboard(suspicious_ips, log_summary, ai_report_md):
    layout = Layout()
    layout.split(
        Layout(name="header", size=10),
        Layout(name="general", size=8),
        Layout(name="details"),
        Layout(name="ai", ratio=1),
        Layout(name="footer", size=3)
    )

    # Header
    header_text = Text.from_markup(AZERBAIJAN_CYBER_LOGO , justify="center")
    layout["header"].update(Panel(header_text, border_style="blue", box=ROUNDED))

    # General Info
    general_grid = Table.grid(expand=True)
    general_grid.add_column(justify="center")
    general_grid.add_column(justify="center")
    general_grid.add_column(justify="center")
    general_grid.add_column(justify="center")
    general_grid.add_row(
        Panel(f"Total Requests\n[bold]{log_summary['total_requests']}[/bold]", box=ROUNDED, style="on #00008B"),
        Panel(f"Unique IPs\n[bold]{log_summary['unique_ips']}[/bold]", box=ROUNDED, style="on #00008B"),
        Panel(f"Suspicious IPs\n[bold]{len(suspicious_ips)}[/bold]", box=ROUNDED, style="on #00008B"),
        Panel(f"4xx Error Ratio\n[bold]{log_summary['error_ratio']:.2%}[/bold]", box=ROUNDED, style="on #00008B"),
    )
    layout["general"].update(Panel(general_grid, title="General Statistics", border_style="blue"))

    # Detailed IPs
    ip_panels = []
    for ip, data in suspicious_ips.items():
        severity_style = "green" if data['severity'] == 'Harmless' else "yellow" if data['severity'] == 'Suspicious' else "red"
        ip_content = f"[bold]{ip}[/bold]\n[ {severity_style} ]Severity: {data['severity']}[ /{severity_style} ]\n"
        for attr in data['attributes']:
            if attr != 'N/A':
                ip_content += f"- {attr}\n"
        ip_panels.append(Panel(ip_content, title=ip, border_style="blue", box=ROUNDED))
    layout["details"].update(Panel(Columns(ip_panels), title="Detailed IP Information", border_style="blue"))

    # AI Result
    layout["ai"].update(Panel(Markdown(ai_report_md), title="AI Analyst Report", border_style="blue"))

    # Footer
    footer_text = Text("[white]Prepared for: Azrieli School of Continuing Studies of the Technion\nby Ahliman Abbasov[/white]", justify="center")
    layout["footer"].update(Panel(footer_text, border_style="blue", box=ROUNDED))

    console.print(layout)

def main():
    parser = argparse.ArgumentParser(description="Log Analysis & CTI Tool")
    parser.add_argument('log_file', help="Path to the access log file")
    args = parser.parse_args()

    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), BarColumn(), transient=True) as progress:
        task = progress.add_task(description="Parsing logs...", total=None)
        logs = parse_log_file(args.log_file)
        progress.update(task, description="Extracting unique IPs...")
        unique_ips = get_unique_ips(logs)
        suspicious_ips = {}
        for ip in progress.track(unique_ips, description="Enriching IPs..."):
            cti = enrich_ip(ip)
            if is_suspicious(cti):
                stats = get_ip_stats(logs, ip)
                severity = determine_severity(cti)
                attributes = get_ip_attributes(ip, cti, stats)
                suspicious_ips[ip] = {'cti': cti, 'stats': stats, 'severity': severity, 'attributes': attributes}

        progress.update(task, description="Generating log summary...")
        log_summary = get_log_summary(logs)

        # Prepare findings for AI
        findings = {
            'general': log_summary,
            'ips': {}
        }
        for ip, data in suspicious_ips.items():
            filtered_attrs = [attr for attr in data['attributes'] if not attr.endswith('N/A')]
            findings['ips'][ip] = {
                'severity': data['severity'],
                'stats': data['stats'],
                'attributes': filtered_attrs
            }

        progress.update(task, description="Generating AI analyst report...")
        ai_report_html = ai_analyst_report(findings)

        # Generate Markdown version of AI report
        md_prompt = """
Based on the following log analysis and CTI findings:

{}

Act as an expert SOC analyst and generate a highly detailed, actionable intelligence report with a strong emphasis on solving security issues. The AI-generated content is the core of this report, so provide in-depth analysis and insights. Structure the report with the following sections, each with comprehensive content:
- Executive Summary: Offer a concise yet thorough overview, including total requests, unique IPs, overall threat level, and key takeaways for decision-makers.
- Threat Assessment: Provide an exhaustive analysis of critical threats, listing all IP addresses with severity levels (Malicious, Suspicious, Harmless), detailed CTI data (e.g., abuse scores, malicious counts, geographic origins), and potential impact on the system.
- Anomalous Patterns: Identify and explain unusual activity patterns (e.g., high 404 ratios, malicious user agents) with specific examples from the data, hypothesize root causes, and correlate with CTI findings.
- Problem-Solving Approach: Deliver a robust strategy to address threats, including root cause analysis, specific mitigation tactics (e.g., IP blocking scripts, firewall rule updates, intrusion detection configurations), and sample configurations or code snippets where applicable.
- Recommendations: Present a prioritized action plan with clear, actionable steps, estimated timelines (e.g., immediate, within 24 hours, within 1 week), and suggested responsible teams or roles (e.g., network admins, security team).
- Additional Insights: Provide advanced observations (e.g., ISP trends, regional threat clusters, historical context) to enhance long-term security posture and prevent recurrence.
Output only the Markdown content for the report section (do not include <html>, <head>, or <body> tags).
Use Markdown syntax with ## for main sections, ### for subsections, detailed lists, tables for data comparison, and emphasis for severity (e.g., **Malicious**).
Ensure the AI content is the highlight, offering deep insights, practical solutions, and a clear narrative to guide security responses.
"""
        findings_json = json.dumps(findings, indent=2)
        md_prompt = md_prompt.format(findings_json)
        ai_report_md = model.generate_content(md_prompt).text.strip()

    # Generate and save reports
    reports_dir = 'reports'
    os.makedirs(reports_dir, exist_ok=True)
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    html_path = os.path.join(reports_dir, f'report_{timestamp}.html')
    html_content = generate_html_report(suspicious_ips, log_summary, ai_report_html, timestamp)
    with open(html_path, 'w') as f:
        f.write(html_content)
    console.print(f"[green]HTML report saved: {html_path}[/green]")

    # Display dashboard
    display_dashboard(suspicious_ips, log_summary, ai_report_md)

if __name__ == "__main__":
    main()