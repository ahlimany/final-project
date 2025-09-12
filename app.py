# app.py
import sys
import os
from flask import Flask, request, render_template, send_file
from threading import Thread
from log_analyzer import analyze_logs, generate_report, get_api_keys, configure_apis

app = Flask(__name__)
UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs('reports', exist_ok=True)

abuseipdb_api_key, virustotal_api_key, gemini_api_key = get_api_keys()
if gemini_api_key:
    configure_apis(gemini_api_key)

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        if 'logfile' not in request.files:
            return 'No file part'
        file = request.files['logfile']
        if file.filename == '':
            return 'No selected file'
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
        file.save(filepath)
        
        # Run analysis in a background thread
        thread = Thread(target=run_analysis, args=(filepath, abuseipdb_api_key, virustotal_api_key, gemini_api_key))
        thread.start()
        
        return 'Analysis started in the background. Check <a href="/report">/report</a> in 1-5 minutes for the results.'
    
    return render_template('index.html')

def run_analysis(filepath, abuseipdb_api_key, virustotal_api_key, gemini_api_key):
    findings, stats = analyze_logs(filepath, abuseipdb_api_key, virustotal_api_key)
    report_file = os.path.join('reports', 'threat_report.html')
    generate_report(findings, stats, report_file, gemini_api_key)

@app.route('/report')
def get_report():
    report_file = os.path.join('reports', 'threat_report.html')
    if os.path.exists(report_file):
        return send_file(report_file)
    else:
        return 'Report is not ready yet. Please try again in a few minutes or refresh the page.'

if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == 'cli':
        log_file = sys.argv[2] if len(sys.argv) > 2 else 'access_log.txt'
        max_lines = int(sys.argv[3]) if len(sys.argv) > 3 else None
        findings, stats = analyze_logs(log_file, abuseipdb_api_key, virustotal_api_key, max_lines)
        report_file = os.path.join('reports', 'threat_report.html')
        generate_report(findings, stats, report_file, gemini_api_key)
        print(f"Analysis complete. See '{report_file}' for the full report.")
    else:
        app.run(debug=True)