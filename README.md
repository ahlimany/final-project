# CLADLA
Cybersecurity Log Analysis and Detection Tool

## Introduction
Cladla (Cybersecurity Log Analysis and Detection Tool) is a robust log analysis and cybersecurity threat intelligence (CTI) tool designed to process access log files and identify potential security threats. Built by Ahliman Abbasov, this tool was created to empower security operations center (SOC) analysts by detecting malicious IP activities, enriching data with CTI sources like AbuseIPDB, VirusTotal, and Talos, and generating actionable AI-powered reports. 

## How to Download
To get started with Cladla, clone the repository from GitHub using the following command:

```bash
git clone https://github.com/ahlimany/cladla.git
```

Navigate to the project directory:
```
bash cd cladla
```
## Installation

Ensure you have Python 3.10 or later installed on your system.
Install the required dependencies using the provided requirements.txt file:

```
bash pip3 install -r requirements.txt
```
### Dependencies
The tool relies on the following Python packages, listed in requirements.txt:

```
requests
beautifulsoup4
google-generativeai
rich
```

## How to Use

Prepare Your Log File:

Ensure you have an ```access_log.txt``` file containing JSON-formatted log entries with fields like remote_addr and status. Place it in the project directory or provide the full path.


Run the Tool:

Execute the script with the following command:
```
bash python3 cladla.py access_log.txt
```
The tool will:

Parse the log file and extract unique IPs.
Enrich IP data with CTI from AbuseIPDB, VirusTotal, and Talos.
Generate an AI-powered analyst report identifying threats and solutions.
Display a dashboard and save an HTML report in the reports/ directory.

## Output:

Check the console for a real-time dashboard.
Review the generated HTML report (e.g., report_20250912_210438.html) in the reports/ folder.



## License
This project is licensed under the MIT License. See the [LICENSE](./LISCENCE) file for details.
