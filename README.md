# Log Analysis & CTI Tool

## Description

This is a Python-based Security Operations Center (SOC) tool designed to analyze web server access logs, enrich them with Cyber Threat Intelligence (CTI) from AbuseIPDB, VirusTotal, and Cisco Talos, and provide statistical insights and actionable AI-generated reports. It supports both CLI and web-based interfaces, making it suitable for analyzing log files to detect suspicious activities and potential threats.

## Instructions

### 1. Install Requirements

To set up the tool, install the required Python packages by running:

```bash
pip install -r requirements.txt
```

Ensure you have Python 3.8+ installed on your system.

### 2. CLI Mode (Recommended)

The CLI mode is lightweight and efficient, ideal for most use cases. To run the tool:

```bash
python app.py cli <path_to_log_file>
```

- Replace `<path_to_log_file>` with the path to your log file (e.g., `access_log.txt`).
- The tool will process the log, generate a report, and save it as `threat_report.html` in the `reports/` directory.
- This mode is **recommended** as it consumes minimal resources.

- To open the report use (Ex: you use firefox browser, if not replace the 'firefox' with your browser)
```bash
firefox reports/threat_report
```

### 3. Web Mode (Not Recommended)

The web mode uses a Flask server and requires more system resources, making it less efficient. To run:

```bash
python app.py
```

- Open your browser and navigate to `http://localhost:5000`.
- Upload a log file via the web interface to generate a report.
- Note: This mode is resource-intensive and should only be used if a GUI is specifically needed.

## Licensing

This tool is released under the GNU GENERAL PUBLIC LICENSE. You are free to use, modify, and distribute it, subject to the terms of the license. See the [LICENSE](./LICENSE) file for details.