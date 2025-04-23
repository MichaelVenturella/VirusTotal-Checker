"""
# VirusTotal Checker

## Overview
VirusTotal Checker is a Python-based command-line tool that scans Indicators of Compromise (IOCs) such as domains, IP addresses, and file hashes using the VirusTotal API. It retrieves and displays the reputation ratings for each IOC, including the number of malicious, suspicious, harmless, and undetected verdicts from VirusTotal's security vendors.

## Features
- Supports domains, IP addresses, and hashes (MD5, SHA1, SHA256).
- Command-line interface with flexible input/output options.
- ASCII art title for a user-friendly experience.
- Verbose logging for debugging.
- Output results to a JSON file for further analysis.
- Respects VirusTotal's API rate limits (4 requests/minute for free accounts).

## Requirements
- Python 3.6+
- `requests` library (`pip install requests`)
- A valid VirusTotal API key (sign up at [virustotal.com](https://www.virustotal.com/) to obtain one)

## Installation
1. Install Python 3.6 or higher.
2. Install the required library:
   ```bash
   pip install requests
   ```
3. Save the script as `virustotal_checker.py`.
4. Obtain a VirusTotal API key from your VirusTotal account.

## Usage
Run the script from the command line with the following syntax:
```bash
python virustotal_checker.py -k <api_key> [-f <input_file>] [-o <output_file>] [-v]
```

### Command-Line Switches
- `-k, --api-key` (required): Your VirusTotal API key.
- `-f, --file` (optional): Path to a text file containing IOCs (one per line).
- `-o, --output` (optional): Path to save results in JSON format.
- `-v, --verbose` (optional): Enable verbose logging for detailed execution info.
- `-stats` (optional): Provides a real-time progress update until completion of script execution

If no input file (`-f`) is provided, the script uses a default list of IOCs:
- `example.com` (domain)
- `8.8.8.8` (IP)
- `d41d8cd98f00b204e9800998ecf8427e` (MD5 hash)
- `invalid_ioc` (invalid IOC)

## Example
### Input File (`iocs.txt`)
```text
example.com
8.8.8.8
d41d8cd98f00b204e9800998ecf8427e
```

### Command
```bash
python virustotal_checker.py -k your_api_key_here -f iocs.txt -o results.json -v
```

### Output
```
    _          _          
   | |__   ___| |__   ___ 
   | '_ \ / __| '_ \ / __|
   | | | | (__| | | | (__ 
   | |_| |_| \___|_| |_| \___|
      VirusTotal Checker

2025-04-23 10:00:01,123 - DEBUG - Querying domain: example.com
IOC: example.com
Type: domain
Malicious: 0
Suspicious: 0
Harmless: 72
Undetected: 20
Total Scans: 92

2025-04-23 10:00:16,456 - DEBUG - Querying ip: 8.8.8.8
IOC: 8.8.8.8
Type: ip
Malicious: 0
Suspicious: 0
Harmless: 68
Undetected: 24
Total Scans: 92

2025-04-23 10:00:31,789 - DEBUG - Querying hash: d41d8cd98f00b204e9800998ecf8427e
IOC: d41d8cd98f00b204e9800998ecf8427e
Type: hash
Malicious: 0
Suspicious: 0
Harmless: 65
Undetected: 27
Total Scans: 92

Results saved to results.json
```

### Output File (`results.json`)
```json
[
  {
    "ioc": "example.com",
    "type": "domain",
    "status": "success",
    "malicious": 0,
    "suspicious": 0,
    "harmless": 72,
    "undetected": 20,
    "total_scans": 92
  },
  {
    "ioc": "8.8.8.8",
    "type": "ip",
    "status": "success",
    "malicious": 0,
    "suspicious": 0,
    "harmless": 68,
    "undetected": 24,
    "total_scans": 92
  },
  {
    "ioc": "d41d8cd98f00b204e9800998ecf8427e",
    "type": "hash",
    "status": "success",
    "malicious": 0,
    "suspicious": 0,
    "harmless": 65,
    "undetected": 27,
    "total_scans": 92
  }
]
```

## Notes
- **API Key**: Keep your VirusTotal API key secure and do not share it publicly.
- **Rate Limiting**: The script includes a 15-second delay between requests to comply with VirusTotal's free API limit (4 requests/minute).
- **Error Handling**: The script handles invalid IOCs, file errors, and API issues (e.g., rate limits, HTTP errors).
- **Output**: Results are printed to the console and optionally saved to a JSON file for further analysis.
- **Verbose Mode**: Use `-v` to see detailed logs, useful for debugging.

## License
This tool is provided under the MIT License. Use it responsibly and in accordance with VirusTotal's terms of service.
"""
