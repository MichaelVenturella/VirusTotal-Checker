import requests
import json
import time
import argparse
import logging
from typing import Dict, List
from uuid import uuid4
from tqdm import tqdm  # Added for progress bar

class VirusTotalChecker:
    def __init__(self, api_key: str, verbose: bool = False):
        self.api_key = api_key
        self.base_url = "https://www.virustotal.com/api/v3"
        self.headers = {"x-apikey": self.api_key}
        self.logger = logging.getLogger("VirusTotalChecker")
        if verbose:
            self.logger.setLevel(logging.DEBUG)
        else:
            self.logger.setLevel(logging.INFO)

    def classify_ioc(self, ioc: str) -> str:
        """Classify IOC type based on its format."""
        if "." in ioc and not ioc.replace(".", "").isdigit():
            return "domain"
        elif ioc.replace(".", "").isdigit() and ioc.count(".") == 3:
            return "ip"
        elif len(ioc) in [32, 40, 64] and all(c in "0123456789abcdef" for c in ioc.lower()):
            return "hash"
        else:
            return "unknown"

    def query_ioc(self, ioc: str, ioc_type: str) -> Dict:
        """Query VirusTotal for a specific IOC."""
        if ioc_type == "domain":
            endpoint = f"{self.base_url}/domains/{ioc}"
        elif ioc_type == "ip":
            endpoint = f"{self.base_url}/ip_addresses/{ioc}"
        elif ioc_type == "hash":
            endpoint = f"{self.base_url}/files/{ioc}"
        else:
            return {"error": "Invalid IOC type", "ioc": ioc}

        self.logger.debug(f"Querying {ioc_type}: {ioc}")
        try:
            response = requests.get(endpoint, headers=self.headers)
            if response.status_code == 200:
                return response.json()
            elif response.status_code == 429:
                self.logger.warning("Rate limit exceeded")
                return {"error": "Rate limit exceeded", "ioc": ioc}
            else:
                self.logger.error(f"HTTP {response.status_code} for {ioc}")
                return {"error": f"HTTP {response.status_code}", "ioc": ioc}
        except requests.RequestException as e:
            self.logger.error(f"Request failed for {ioc}: {str(e)}")
            return {"error": str(e), "ioc": ioc}

    def parse_result(self, result: Dict, ioc: str, ioc_type: str) -> Dict:
        """Parse VirusTotal response and extract relevant rating information."""
        if "error" in result:
            return {
                "ioc": ioc,
                "type": ioc_type,
                "status": "error",
                "message": result["error"]
            }

        data = result.get("data", {}).get("attributes", {})
        last_analysis_stats = data.get("last_analysis_stats", {})
        
        return {
            "ioc": ioc,
            "type": ioc_type,
            "status": "success",
            "malicious": last_analysis_stats.get("malicious", 0),
            "suspicious": last_analysis_stats.get("suspicious", 0),
            "harmless": last_analysis_stats.get("harmless", 0),
            "undetected": last_analysis_stats.get("undetected", 0),
            "total_scans": sum(last_analysis_stats.values()),
        }

    def scan_iocs(self, iocs: List[str], show_stats: bool = False) -> List[Dict]:
        """Scan a list of IOCs and return their ratings."""
        results = []
        # Use tqdm for progress bar if show_stats is True
        ioc_iterator = tqdm(iocs, desc="Scanning IOCs", unit="ioc") if show_stats else iocs
        
        for ioc in ioc_iterator:
            ioc = ioc.strip()
            if not ioc:
                continue
                
            ioc_type = self.classify_ioc(ioc)
            if ioc_type == "unknown":
                self.logger.warning(f"Skipping invalid IOC: {ioc}")
                results.append({
                    "ioc": ioc,
                    "type": ioc_type,
                    "status": "error",
                    "message": "Invalid IOC format"
                })
                continue
                
            result = self.query_ioc(ioc, ioc_type)
            parsed_result = self.parse_result(result, ioc, ioc_type)
            results.append(parsed_result)
            
            # Respect VirusTotal's rate limit (4 requests per minute for free API)
            time.sleep(15)
            
        return results

def print_ascii_title():
    """Print ASCII art title for VirusTotal Checker."""
    ascii_art = """
    _          _          
   | |__   ___| |__   ___ 
   | '_ \ / __| '_ \ / __|
   | | | | (__| | | | (__ 
   |_| |_| \___|_| |_| \___|
      VirusTotal Checker
    """
    print(ascii_art)

def main():
    # Set up argument parser
    parser = argparse.ArgumentParser(description="VirusTotal Checker: Scan IOCs using VirusTotal API")
    parser.add_argument("-k", "--api-key", required=True, help="VirusTotal API key")
    parser.add_argument("-f", "--file", help="Input file with IOCs (one per line)")
    parser.add_argument("-o", "--output", help="Output file to save results (JSON format)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose logging")
    parser.add_argument("-stats", action="store_true", help="Show scanning progress stats")
    
    args = parser.parse_args()

    # Set up logging
    logging.basicConfig(format="%(asctime)s - %(levelname)s - %(message)s")
    
    # Print ASCII title
    print_ascii_title()

    # Initialize scanner
    scanner = VirusTotalChecker(args.api_key, args.verbose)

    # Load IOCs
    if args.file:
        try:
            with open(args.file, "r") as f:
                iocs = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print(f"Error: Input file '{args.file}' not found")
            return
    else:
        # Default IOCs if no file is provided
        iocs = [
            "example.com",
            "8.8.8.8",
            "d41d8cd98f00b204e9800998ecf8427e",
            "invalid_ioc"
        ]

    # Scan IOCs with stats option
    results = scanner.scan_iocs(iocs, show_stats=args.stats)

    # Print results
    for result in results:
        print("\nIOC:", result["ioc"])
        print("Type:", result["type"])
        if result["status"] == "success":
            print(f"Malicious: {result['malicious']}")
            print(f"Suspicious: {result['suspicious']}")
            print(f"Harmless: {result['harmless']}")
            print(f"Undetected: {result['undetected']}")
            print(f"Total Scans: {result['total_scans']}")
        else:
            print("Error:", result["message"])

    # Save results to output file if specified
    if args.output:
        try:
            with open(args.output, "w") as f:
                json.dump(results, f, indent=2)
            print(f"\nResults saved to {args.output}")
        except Exception as e:
            print(f"Error saving to output file: {str(e)}")

if __name__ == "__main__":
    main()
