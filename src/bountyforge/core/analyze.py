import json
from typing import List, Dict


class NucleiScanAnalyzer:
    def __init__(self, scan_results_file: str):
        """
        Initialize the analyzer with the path to the Nuclei scan results file.
        :param scan_results_file: Path to the JSON file containing Nuclei scan results.
        """
        self.scan_results_file = scan_results_file

    def load_results(self) -> List[Dict]:
        """
        Load scan results from the JSON file.
        :return: List of scan result dictionaries.
        """
        try:
            with open(self.scan_results_file, 'r', encoding='utf-8') as file:
                return json.load(file)
        except (FileNotFoundError, json.JSONDecodeError) as e:
            print(f"Error loading scan results: {e}")
            return []

    def analyze_results(self) -> Dict[str, int]:
        """
        Analyze the scan results and provide a summary.
        :return: Dictionary with summary of findings.
        """
        results = self.load_results()
        summary = {
            "total_findings": 0,
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0
        }

        for result in results:
            severity = result.get("severity", "info").lower()
            summary["total_findings"] += 1
            if severity in summary:
                summary[severity] += 1

        return summary

    def print_summary(self):
        """
        Print a summary of the scan results.
        """
        summary = self.analyze_results()
        print("Nuclei Scan Results Summary:")
        print(f"Total Findings: {summary['total_findings']}")
        print(f"Critical: {summary['critical']}")
        print(f"High: {summary['high']}")
        print(f"Medium: {summary['medium']}")
        print(f"Low: {summary['low']}")
        print(f"Info: {summary['info']}")

# Example usage:
# analyzer = NucleiScanAnalyzer("path/to/nuclei_results.json")
# analyzer.print_summary()
