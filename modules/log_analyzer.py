"""
Log Analyzer Module
Provides log analysis capabilities including parsing, pattern detection, and security monitoring.
"""

import os
import re
import json
import csv
import time
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
from collections import defaultdict, Counter


class LogAnalyzer:
    """Log analysis functionality for the cybersecurity toolkit."""
    
    def __init__(self):
        """Initialize the log analyzer."""
        self.log_entries = []
        self.analysis_results = {}
        self.suspicious_activities = []
        self.patterns_detected = []
    
    def display_menu(self):
        """Display log analysis menu options."""
        print("\n" + "-"*40)
        print("LOG ANALYSIS OPTIONS")
        print("-"*40)
        print("1. Load Log File")
        print("2. Parse System Logs")
        print("3. Detect Suspicious Activities")
        print("4. Search for Patterns")
        print("5. Generate Security Report")
        print("6. Real-time Log Monitoring")
        print("7. Export Analysis Results")
        print("8. View Analysis History")
        print("9. Back to Main Menu")
        print("-"*40)
    
    def get_user_choice(self):
        """Get user's menu choice with validation."""
        while True:
            try:
                choice = input("\nEnter your choice (1-9): ").strip()
                if choice in ['1', '2', '3', '4', '5', '6', '7', '8', '9']:
                    return int(choice)
                else:
                    print("Invalid choice. Please enter a number between 1-9.")
            except KeyboardInterrupt:
                return 9
            except Exception as e:
                print(f"Error: {e}. Please try again.")
    
    def load_log_file(self):
        """Load a log file for analysis."""
        print("\n--- LOAD LOG FILE ---")
        file_path = input("Enter path to log file: ").strip()
        
        if not file_path:
            print("Error: File path cannot be empty.")
            return
        
        if not os.path.exists(file_path):
            print(f"Error: File '{file_path}' not found.")
            return
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
                self.log_entries = file.readlines()
            
            print(f"Successfully loaded {len(self.log_entries)} log entries.")
            
            # Ask if user wants to parse immediately
            parse_now = input("Parse log entries now? (y/n): ").strip().lower()
            if parse_now == 'y':
                self.parse_logs()
                
        except Exception as e:
            print(f"Error loading log file: {e}")
    
    def parse_logs(self):
        """Parse loaded log entries."""
        print("\n--- PARSING LOG ENTRIES ---")
        
        if not self.log_entries:
            print("No log entries loaded. Please load a log file first.")
            return
        
        parsed_count = 0
        for i, entry in enumerate(self.log_entries):
            try:
                parsed_entry = self.parse_log_entry(entry.strip())
                if parsed_entry:
                    self.log_entries[i] = parsed_entry
                    parsed_count += 1
            except Exception as e:
                print(f"Error parsing entry {i+1}: {e}")
        
        print(f"Successfully parsed {parsed_count} log entries.")
    
    def parse_log_entry(self, entry: str) -> Optional[Dict[str, Any]]:
        """Parse a single log entry."""
        # This is a placeholder implementation
        # Real implementation would depend on log format (syslog, apache, etc.)
        
        # Basic parsing for common log formats
        parsed = {
            'raw': entry,
            'timestamp': None,
            'level': None,
            'source': None,
            'message': entry,
            'parsed': False
        }
        
        # Try to extract timestamp (common formats)
        timestamp_patterns = [
            r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})',
            r'(\w{3} \d{1,2} \d{2}:\d{2}:\d{2})',
            r'(\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2})'
        ]
        
        for pattern in timestamp_patterns:
            match = re.search(pattern, entry)
            if match:
                parsed['timestamp'] = match.group(1)
                break
        
        # Try to extract log level
        level_patterns = [
            r'(ERROR|WARN|INFO|DEBUG|CRITICAL)',
            r'(error|warning|info|debug|critical)',
            r'(\d+\.\d+\.\d+\.\d+)'  # IP address
        ]
        
        for pattern in level_patterns:
            match = re.search(pattern, entry, re.IGNORECASE)
            if match:
                parsed['level'] = match.group(1).upper()
                break
        
        parsed['parsed'] = True
        return parsed
    
    def detect_suspicious_activities(self):
        """Detect suspicious activities in logs."""
        print("\n--- DETECTING SUSPICIOUS ACTIVITIES ---")
        
        if not self.log_entries:
            print("No log entries loaded. Please load a log file first.")
            return
        
        print("Suspicious activity detection - PLACEHOLDER")
        print("To implement:")
        print("1. Failed login attempts (brute force)")
        print("2. Unusual access patterns")
        print("3. Privilege escalation attempts")
        print("4. File system changes")
        print("5. Network anomalies")
        print("6. Malware indicators")
        
        # Example implementation structure:
        suspicious_patterns = [
            r'failed.*login',
            r'authentication.*failed',
            r'access.*denied',
            r'permission.*denied',
            r'root.*login',
            r'sudo.*failed'
        ]
        
        detected_count = 0
        for entry in self.log_entries:
            if isinstance(entry, dict) and entry.get('parsed'):
                for pattern in suspicious_patterns:
                    if re.search(pattern, entry['message'], re.IGNORECASE):
                        self.suspicious_activities.append({
                            'entry': entry,
                            'pattern': pattern,
                            'timestamp': entry.get('timestamp', 'Unknown')
                        })
                        detected_count += 1
                        break
        
        print(f"Detected {detected_count} potentially suspicious activities.")
    
    def search_patterns(self):
        """Search for specific patterns in logs."""
        print("\n--- SEARCH FOR PATTERNS ---")
        
        if not self.log_entries:
            print("No log entries loaded. Please load a log file first.")
            return
        
        pattern = input("Enter search pattern (regex supported): ").strip()
        if not pattern:
            print("Error: Pattern cannot be empty.")
            return
        
        try:
            regex = re.compile(pattern, re.IGNORECASE)
            matches = []
            
            for i, entry in enumerate(self.log_entries):
                if isinstance(entry, dict) and entry.get('parsed'):
                    if regex.search(entry['message']):
                        matches.append({
                            'line_number': i + 1,
                            'entry': entry,
                            'match': regex.search(entry['message']).group()
                        })
                elif isinstance(entry, str):
                    if regex.search(entry):
                        matches.append({
                            'line_number': i + 1,
                            'entry': {'raw': entry, 'message': entry},
                            'match': regex.search(entry).group()
                        })
            
            print(f"Found {len(matches)} matches for pattern '{pattern}':")
            for match in matches[:10]:  # Show first 10 matches
                print(f"  Line {match['line_number']}: {match['match']}")
            
            if len(matches) > 10:
                print(f"  ... and {len(matches) - 10} more matches")
            
            self.patterns_detected.extend(matches)
            
        except re.error as e:
            print(f"Error: Invalid regex pattern: {e}")
        except Exception as e:
            print(f"Error searching patterns: {e}")
    
    def generate_security_report(self):
        """Generate a comprehensive security report."""
        print("\n--- GENERATING SECURITY REPORT ---")
        
        if not self.log_entries:
            print("No log entries loaded. Please load a log file first.")
            return
        
        print("Security report generation - PLACEHOLDER")
        print("To implement:")
        print("1. Summary statistics")
        print("2. Top error sources")
        print("3. Failed authentication attempts")
        print("4. Unusual access patterns")
        print("5. Security recommendations")
        print("6. Risk assessment")
        
        # Basic report generation
        report = {
            'generated_at': datetime.now().isoformat(),
            'total_entries': len(self.log_entries),
            'suspicious_activities': len(self.suspicious_activities),
            'patterns_found': len(self.patterns_detected),
            'summary': self.generate_summary()
        }
        
        self.analysis_results['security_report'] = report
        
        print("\nSecurity Report Generated:")
        print(f"  Total log entries: {report['total_entries']}")
        print(f"  Suspicious activities: {report['suspicious_activities']}")
        print(f"  Patterns detected: {report['patterns_found']}")
    
    def generate_summary(self) -> Dict[str, Any]:
        """Generate summary statistics from logs."""
        summary = {
            'error_count': 0,
            'warning_count': 0,
            'info_count': 0,
            'unique_sources': set(),
            'time_range': {'start': None, 'end': None}
        }
        
        for entry in self.log_entries:
            if isinstance(entry, dict) and entry.get('parsed'):
                level = entry.get('level', '').upper()
                if 'ERROR' in level:
                    summary['error_count'] += 1
                elif 'WARN' in level:
                    summary['warning_count'] += 1
                elif 'INFO' in level:
                    summary['info_count'] += 1
                
                if entry.get('source'):
                    summary['unique_sources'].add(entry['source'])
        
        summary['unique_sources'] = list(summary['unique_sources'])
        return summary
    
    def real_time_monitoring(self):
        """Monitor logs in real-time."""
        print("\n--- REAL-TIME LOG MONITORING ---")
        print("Real-time monitoring functionality - PLACEHOLDER")
        print("To implement:")
        print("1. File watching (using watchdog library)")
        print("2. Tail log files")
        print("3. Live pattern matching")
        print("4. Alert system")
        print("5. Dashboard updates")
        
        log_file = input("Enter log file path to monitor: ").strip()
        if not log_file or not os.path.exists(log_file):
            print("Invalid log file path.")
            return
        
        print(f"Monitoring {log_file}...")
        print("Press Ctrl+C to stop monitoring")
        
        # Placeholder for real-time monitoring
        try:
            while True:
                # In real implementation, use file watching
                time.sleep(1)
        except KeyboardInterrupt:
            print("\nMonitoring stopped.")
    
    def export_results(self):
        """Export analysis results to file."""
        print("\n--- EXPORT ANALYSIS RESULTS ---")
        
        if not self.analysis_results and not self.suspicious_activities:
            print("No analysis results to export.")
            return
        
        filename = input("Enter filename to save results (e.g., analysis_results.json): ").strip()
        if not filename:
            print("Error: Filename cannot be empty.")
            return
        
        try:
            export_data = {
                'analysis_results': self.analysis_results,
                'suspicious_activities': self.suspicious_activities,
                'patterns_detected': self.patterns_detected,
                'exported_at': datetime.now().isoformat()
            }
            
            if filename.endswith('.json'):
                with open(filename, 'w') as f:
                    json.dump(export_data, f, indent=2, default=str)
            elif filename.endswith('.csv'):
                self.export_to_csv(filename, export_data)
            else:
                with open(filename, 'w') as f:
                    f.write(json.dumps(export_data, indent=2, default=str))
            
            print(f"Results exported to {filename}")
        except Exception as e:
            print(f"Error exporting results: {e}")
    
    def export_to_csv(self, filename: str, data: Dict[str, Any]):
        """Export data to CSV format."""
        with open(filename, 'w', newline='') as csvfile:
            writer = csv.writer(csvfile)
            
            # Write suspicious activities
            if data['suspicious_activities']:
                writer.writerow(['Suspicious Activities'])
                writer.writerow(['Timestamp', 'Pattern', 'Message'])
                for activity in data['suspicious_activities']:
                    writer.writerow([
                        activity.get('timestamp', 'Unknown'),
                        activity.get('pattern', 'Unknown'),
                        activity['entry'].get('message', 'Unknown')
                    ])
                writer.writerow([])
            
            # Write patterns detected
            if data['patterns_detected']:
                writer.writerow(['Pattern Matches'])
                writer.writerow(['Line Number', 'Match', 'Message'])
                for pattern in data['patterns_detected']:
                    writer.writerow([
                        pattern.get('line_number', 'Unknown'),
                        pattern.get('match', 'Unknown'),
                        pattern['entry'].get('message', 'Unknown')
                    ])
    
    def view_analysis_history(self):
        """View analysis history and results."""
        print("\n--- ANALYSIS HISTORY ---")
        
        if not self.analysis_results and not self.suspicious_activities:
            print("No analysis history available.")
            return
        
        if self.analysis_results:
            print("\nAnalysis Results:")
            for key, value in self.analysis_results.items():
                print(f"  {key}: {value}")
        
        if self.suspicious_activities:
            print(f"\nSuspicious Activities ({len(self.suspicious_activities)}):")
            for i, activity in enumerate(self.suspicious_activities[:5], 1):
                print(f"  {i}. {activity.get('timestamp', 'Unknown')} - {activity.get('pattern', 'Unknown')}")
        
        if self.patterns_detected:
            print(f"\nPatterns Detected ({len(self.patterns_detected)}):")
            for i, pattern in enumerate(self.patterns_detected[:5], 1):
                print(f"  {i}. Line {pattern.get('line_number', 'Unknown')} - {pattern.get('match', 'Unknown')}")
    
    def run(self):
        """Main log analysis interface."""
        while True:
            try:
                self.display_menu()
                choice = self.get_user_choice()
                
                if choice == 1:
                    self.load_log_file()
                elif choice == 2:
                    self.parse_logs()
                elif choice == 3:
                    self.detect_suspicious_activities()
                elif choice == 4:
                    self.search_patterns()
                elif choice == 5:
                    self.generate_security_report()
                elif choice == 6:
                    self.real_time_monitoring()
                elif choice == 7:
                    self.export_results()
                elif choice == 8:
                    self.view_analysis_history()
                elif choice == 9:
                    break
                
                if choice != 9:
                    input("\nPress Enter to continue...")
                    
            except KeyboardInterrupt:
                print("\n\nReturning to main menu...")
                break
            except Exception as e:
                print(f"\nAn error occurred: {e}")
                input("Press Enter to continue...")


# Example usage and testing
if __name__ == "__main__":
    analyzer = LogAnalyzer()
    analyzer.run()
