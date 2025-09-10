#!/usr/bin/env python3
"""
Cybersecurity Toolkit - Main Application
A comprehensive Python toolkit for network scanning, log analysis, and file encryption.
"""

import sys
import os
from modules.network_scanner import NetworkScanner
from modules.log_analyzer import LogAnalyzer
from modules.file_encryptor import FileEncryptor
from modules.threat_analyzer import ThreatAnalyzer


class CybersecurityToolkit:
    """Main class for the Cybersecurity Toolkit application."""
    
    def __init__(self):
        """Initialize the toolkit with all modules."""
        self.network_scanner = NetworkScanner()
        self.log_analyzer = LogAnalyzer()
        self.file_encryptor = FileEncryptor()
        self.threat_analyzer = ThreatAnalyzer()
        self.running = True
    
    def display_menu(self):
        """Display the main menu options."""
        print("\n" + "="*60)
        print("           CYBERSECURITY TOOLKIT")
        print("="*60)
        print("1. Network Scanning")
        print("2. Log Analysis")
        print("3. File Encryption/Decryption")
        print("4. Threat Intelligence Analysis")
        print("5. Help & Documentation")
        print("6. Exit")
        print("="*60)
    
    def get_user_choice(self):
        """Get user's menu choice with input validation."""
        while True:
            try:
                choice = input("\nEnter your choice (1-6): ").strip()
                if choice in ['1', '2', '3', '4', '5', '6']:
                    return int(choice)
                else:
                    print("Invalid choice. Please enter a number between 1-6.")
            except KeyboardInterrupt:
                print("\n\nExiting...")
                return 6
            except Exception as e:
                print(f"Error: {e}. Please try again.")
    
    def run_network_scanning(self):
        """Run the network scanning module."""
        print("\n" + "-"*50)
        print("NETWORK SCANNING MODULE")
        print("-"*50)
        self.network_scanner.run()
    
    def run_log_analysis(self):
        """Run the log analysis module."""
        print("\n" + "-"*50)
        print("LOG ANALYSIS MODULE")
        print("-"*50)
        self.log_analyzer.run()
    
    def run_file_encryption(self):
        """Run the file encryption module."""
        print("\n" + "-"*50)
        print("FILE ENCRYPTION MODULE")
        print("-"*50)
        self.file_encryptor.run()
    
    def run_threat_analysis(self):
        """Run the threat intelligence analysis module."""
        print("\n" + "-"*50)
        print("THREAT INTELLIGENCE ANALYSIS MODULE")
        print("-"*50)
        self.threat_analyzer.run()
    
    def show_help(self):
        """Display help and documentation."""
        print("\n" + "-"*50)
        print("HELP & DOCUMENTATION")
        print("-"*50)
        print("""
CYBERSECURITY TOOLKIT - MODULE DESCRIPTIONS:

1. NETWORK SCANNING:
   - Port scanning to identify open ports
   - Host discovery on local network
   - Service detection and version identification
   - Network vulnerability assessment
   
2. LOG ANALYSIS:
   - Parse and analyze system logs
   - Detect suspicious activities and patterns
   - Generate security reports
   - Real-time log monitoring
   
3. FILE ENCRYPTION:
   - Encrypt files with AES encryption
   - Decrypt files with proper authentication
   - Generate and manage encryption keys
   - Secure file deletion

4. THREAT INTELLIGENCE ANALYSIS:
   - Analyze cybersecurity threat datasets
   - Geographic and industry impact analysis
   - Temporal trend identification
   - Financial impact assessment
   - Vulnerability and defense effectiveness analysis
   - Generate comprehensive threat intelligence reports

EXPANSION GUIDELINES:
- Each module is designed to be easily extensible
- Add new functions to respective module classes
- Follow the existing pattern for user interaction
- Update this help section when adding new features
- Consider adding configuration files for advanced settings

REQUIREMENTS:
- Python 3.7+
- See requirements.txt for specific dependencies
- Some modules may require additional system permissions
        """)
    
    def run(self):
        """Main application loop."""
        print("Welcome to the Cybersecurity Toolkit!")
        print("This toolkit provides essential cybersecurity tools for analysis and protection.")
        
        while self.running:
            try:
                self.display_menu()
                choice = self.get_user_choice()
                
                if choice == 1:
                    self.run_network_scanning()
                elif choice == 2:
                    self.run_log_analysis()
                elif choice == 3:
                    self.run_file_encryption()
                elif choice == 4:
                    self.run_threat_analysis()
                elif choice == 5:
                    self.show_help()
                elif choice == 6:
                    print("\nThank you for using the Cybersecurity Toolkit!")
                    self.running = False
                
                if self.running:
                    input("\nPress Enter to continue...")
                    
            except KeyboardInterrupt:
                print("\n\nExiting...")
                self.running = False
            except Exception as e:
                print(f"\nAn error occurred: {e}")
                print("Please try again or contact support.")
                input("Press Enter to continue...")


def main():
    """Main entry point of the application."""
    try:
        toolkit = CybersecurityToolkit()
        toolkit.run()
    except Exception as e:
        print(f"Failed to start Cybersecurity Toolkit: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
