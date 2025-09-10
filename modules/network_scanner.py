"""
Network Scanner Module
Provides network scanning capabilities including port scanning, host discovery, and service detection.
"""

import socket
import subprocess
import sys
import threading
import time
from typing import List, Dict, Tuple


class NetworkScanner:
    """Network scanning functionality for the cybersecurity toolkit."""
    
    def __init__(self):
        """Initialize the network scanner."""
        self.scan_results = []
        self.open_ports = []
        self.hosts_found = []
    
    def display_menu(self):
        """Display network scanning menu options."""
        print("\n" + "-"*40)
        print("NETWORK SCANNING OPTIONS")
        print("-"*40)
        print("1. Port Scan (Single Host)")
        print("2. Port Scan (Multiple Hosts)")
        print("3. Host Discovery (Network Scan)")
        print("4. Service Detection")
        print("5. Vulnerability Scan (Basic)")
        print("6. View Scan Results")
        print("7. Export Results")
        print("8. Back to Main Menu")
        print("-"*40)
    
    def get_user_choice(self):
        """Get user's menu choice with validation."""
        while True:
            try:
                choice = input("\nEnter your choice (1-8): ").strip()
                if choice in ['1', '2', '3', '4', '5', '6', '7', '8']:
                    return int(choice)
                else:
                    print("Invalid choice. Please enter a number between 1-8.")
            except KeyboardInterrupt:
                return 8
            except Exception as e:
                print(f"Error: {e}. Please try again.")
    
    def port_scan_single(self):
        """Scan ports on a single host."""
        print("\n--- PORT SCAN (SINGLE HOST) ---")
        host = input("Enter target host (IP or hostname): ").strip()
        
        if not host:
            print("Error: Host cannot be empty.")
            return
        
        print("Enter port range to scan:")
        start_port = self.get_port_input("Start port (1-65535): ")
        end_port = self.get_port_input("End port (1-65535): ")
        
        if start_port is None or end_port is None:
            return
        
        if start_port > end_port:
            print("Error: Start port cannot be greater than end port.")
            return
        
        print(f"\nScanning {host} from port {start_port} to {end_port}...")
        self.scan_ports(host, start_port, end_port)
    
    def port_scan_multiple(self):
        """Scan ports on multiple hosts."""
        print("\n--- PORT SCAN (MULTIPLE HOSTS) ---")
        hosts_input = input("Enter target hosts (comma-separated IPs or hostnames): ").strip()
        
        if not hosts_input:
            print("Error: Hosts cannot be empty.")
            return
        
        hosts = [host.strip() for host in hosts_input.split(',')]
        
        print("Enter port range to scan:")
        start_port = self.get_port_input("Start port (1-65535): ")
        end_port = self.get_port_input("End port (1-65535): ")
        
        if start_port is None or end_port is None:
            return
        
        if start_port > end_port:
            print("Error: Start port cannot be greater than end port.")
            return
        
        print(f"\nScanning {len(hosts)} hosts from port {start_port} to {end_port}...")
        for host in hosts:
            if host:
                print(f"\nScanning {host}...")
                self.scan_ports(host, start_port, end_port)
    
    def get_port_input(self, prompt: str) -> int:
        """Get port number input with validation."""
        while True:
            try:
                port = input(prompt).strip()
                if not port:
                    return None
                port = int(port)
                if 1 <= port <= 65535:
                    return port
                else:
                    print("Error: Port must be between 1 and 65535.")
            except ValueError:
                print("Error: Please enter a valid port number.")
            except KeyboardInterrupt:
                return None
    
    def scan_ports(self, host: str, start_port: int, end_port: int):
        """Scan ports on the specified host."""
        open_ports = []
        
        def scan_port(port):
            """Scan a single port."""
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((host, port))
                if result == 0:
                    open_ports.append(port)
                    print(f"Port {port}: OPEN")
                sock.close()
            except Exception:
                pass
        
        # Use threading for faster scanning
        threads = []
        for port in range(start_port, end_port + 1):
            thread = threading.Thread(target=scan_port, args=(port,))
            threads.append(thread)
            thread.start()
        
        # Wait for all threads to complete
        for thread in threads:
            thread.join()
        
        if open_ports:
            print(f"\nFound {len(open_ports)} open ports on {host}: {sorted(open_ports)}")
            self.scan_results.append({
                'host': host,
                'open_ports': sorted(open_ports),
                'scan_time': time.strftime('%Y-%m-%d %H:%M:%S')
            })
        else:
            print(f"No open ports found on {host}")
    
    def host_discovery(self):
        """Discover hosts on the local network."""
        print("\n--- HOST DISCOVERY ---")
        network = input("Enter network (e.g., 192.168.1.0/24): ").strip()
        
        if not network:
            print("Error: Network cannot be empty.")
            return
        
        print(f"Discovering hosts on {network}...")
        print("This may take a few minutes...")
        
        # Basic ping sweep (placeholder implementation)
        self.ping_sweep(network)
    
    def ping_sweep(self, network: str):
        """Perform a ping sweep to discover hosts."""
        # This is a placeholder implementation
        # In a real implementation, you would parse the network CIDR
        # and ping each IP address in the range
        
        print("Ping sweep functionality - PLACEHOLDER")
        print("To implement:")
        print("1. Parse network CIDR notation")
        print("2. Generate list of IP addresses to ping")
        print("3. Use subprocess to run ping commands")
        print("4. Parse ping results to identify live hosts")
        print("5. Store results in self.hosts_found")
        
        # Example of what the implementation might look like:
        # import ipaddress
        # network_obj = ipaddress.ip_network(network, strict=False)
        # for ip in network_obj.hosts():
        #     if self.ping_host(str(ip)):
        #         self.hosts_found.append(str(ip))
    
    def service_detection(self):
        """Detect services running on open ports."""
        print("\n--- SERVICE DETECTION ---")
        
        if not self.scan_results:
            print("No scan results available. Please run a port scan first.")
            return
        
        print("Service detection functionality - PLACEHOLDER")
        print("To implement:")
        print("1. Use socket connections to probe open ports")
        print("2. Send service-specific probes (HTTP, SSH, FTP, etc.)")
        print("3. Parse service banners and responses")
        print("4. Match against known service signatures")
        print("5. Store service information with port data")
    
    def vulnerability_scan(self):
        """Perform basic vulnerability scanning."""
        print("\n--- VULNERABILITY SCAN ---")
        print("Vulnerability scanning functionality - PLACEHOLDER")
        print("To implement:")
        print("1. Check for common vulnerable services")
        print("2. Test for default credentials")
        print("3. Check for outdated software versions")
        print("4. Look for misconfigurations")
        print("5. Generate vulnerability report")
    
    def view_results(self):
        """Display scan results."""
        print("\n--- SCAN RESULTS ---")
        
        if not self.scan_results:
            print("No scan results available.")
            return
        
        for i, result in enumerate(self.scan_results, 1):
            print(f"\nScan {i}:")
            print(f"  Host: {result['host']}")
            print(f"  Open Ports: {result['open_ports']}")
            print(f"  Scan Time: {result['scan_time']}")
    
    def export_results(self):
        """Export scan results to file."""
        print("\n--- EXPORT RESULTS ---")
        
        if not self.scan_results:
            print("No scan results to export.")
            return
        
        filename = input("Enter filename to save results (e.g., scan_results.txt): ").strip()
        if not filename:
            print("Error: Filename cannot be empty.")
            return
        
        try:
            with open(filename, 'w') as f:
                f.write("Cybersecurity Toolkit - Network Scan Results\n")
                f.write("="*50 + "\n\n")
                
                for i, result in enumerate(self.scan_results, 1):
                    f.write(f"Scan {i}:\n")
                    f.write(f"  Host: {result['host']}\n")
                    f.write(f"  Open Ports: {result['open_ports']}\n")
                    f.write(f"  Scan Time: {result['scan_time']}\n\n")
            
            print(f"Results exported to {filename}")
        except Exception as e:
            print(f"Error exporting results: {e}")
    
    def run(self):
        """Main network scanning interface."""
        while True:
            try:
                self.display_menu()
                choice = self.get_user_choice()
                
                if choice == 1:
                    self.port_scan_single()
                elif choice == 2:
                    self.port_scan_multiple()
                elif choice == 3:
                    self.host_discovery()
                elif choice == 4:
                    self.service_detection()
                elif choice == 5:
                    self.vulnerability_scan()
                elif choice == 6:
                    self.view_results()
                elif choice == 7:
                    self.export_results()
                elif choice == 8:
                    break
                
                if choice != 8:
                    input("\nPress Enter to continue...")
                    
            except KeyboardInterrupt:
                print("\n\nReturning to main menu...")
                break
            except Exception as e:
                print(f"\nAn error occurred: {e}")
                input("Press Enter to continue...")


# Example usage and testing
if __name__ == "__main__":
    scanner = NetworkScanner()
    scanner.run()
