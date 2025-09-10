# Cybersecurity Toolkit

A comprehensive Python-based cybersecurity toolkit providing essential tools for network scanning, log analysis, and file encryption.

## Features

### 🔍 Network Scanning

- Port scanning (single and multiple hosts)
- Host discovery on local networks
- Service detection and version identification
- Basic vulnerability scanning
- Export scan results to various formats

### 📊 Log Analysis

- Parse and analyze system logs
- Detect suspicious activities and patterns
- Real-time log monitoring
- Generate comprehensive security reports
- Support for multiple log formats

### 🔐 File Encryption

- AES encryption for files and directories
- Secure key generation and management
- Password-protected encryption keys
- Secure file deletion
- Batch encryption/decryption operations

## Installation

1. Clone the repository:

```bash
git clone <repository-url>
cd cybersecurity_project
```

2. Install dependencies:

```bash
pip install -r requirements.txt
```

3. Run the toolkit:

```bash
python cybersecurity_toolkit.py
```

## Usage

### Main Menu

The toolkit provides a user-friendly menu system with the following options:

1. **Network Scanning** - Scan networks and hosts for open ports and services
2. **Log Analysis** - Analyze log files for security threats and patterns
3. **File Encryption** - Encrypt/decrypt files and manage encryption keys
4. **Help & Documentation** - View detailed help and expansion guidelines
5. **Exit** - Close the application

### Network Scanning Module

- **Port Scan (Single Host)**: Scan a single target for open ports
- **Port Scan (Multiple Hosts)**: Scan multiple targets simultaneously
- **Host Discovery**: Discover live hosts on a network
- **Service Detection**: Identify services running on open ports
- **Vulnerability Scan**: Basic vulnerability assessment
- **View/Export Results**: Review and export scan results

### Log Analysis Module

- **Load Log File**: Load log files for analysis
- **Parse System Logs**: Parse various log formats
- **Detect Suspicious Activities**: Identify potential security threats
- **Search for Patterns**: Search logs using regex patterns
- **Generate Security Report**: Create comprehensive security reports
- **Real-time Monitoring**: Monitor logs in real-time
- **Export Results**: Export analysis results

### File Encryption Module

- **Generate New Key**: Create new encryption keys
- **Load Existing Key**: Load previously generated keys
- **Encrypt File**: Encrypt individual files
- **Decrypt File**: Decrypt encrypted files
- **Encrypt Directory**: Encrypt entire directories
- **Decrypt Directory**: Decrypt entire directories
- **Secure File Deletion**: Permanently delete files
- **Key Management**: Manage encryption keys

## Project Structure

```
cybersecurity_project/
├── cybersecurity_toolkit.py    # Main application entry point
├── modules/                     # Module directory
│   ├── __init__.py
│   ├── network_scanner.py      # Network scanning functionality
│   ├── log_analyzer.py         # Log analysis functionality
│   └── file_encryptor.py       # File encryption functionality
├── requirements.txt            # Python dependencies
└── README.md                   # This file
```

## Expansion Guidelines

### Adding New Features

Each module is designed to be easily extensible:

1. **Network Scanner**: Add new scanning techniques, vulnerability checks, or output formats
2. **Log Analyzer**: Add new log parsers, detection rules, or analysis algorithms
3. **File Encryptor**: Add new encryption algorithms, key management features, or security enhancements

### Development Best Practices

- Follow the existing code structure and patterns
- Add comprehensive error handling
- Include user input validation
- Update help documentation when adding features
- Test thoroughly before deployment

### Security Considerations

- Always validate user inputs
- Use secure random number generation for keys
- Implement proper error handling to avoid information disclosure
- Follow principle of least privilege
- Regular security audits and updates

## Dependencies

- Python 3.7+
- cryptography (for encryption)
- scapy (for network scanning)
- watchdog (for file monitoring)
- pandas (for data analysis)
- Additional dependencies listed in requirements.txt

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

This toolkit is for educational and authorized security testing purposes only. Users are responsible for ensuring they have proper authorization before using these tools on any network or system.

## Support

For questions, issues, or contributions, please open an issue on the project repository.
