 # Port Scanner

A Python-based port scanner designed to scan for open TCP/UDP ports and provide OS detection for specified hosts. This tool is useful for network security analysis and penetration testing.

---

## Features
- Scans for open TCP and UDP ports.
- Multi-threaded scanning for efficiency.
- Detects operating systems of target hosts.
- Saves results to an output file for later analysis.
- Customizable scanning range (default: ports 1–1024).

---

## Prerequisites

Before running this script, ensure you have the following installed:

- **Python 3.8+**
- Required Python libraries (install via `pip`):
  ```bash
  pip install -r requirements.txt
  ```

---

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/canugod/port-scanner.git
   cd port-scanner
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

---

## Usage

Run the script by executing the following command:
```bash
python port_scanner.py
```

### Command-Line Arguments:
- `--host` (required): Target host IP address or hostname.
- `--ports` (optional): Port range to scan (e.g., `1-1024`).
- `--output` (optional): Path to save the scan results.

Example:
```bash
python port_scanner.py --host 192.168.1.1 --ports 1-500 --output results.txt
```

---

## Output
- The scan results will be saved in the specified output file (default: `scan_results.txt`).
- Output includes:
  - Open TCP/UDP ports
  - Detected OS (if applicable)

---

## File Structure
```
port-scanner/
├── port_scanner.py         # Main script
├── requirements.txt        # Python dependencies
├── scan_results.txt        # Default output file
└── README.md               # Documentation
```

---

## Dependencies
This script uses the following Python libraries:
- `socket`
- `concurrent.futures`
- `os`
- `argparse`
- `platform`

---

## Known Issues
- **Permissions**: Ensure you have appropriate permissions to scan the target host.
- **Firewall Restrictions**: Scanning may be blocked by firewalls or intrusion detection systems.

---

## Legal Disclaimer
This tool is designed for educational purposes only. Use it on networks you own or have explicit permission to test. Unauthorized use of this tool may violate local laws.

---

## Contributing
Contributions are welcome! To contribute:
1. Fork the repository.
2. Create a new branch (`git checkout -b feature-name`).
3. Commit your changes (`git commit -m 'Add new feature'`).
4. Push to the branch (`git push origin feature-name`).
5. Create a pull request.

---

## License
This project is licensed under the MIT License. See `LICENSE` for details.

---

## Author
Created by [Suraj](https://github.com/canugod). For any inquiries, please open an issue or contact me directly.

---
