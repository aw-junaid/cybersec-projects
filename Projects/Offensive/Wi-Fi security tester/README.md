## How to Run This Script

### Prerequisites
1. **Linux system** (tested on Ubuntu, Debian, Fedora)
2. **NetworkManager** installed (usually comes pre-installed)
3. **Python 3** installed
4. **Wi-Fi adapter** that supports scanning

### Step-by-Step Instructions

1. **Make the script executable:**
   ```bash
   chmod +x wifi_tester.py
   ```

2. **Run the script:**
   ```bash
   ./wifi_tester.py
   ```
   Or using Python directly:
   ```bash
   python3 wifi_tester.py
   ```

3. **Expected output:**
   ```
   Scanning for Wi-Fi networks...

   === Wi-Fi Security Report ===

   SSID: MyHomeNetwork
     Security: WPA2
     Signal: 85%
     Score: 100/100
      - OK

   SSID: CoffeeShopWiFi
     Security: OPEN
     Signal: 60%
     Score: 30/100
      - Weak encryption (Open/WEP)

   SSID: linksys12345
     Security: WPA2
     Signal: 45%
     Score: 85/100
      - Default SSID detected

   Report saved to wifi_report.json
   ```

### Troubleshooting

**If you get "nmcli not found" error:**
- Install NetworkManager:
  ```bash
  # Ubuntu/Debian
  sudo apt update && sudo apt install network-manager
  
  # Fedora/RHEL
  sudo dnf install NetworkManager
  ```

**If you get permission errors:**
- Run with sudo (but be cautious):
  ```bash
  sudo python3 wifi_tester.py
  ```

**If no networks are detected:**
- Ensure Wi-Fi is enabled on your system
- Check if you're in a location with Wi-Fi networks
- Verify NetworkManager is running:
  ```bash
  systemctl status NetworkManager
  ```

### Output Files
- **Console output**: Human-readable security report
- **wifi_report.json**: Detailed JSON data for further analysis

### Security Notes
- This tool is for **educational purposes only**
- Only scan networks you own or have permission to test
- The analysis is **read-only** - it doesn't attempt to connect or crack networks
- Results help identify potential security improvements for your own networks

The script provides a safety score (0-100) for each detected network based on encryption strength, SSID naming conventions, and signal quality.
