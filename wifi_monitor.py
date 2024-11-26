import subprocess
import json
import time
import logging
import os

# Define log file path
LOG_FILE_PATH = '/home/bjorn/Bjorn/data/logs/wifi_monitor.log'

# Configure the logger
logger = logging.getLogger("wifi_monitor")
logger.setLevel(logging.DEBUG)

# Create file handler to log to a specific file
file_handler = logging.FileHandler(LOG_FILE_PATH)
file_handler.setLevel(logging.DEBUG)

# Create console handler for real-time console output
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)

# Define log format
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
file_handler.setFormatter(formatter)
console_handler.setFormatter(formatter)

# Add handlers to the logger
logger.addHandler(file_handler)
logger.addHandler(console_handler)

# Path to JSON file with Wi-Fi credentials
WIFI_CREDENTIALS_FILE = '/home/bjorn/Bjorn/config/wifi_networks.json'
CHECK_INTERVAL = 60  # Time in seconds to check for idle status and scan networks

def load_wifi_credentials():
    """Load Wi-Fi credentials from JSON file."""
    try:
        with open(WIFI_CREDENTIALS_FILE, 'r') as file:
            credentials = json.load(file)
        logger.info("Wi-Fi credentials loaded successfully.")
        return credentials
    except Exception as e:
        logger.error(f"Error loading Wi-Fi credentials: {e}")
        return []

def scan_available_networks():
    """Scan for available Wi-Fi networks using `iwlist`."""
    try:
        result = subprocess.run(["sudo", "iwlist", "wlan0", "scan"], capture_output=True, text=True)
        available_networks = []
        for line in result.stdout.splitlines():
            if "ESSID:" in line:
                ssid = line.split(":")[1].strip().strip('"')
                available_networks.append(ssid)
            elif "Address:" in line:
                bssid = line.split("Address:")[1].strip()
                available_networks.append(bssid)
        return available_networks
    except subprocess.CalledProcessError as e:
        logger.error(f"Wi-Fi scan failed: {e.stderr}")
        return []

def connect_to_network(ssid, password):
    """Connect to a Wi-Fi network using `nmcli`."""
    try:
        # Disconnect from any existing network
        subprocess.run(["nmcli", "device", "disconnect", "wlan0"], check=True)
        
        # Connect to the new network
        connect_command = ["nmcli", "device", "wifi", "connect", ssid, "password", password]
        result = subprocess.run(connect_command, capture_output=True, text=True, check=True)
        
        logger.info(f"Successfully connected to network {ssid}")
        return True
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to connect to {ssid}: {e.stderr}")
        return False

def switch_network_if_idle(orchestrator):
    """Check if Bjorn is idle and switch networks if a known one is available."""
    credentials = load_wifi_credentials()
    
    while True:
        # Check if Bjorn is idle
        if orchestrator.shared_data.bjornorch_status == "idle_action":  
            logger.info("Bjorn is idle. Scanning for known networks...")
            available_ssids = scan_available_networks()
            
            # Attempt to connect to any known network in range
            for network in credentials:
                if network['SSID'] in available_ssids or network.get('BSSID') in available_ssids:
                    logger.info(f"Found known network {network['SSID']}. Attempting to connect...")
                    
                    if connect_to_network(network['SSID'], network['Password']):
                        logger.info(f"Connected to {network['SSID']}. Network switching complete.")
                        break  # Stop after connecting to a new network

        # Wait before checking again
        time.sleep(CHECK_INTERVAL)
