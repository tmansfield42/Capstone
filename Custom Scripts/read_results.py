#!/usr/bin/env python3
import json
import sys
import xml.etree.ElementTree as ET # Import the XML parser
from datetime import datetime

# Define the file path in one place
JSON_FILE = "/home/pi/scan_results.json"

def parse_nmap_xml(xml_string):
    """
    Takes Nmap's raw XML output and parses it into a 
    human-readable summary.
    """
    summary = ""
    try:
        # Load the XML string into the parser
        root = ET.fromstring(xml_string)
        
        # Find the 'host' tag
        host = root.find('host')
        if host is None:
            return "Host data not found in XML.\n"
            
        # --- Get Host Status ---
        status = host.find('status')
        if status is not None and status.get('state') == 'down':
            return "Host was down.\n"

        # --- Get OS Guess ---
        os_match = host.find('os/osmatch')
        if os_match is not None:
            summary += f"  OS Guess: {os_match.get('name')} ({os_match.get('accuracy')}_ accuracy)\n"
        
        # --- Get Open Ports ---
        ports_element = host.find('ports')
        if ports_element is not None:
            summary += "  Open Ports:\n"
            open_ports = []
            for port in ports_element.findall('port'):
                if port.find('state').get('state') == 'open':
                    portid = port.get('portid')
                    service = port.find('service')
                    name = service.get('name', 'unknown')
                    product = service.get('product', '')
                    version = service.get('version', '')
                    
                    port_info = f"    - {portid}/tcp: {name}"
                    if product:
                        port_info += f" (Product: {product}, Version: {version})"
                    open_ports.append(port_info)
            
            if not open_ports:
                summary += "    (No open ports found)\n"
            else:
                summary += "\n".join(open_ports) + "\n"

        return summary

    except ET.ParseError:
        return "Scan failed (could not parse XML).\n"
    except Exception as e:
        return f"An error occurred during parsing: {e}\n"


def main():
    """
    Main function to load and display all scan results.
    """
    try:
        # Open and load the JSON file
        with open(JSON_FILE, "r") as f:
            scans = json.load(f)
    except FileNotFoundError:
        print(f"Error: Could not find results file at {JSON_FILE}")
        print("Please run the 'start_scan.py' script first.")
        return
    except json.JSONDecodeError:
        print(f"Error: Could not read {JSON_FILE}. File may be corrupt.")
        return

    print(f"Loaded {len(scans)} devices from {JSON_FILE}\n")
    
    # Loop through each scan in the file
    for ip, xml_data in scans.items():
        print("=" * 30)
        print(f"DEVICE: {ip}")
        print("=" * 30)
        
        # Parse the XML data for this device
        summary = parse_nmap_xml(xml_data)
        print(summary)


if __name__ == "__main__":
    main()
