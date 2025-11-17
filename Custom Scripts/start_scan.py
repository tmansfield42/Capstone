import os, json, subprocess

def arp_scan():
    result = subprocess.getoutput("sudo arp-scan --localnet")
    devices = []
    for line in result.splitlines():
        if ":" in line and "." in line:
            parts = line.split()
            devices.append({"ip": parts[0], "mac": parts[1]})
    return devices

def nmap_scan(ip):
    result = subprocess.getoutput(f"sudo nmap -sV -O -T4 -oX - {ip}")
    return result

def main():
    devices = arp_scan()
    scans = {}
    for d in devices:
        ip = d["ip"]
        print(f" Scanning {ip} ...")
        scans[ip] = nmap_scan(ip)
        print(f" Done with {ip}")
    with open("/home/pi/scan_results.json", "w") as f:
        json.dump(scans, f, indent=4)

if __name__ == "__main__":
    main()

