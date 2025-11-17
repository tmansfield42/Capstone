import json
from vuln_database import VULN_DB

def extract_services(nmap_xml_string):
    services = []
    for line in nmap_xml_string.split("\n"):
        if "<service " in line and "product=" in line:
            name = line.split('product="')[1].split('"')[0]
            version = "unknown"
            if 'version="' in line:
                version = line.split('version="')[1].split('"')[0]
            services.append((name.lower(), version))
    return services

def run_risk_model():
    with open("scan_results.json") as f:
        scan = json.load(f)

    output = []

    for ip, xml_data in scan.items():
        if ip in ("Starting","Ending"):
            continue

        services = extract_services(xml_data)

        for svc_name, version in services:
            entry = {
                "ip": ip,
                "service": svc_name,
                "version": version,
                "risk_score": 0,
                "vulnerabilities": []
            }

            # Check DB for exact match
            if svc_name in VULN_DB and version in VULN_DB[svc_name]:
                vuln_info = VULN_DB[svc_name][version]
                entry["risk_score"] = vuln_info["risk_score"]
                entry["vulnerabilities"] = vuln_info["cves"]

            output.append(entry)

    with open("risk_output.json", "w") as f:
        json.dump(output, f, indent=4)

    print("Created risk_output.json")

if __name__ == "__main__":
    run_risk_model()

