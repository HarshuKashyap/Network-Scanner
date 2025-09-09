import nmap
import json
import datetime

def scan_network(target):
    scanner = nmap.PortScanner()
    print(f" Scanning {target} ...")
    scanner.scan(target, arguments="-sV")

    results = {}
    for host in scanner.all_hosts():
        results[host] = {
            "state": scanner[host].state(),
            "protocols": {}
        }
        for proto in scanner[host].all_protocols():
            results[host]["protocols"][proto] = {}
            for port in scanner[host][proto].keys():
                results[host]["protocols"][proto][port] = scanner[host][proto][port]

    return results

def save_report(results, filename="scan_report.json"):
    with open(filename, "w") as f:
        json.dump(results, f, indent=4)
    print(f"Report saved as {filename}")

if __name__ == "__main__":
    target = input("Enter IP or Range (e.g., 192.168.1.0/24): ")
    scan_results = scan_network(target)
    save_report(scan_results, f"scan_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
