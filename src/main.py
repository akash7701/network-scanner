import sys
from scanner import scan_network
from cve_detector import load_cve_database, get_cve_count
from database import init_db, store_scan_result, query_scan_results

def main():
    init_db()

    ip_list = ["192.168.1.1", "192.168.1.10"]  # Update with your target IPs
    port_list = range(20, 1025)

    scan_results = scan_network(ip_list, port_list)
    
    print("Scan Results:\n" + "=" * 30)
    for ip, ports in scan_results.items():
        print(f"\nIP: {ip}")
        for port, banner in ports:
            print(f'  Port: {port} - Banner: {banner}')
            # Check CVE count
            cve_count = get_cve_count(banner, cve_data)
            print(f'  Checking CVEs for: {banner}')
            print(f'  CVE count: {cve_count}')
            store_scan_result(ip, port, banner, cve_count)

    print("\nStored Scan Results:\n" + "=" * 30)
    stored_results = query_scan_results()
    for row in stored_results:
        print(f'  IP: {row[0]}, Port: {row[1]}, Banner: {row[2]}, CVE Count: {row[3]}')

if __name__ == "__main__":
    cve_data = load_cve_database('data/CVE Databases')  # Ensure the path is correct
    main()
    sys.exit()  # Exit the program after execution
