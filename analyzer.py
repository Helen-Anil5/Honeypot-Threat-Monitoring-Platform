import re
import csv
from collections import Counter

def analyze_and_export_logs():
    log_file = 'honeypot_logs.txt'
    csv_file = 'honeypot_report.csv'
    
    try:
        with open(log_file, 'r', encoding='utf-8') as f:
            logs = f.readlines()
    except FileNotFoundError:
        print("No logs found yet.")
        return

    # Set up the CSV file
    with open(csv_file, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(['Timestamp', 'Attacker_IP', 'Request_Type', 'Path', 'Payload'])

        for log in logs:
            # Extract parts of the log using regex
            timestamp = log.split('|')[0].strip()
            ip_match = re.search(r'from (\d+\.\d+\.\d+\.\d+)', log)
            ip = ip_match.group(1) if ip_match else 'Unknown'
            
            if 'POST Request' in log:
                req_type = 'POST'
                payload_match = re.search(r'Payload: (.*)', log)
                payload = payload_match.group(1).strip() if payload_match else 'None'
                path_match = re.search(r'Path: (.*?) \|', log)
                path = path_match.group(1).strip() if path_match else '/'
            elif 'GET Request' in log:
                req_type = 'GET'
                payload = 'N/A'
                path_match = re.search(r'Path: (.*?) \|', log)
                path = path_match.group(1).strip() if path_match else '/'
            else:
                req_type = 'OTHER'
                payload = 'N/A'
                path = 'N/A'

            # Write the row to CSV
            writer.writerow([timestamp, ip, req_type, path, payload])

    print(f"✅ Success! Exported {len(logs)} events to {csv_file}")
    print("You can now open this file in Microsoft Excel!")

if __name__ == '__main__':
    analyze_and_export_logs()