# Name: Jamie Knowles (C00307559)
# Date: 15/10/2025
# Purpose:Parse auth lines into timestamp lists

import re
from datetime import datetime
from collections import defaultdict

# Name of the log file to read
LOG_FILE = "sample_auth_small.log"

# Regex to capture timestamp and IP from lines like:
# Oct 15 13:45:01 sshd[xxx]: Failed password for invalid user from 203.0.113.45
pattern = re.compile(r"([A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}).*from\s+([\d\.]+)")

# Dictionary to store IP and list of timestamps
ip_timestamps = defaultdict(list)

# Read the log file line by line
with open(LOG_FILE, "r", encoding="utf-8", errors="replace") as file:
    for line in file:
        match = pattern.search(line)
        if match:
            time_text, ip = match.groups()
            try:
                # Year to make parsing work
                time_obj = datetime.strptime("2025 " + time_text, "%Y %b %d %H:%M:%S")
                ip_timestamps[ip].append(time_obj)
            except Exception:
                print(f"Failed to parse time in line: {line.strip()}")

# Sort timestamps for each IP
for ip in ip_timestamps:
    ip_timestamps[ip].sort()

# Print in the required format
for ip, times in ip_timestamps.items():
    print(f'"{ip}": [')
    for t in times:
        print(f'  "{t.strftime("%b %d %H:%M:%S")}",')
    print("],\n")