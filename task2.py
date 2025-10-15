# Name: Jamie Knowles (C00307559)
# Date: 15/10/2025
# Purpose: Task2 Detect brute-force bursts (>=5 failures within 10 mins)

from datetime import datetime, timedelta
from collections import defaultdict
import re

LOG_FILE = "sample_auth_small.log"

# Regex to capture timestamp and IP
pattern = re.compile(r"([A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}).*from\s+([\d\.]+)")

# Store timestamps for each IP
ip_timestamps = defaultdict(list)

# Step 1: Read and parse log file
with open(LOG_FILE, "r", encoding="utf-8", errors="replace") as file:
    for line in file:
        match = pattern.search(line)
        if match:
            time_text, ip = match.groups()
            try:
                # Prepend a year so datetime can parse correctly
                t = datetime.strptime("2025 " + time_text, "%Y %b %d %H:%M:%S")
                ip_timestamps[ip].append(t)
            except Exception:
                print(f"Could not parse: {line.strip()}")

# Sort timestamps for each IP
for ip in ip_timestamps:
    ip_timestamps[ip].sort()

# Step 2: Detect brute force bursts
window = timedelta(minutes=10)
incidents = []  # store detected incidents

for ip, times in ip_timestamps.items():
    for i in range(len(times) - 4):  # need at least 5 attempts
        if times[i + 4] - times[i] <= window:  # 5 attempts within 10 mins
            # record this incident
            incident = {
                "ip": ip,
                "count": 5,
                "first_time": times[i].strftime("%b %d %H:%M:%S"),
                "last_time": times[i + 4].strftime("%b %d %H:%M:%S")
            }
            incidents.append(incident)
            break  # stop after first detection for this IP

# Step 3: Print detected incidents
print("\nDetected brute force bursts:\n")
for inc in incidents:
    print(f"IP: {inc['ip']}")
    print(f"Attempts: {inc['count']}")
    print(f"Brute Force Lenght From: {inc['first_time']} Till= {inc['last_time']}")
    print()