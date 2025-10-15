# Name: Jamie Knowles (C00307559)
# Date: 15/10/2025
# Purpose: Task 3 Generate report and bar chart

from datetime import datetime, timedelta
from collections import defaultdict, Counter
import re
import matplotlib.pyplot as plt
import json

LOG_FILE = "sample_auth_small.log"

# Regex to capture timestamp and IP address
pattern = re.compile(r"([A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}).*from\s+([\d\.]+)")

# Step 1: Store timestamps for each IP
ip_timestamps = defaultdict(list)

with open(LOG_FILE, "r", encoding="utf-8", errors="replace") as file:
    for line in file:
        match = pattern.search(line)
        if match:
            time_text, ip = match.groups()
            try:
                # Prepend year so datetime can parse correctly
                t = datetime.strptime("2025 " + time_text, "%Y %b %d %H:%M:%S")
                ip_timestamps[ip].append(t)
            except Exception:
                print(f"Could not parse: {line.strip()}")

# Sort timestamps for each IP
for ip in ip_timestamps:
    ip_timestamps[ip].sort()

# Step 2: Detect brute force bursts (>=5 failures within 10 mins)
window = timedelta(minutes=10)
incidents = []

for ip, times in ip_timestamps.items():
    for i in range(len(times) - 4):
        if times[i + 4] - times[i] <= window:
            incidents.append({
                "ip": ip,
                "count": len(times),
                "first": times[i].strftime("%Y-%m-%dT%H:%M:%S"),
                "last": times[i + 4].strftime("%Y-%m-%dT%H:%M:%S")
            })
            break  # Stop after first detection for this IP

# Step 3: Save incidents to a text file
timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
output_file = f"bruteforce_incidents_{timestamp}.txt"

with open(output_file, "w") as f:
    json.dump(incidents, f, indent=4)

print(f"Brute force incidents saved to: {output_file}")

# Step 4: Create bar chart
if incidents:
    # Count total failed attempts for each IP
    ip_counts = Counter(ip for ip in ip_timestamps)

    # Get top 10 offending IPs
    top_ips = ip_counts.most_common(10)
    ips = [ip for ip, _ in top_ips]
    counts = [count for _, count in top_ips]

    # Create bar chart
    plt.bar(ips, counts)
    plt.title("Failed Login Attempts per IP")
    plt.xlabel("IP Address")
    plt.ylabel("Number of Failed Attempts")
    plt.xticks(rotation=45, ha="right")
    plt.tight_layout()

    chart_name = f"failed_logins_chart_{timestamp}.png"
    plt.savefig(chart_name)
    print(f"Bar chart saved as: {chart_name}")
else:
    print("No brute force activity detected.")

print("\nAnalysis complete!")