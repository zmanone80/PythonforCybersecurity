# Read and analyze the logs

import re

from collections import defaultdict
from urllib.parse import urlparse


log_file_path = r'C:\Users\201751009\PythonforCybersecurity\start\CH07\access.log'

with open(log_file_path, 'r') as file:
    log_lines = file.readlines()

status_code_counts = defaultdict(int)

for line in log_lines:
    match = re.search(r'\" \d{3} ', line)
    if match:
        status_code = match.group().strip().split()[1]
        status_code_counts[status_code] += 1

print("Staus Code Distribution")
for code, count in status_code_counts.items():
    print(f"{code}: {count}")


ip_counts = defaultdict(int)
total_requests = len(log_lines)

for line in log_lines:
    ip_address = line.split()[0]
    ip_counts[ip_address] += 1
    
most_frequent_ip = max(ip_counts, key=ip_counts.get)
percentage = (ip_counts[most_frequent_ip] / total_requests) * 100

print(f"Most frequent IP: {most_frequent_ip} - {percentage: .2f}% of total")


restricted_pages = ['/admin', '/login', '/secret', '/private']
restricted_attempts = []

for line in log_lines:
    request = re.search(r'\"(GET|POST) (.*?) HTTP/', line)
    if request:
        url = request.group(2)
        for restricted in restricted_pages:
            if restricted in url:
                restricted_attempts.append(line)

print(f"Attempts to access restricted pages: {len(restricted_attempts)}")
for attempts in restricted_attempts:
    print(attempts)



#Analyze Out of country IP address
#None-refeering traffic(deep linking!)