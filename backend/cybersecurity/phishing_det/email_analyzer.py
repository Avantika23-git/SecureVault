from .phishing_keywords import detect_keywords
from .url_checker import extract_urls

import re
import socket
import requests
import json
import os
from urllib.parse import urlparse

from .virustotal_api import check_url





# Extract domain from URL
def extract_domain(url):
    return urlparse(url).netloc


# Convert domain to IP address
def get_ip(domain):
    try:
        return socket.gethostbyname(domain)
    except:
        return "Unknown"


# Get geolocation details from IP address
def get_location(ip):

    if ip == "Unknown":
        return {
            "country": "Unknown",
            "city": "Unknown",
            "isp": "Unknown"
        }

    try:
        response = requests.get(f"http://ip-api.com/json/{ip}")

        data = response.json()

        return {
            "country": data.get("country"),
            "city": data.get("city"),
            "isp": data.get("isp")
        }

    except:
        return {
            "country": "Unknown",
            "city": "Unknown",
            "isp": "Unknown"
        }


# Calculate phishing score and threat level
def calculate_score(text):
    text = text.replace("hxxps://", "https://")
    text = text.replace("hxxp://", "http://")
    text = text.replace("[.]", ".")
    score = 0
    
    urls = extract_urls(text)

    if len(urls) > 0:
        score += 20

    keyword_score, tactics = detect_keywords(text)

    score += keyword_score
    score = min(score, 100)

    if score < 30:
        level = "LOW"

    elif score < 60:
        level = "MEDIUM"

    else:
        level = "HIGH"

    return score, level, tactics


# Main email analysis function
# Main email analysis function
def analyze_email(text):

    text = text.replace("hxxps://", "https://")
    text = text.replace("hxxp://", "http://")
    text = text.replace("[.]", ".")

    score, level, tactics = calculate_score(text)

    urls = extract_urls(text)

    url_details = []

    for url in urls:
        domain = extract_domain(url)
        ip = get_ip(domain)
        location = get_location(ip)
        vt_result = check_url(url)

        url_details.append({
            "url": url,
            "domain": domain,
            "ip": ip,
            "country": location["country"],
            "city": location["city"],
            "isp": location["isp"],
            "malicious_engines": vt_result["malicious"],
            "suspicious_engines": vt_result["suspicious"]
        })

    # moved outside the loop — now this always runs
    report = {
        "risk_score": score,
        "threat_level": level,
        "tactics": tactics,
        "url_details": url_details
    }
    save_report(report)

    return report

# Save report to JSON file
import uuid
from datetime import datetime
import json
import os

REPORT_FILE = "reports/report_history.json"


def save_report(report):

    os.makedirs("reports", exist_ok=True)

    if os.path.exists(REPORT_FILE):

        with open(REPORT_FILE, "r") as f:
            try:
                reports = json.load(f)
            except:
                reports = []

    else:
        reports = []

    record = {
        "id": str(uuid.uuid4())[:8],
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "risk_score": report["risk_score"],
        "threat_level": report["threat_level"],
        "tactics": report["tactics"],
        "url_details": report["url_details"]
    }

    reports.append(record)

    with open(REPORT_FILE, "w") as f:
        json.dump(reports, f, indent=4)

    print("Report saved.")

    return record