import re
import requests
import tldextract
from urllib.parse import urlparse

# Optional: Enable VirusTotal scanning
USE_VIRUSTOTAL = False
VIRUSTOTAL_API_KEY = "YOUR_API_KEY"  # Optional

def is_suspicious_url(url):
    reasons = []

    # Check if the URL uses an IP address instead of a domain
    if re.match(r'https?://\d+\.\d+\.\d+\.\d+', url):
        reasons.append("Uses IP address instead of domain.")

    # Check for @ symbol which can be used to obscure URLs
    if "@" in url:
        reasons.append("URL contains '@' symbol.")

    # Check URL length
    if len(url) > 75:
        reasons.append("Very long URL.")

    # Check number of subdomains
    ext = tldextract.extract(url)
    if ext.subdomain and len(ext.subdomain.split(".")) > 2:
        reasons.append("Too many subdomains.")

    # Check for common phishing keywords
    phishing_keywords = ["login", "verify", "secure", "update", "banking"]
    if any(keyword in url.lower() for keyword in phishing_keywords):
        reasons.append("Contains phishing-related keywords.")

    return reasons

def check_virustotal(url):
    headers = {
        "x-apikey": VIRUSTOTAL_API_KEY
    }
    scan_url = "https://www.virustotal.com/api/v3/urls"
    encoded_url = requests.post(scan_url, headers=headers, data={"url": url})
    if encoded_url.status_code != 200:
        return "VirusTotal scan failed."

    analysis_url = f"{scan_url}/{encoded_url.json()['data']['id']}"
    analysis = requests.get(analysis_url, headers=headers).json()
    malicious_votes = analysis['data']['attributes']['last_analysis_stats']['malicious']
    if malicious_votes > 0:
        return f"VirusTotal: {malicious_votes} vendors flagged this URL as malicious."
    return "VirusTotal: Clean"

def scan_url(url):
    print(f"\nScanning URL: {url}")
    findings = is_suspicious_u
# Brainwave_Matrix_Intern
