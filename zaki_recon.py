import requests
import socket
import whois
import argparse
import dns.resolver
import subprocess
import urllib3
from fpdf import FPDF
import re

def get_ip(domain):
    try:
        return socket.gethostbyname(domain)
    except socket.gaierror:
        return "Unable to resolve domain"

def get_whois(domain):
    try:
        w = whois.whois(domain)
        return w.text
    except:
        return "Whois lookup failed"

def get_headers(url):
    try:
        response = requests.get(url, timeout=5)
        return response.headers
    except requests.RequestException:
        return "Failed to fetch headers"

def get_dns_records(domain):
    records = {}
    record_types = ['A', 'MX', 'NS', 'TXT']
    for record in record_types:
        try:
            answers = dns.resolver.resolve(domain, record)
            records[record] = [rdata.to_text() for rdata in answers]
        except:
            records[record] = "No record found"
    return records

def scan_ports(domain):
    open_ports = []
    common_ports = [21, 22, 25, 53, 80, 443, 3306, 8080]
    for port in common_ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((domain, port))
        if result == 0:
            open_ports.append(port)
        sock.close()
    return open_ports if open_ports else "No common ports open"

def traceroute(domain):
    try:
        result = subprocess.run(["traceroute", domain], capture_output=True, text=True, check=True)
        return result.stdout
    except:
        return "Traceroute failed or not supported on this OS"

def check_vulnerabilities(domain):
    try:
        url = f"http://{domain}"
        http = urllib3.PoolManager()
        response = http.request("GET", url)
        server_header = response.headers.get("Server", "Unknown")
        
        vulnerabilities = []
        if "Apache" in server_header:
            vulnerabilities.append("Potential Apache vulnerabilities detected")
        if "nginx" in server_header:
            vulnerabilities.append("Potential Nginx vulnerabilities detected")
        if not vulnerabilities:
            return "No known vulnerabilities detected"
        return " | " .join(vulnerabilities)
    except:
        return "Failed to check vulnerabilities"

def check_xss(url):
    try:
        payload = "<script>alert('XSS')</script>"
        response = requests.get(f"{url}?q={payload}")
        if payload in response.text:
            return "XSS vulnerability detected!"
        return "No XSS vulnerabilities found"
    except:
        return "Failed to test for XSS"

def check_sql_injection(url):
    try:
        payload = "' OR '1'='1"  # Basic SQL Injection payload
        response = requests.get(f"{url}?id={payload}")
        if re.search("error|sql syntax|mysql_fetch|ORA-", response.text, re.IGNORECASE):
            return "SQL Injection vulnerability detected!"
        return "No SQL Injection vulnerabilities found"
    except:
        return "Failed to test for SQL Injection"

def detect_cms(url):
    try:
        response = requests.get(url, timeout=5)
        cms_signatures = {
            "WordPress": ["wp-content", "wp-includes", "wp-json"],
            "Joomla": ["/administrator", "Joomla"],
            "Drupal": ["/sites/default", "Drupal.settings"],
        }
        for cms, signs in cms_signatures.items():
            if any(sign in response.text for sign in signs):
                return f"{cms} detected"
        if "X-Powered-By" in response.headers:
            return f"Detected CMS via headers: {response.headers['X-Powered-By']}"
        return "CMS not detected"
    except:
        return "Failed to detect CMS"

def generate_report(domain, data):
    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()
    pdf.set_font("Arial", "B", 16)
    pdf.cell(200, 10, f"Zaki Recon Report for {domain}", ln=True, align='C')
    pdf.ln(10)
    
    pdf.set_font("Arial", "", 12)
    for section, content in data.items():
        pdf.set_font("Arial", "B", 14)
        pdf.cell(0, 10, section, ln=True)
        pdf.set_font("Arial", "", 12)
        pdf.multi_cell(0, 8, str(content))
        pdf.ln(5)
    
    report_filename = f"Zaki_{domain}_report.pdf"
    pdf.output(report_filename)
    print(f"\n[+] Report saved as {report_filename}")

def main():
    parser = argparse.ArgumentParser(description="Zaki Recon Tool")
    parser.add_argument("domain", help="Target domain (e.g. example.com)")
    args = parser.parse_args()
    
    domain = args.domain
    report_data = {}
    
    report_data["IP Address"] = get_ip(domain)
    report_data["Whois Info"] = get_whois(domain)
    report_data["HTTP Headers"] = get_headers(f"http://{domain}")
    report_data["DNS Records"] = get_dns_records(domain)
    report_data["Open Ports"] = scan_ports(domain)
    report_data["Traceroute"] = traceroute(domain)
    report_data["Vulnerability Scan"] = check_vulnerabilities(domain)
    report_data["XSS Scan"] = check_xss(f"http://{domain}")
    report_data["SQL Injection Scan"] = check_sql_injection(f"http://{domain}")
    report_data["CMS Detection"] = detect_cms(f"http://{domain}")
    
    for section, content in report_data.items():
        print(f"\n[*] {section}:")
        print(content)
    
    generate_report(domain, report_data)

if __name__ == "__main__":
    main()
