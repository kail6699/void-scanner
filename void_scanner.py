import socket
import ssl
import json
import urllib.request
import sys
import time
from datetime import datetime
import os

# تفعيل أكواد ANSI في الويندوز
os.system("")

# ============================================
# الألوان (بنفسجي + أزرق)
# ============================================
PURPLE = "\033[95m"   # بنفسجي (للعناوين والفواصل)
BLUE   = "\033[94m"   # أزرق (للمعلومات)
BOLD   = "\033[1m"
RESET  = "\033[0m"

# ============================================
# VOID SCANNER - Network & Web Vulnerability Scanner
# ============================================

def scan_port(host, port, timeout=2):
    """فحص منفذ واحد"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except:
        return False

def scan_common_ports(host):
    """فحص المنافذ الشائعة"""
    ports = {
        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
        80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
        3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 8080: "HTTP-Proxy", 8443: "HTTPS-Alt"
    }
    
    open_ports = []
    print(BLUE + "\n[*] Scanning common ports..." + RESET)
    for port, service in ports.items():
        if scan_port(host, port):
            open_ports.append((port, service))
            print(BLUE + f"    [+] Port {port} ({service}) - OPEN" + RESET)
    
    if not open_ports:
        print(BLUE + "    [-] No open ports found" + RESET)
    
    return open_ports

def get_ip_info(host):
    """جلب معلومات IP"""
    try:
        ip = socket.gethostbyname(host)
        url = f'http://ip-api.com/json/{ip}'
        response = urllib.request.urlopen(url, timeout=5)
        data = json.loads(response.read().decode())
        return data
    except:
        return None

def get_ssl_info(host):
    """جلب معلومات شهادة SSL"""
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                return cert
    except:
        return None

def get_headers(host):
    """جلب هيدرز السيرفر"""
    try:
        url = f'https://{host}'
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        response = urllib.request.urlopen(req, timeout=5)
        return dict(response.headers)
    except:
        return None

def check_security_headers(headers):
    """فحص الهيدرز الأمنية"""
    if not headers:
        return []
    security_headers = {
        'Strict-Transport-Security': 'HSTS',
        'X-Frame-Options': 'Clickjacking Protection',
        'X-Content-Type-Options': 'MIME Sniffing Protection',
        'Content-Security-Policy': 'CSP',
        'X-XSS-Protection': 'XSS Protection',
        'Referrer-Policy': 'Referrer Policy'
    }
    missing = []
    for header, name in security_headers.items():
        if header not in headers:
            missing.append(name)
    return missing

def check_vulnerabilities(host):
    """فحص الثغرات الشائعة"""
    vulns = []
    try:
        url = f'http://{host}'
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        response = urllib.request.urlopen(req, timeout=5)
        if response.status == 200:
            if url.startswith('http://'):
                vulns.append("HTTP without HTTPS redirect")
    except:
        pass
    try:
        url = f'https://{host}'
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        response = urllib.request.urlopen(req, timeout=5)
        headers = dict(response.headers)
        if 'Server' in headers:
            server = headers['Server']
            if 'Apache' in server and '2.4' in server:
                vulns.append(f"Old Apache version: {server}")
            if 'nginx' in server:
                vulns.append(f"Server info exposed: {server}")
        if 'X-Powered-By' in headers:
            vulns.append(f"Technology exposed: {headers['X-Powered-By']}")
    except:
        pass
    return vulns

def generate_report(host):
    """توليد التقرير الكامل"""
    print(PURPLE + BOLD + "\n" + "="*60 + RESET)
    print(PURPLE + BOLD + f"  VOID SCANNER - TARGET: {host.upper()}" + RESET)
    print(PURPLE + BOLD + f"  TIME: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}" + RESET)
    print(PURPLE + BOLD + "="*60 + RESET)
    
    # 1. IP Information
    ip_info = get_ip_info(host)
    if ip_info:
        print(PURPLE + BOLD + "\n[+] IP INFORMATION" + RESET)
        print(PURPLE + "-"*40 + RESET)
        print(BLUE + f"    IP Address    : {ip_info.get('query', 'N/A')}" + RESET)
        print(BLUE + f"    Country       : {ip_info.get('country', 'N/A')}" + RESET)
        print(BLUE + f"    City          : {ip_info.get('city', 'N/A')}" + RESET)
        print(BLUE + f"    ISP           : {ip_info.get('isp', 'N/A')}" + RESET)
        print(BLUE + f"    Organization  : {ip_info.get('org', 'N/A')}" + RESET)
    
    # 2. Port Scan
    open_ports = scan_common_ports(host)
    
    # 3. SSL Info
    ssl_info = get_ssl_info(host)
    if ssl_info:
        print(PURPLE + BOLD + "\n[+] SSL CERTIFICATE" + RESET)
        print(PURPLE + "-"*40 + RESET)
        print(BLUE + f"    Subject   : {ssl_info.get('subject', 'N/A')}" + RESET)
        print(BLUE + f"    Issuer    : {ssl_info.get('issuer', 'N/A')}" + RESET)
        print(BLUE + f"    Valid To  : {ssl_info.get('notAfter', 'N/A')}" + RESET)
    else:
        print(PURPLE + "\n[-] SSL Certificate: Not available or invalid" + RESET)
    
    # 4. Headers
    headers = get_headers(host)
    if headers:
        print(PURPLE + BOLD + "\n[+] SERVER HEADERS" + RESET)
        print(PURPLE + "-"*40 + RESET)
        for key, value in headers.items():
            print(BLUE + f"    {key}: {value}" + RESET)
        
        # 5. Security Headers Check
        missing = check_security_headers(headers)
        if missing:
            print(PURPLE + BOLD + "\n[!] MISSING SECURITY HEADERS" + RESET)
            print(PURPLE + "-"*40 + RESET)
            for m in missing:
                print(BLUE + f"    [-] {m}" + RESET)
        else:
            print(PURPLE + "\n[+] All security headers present" + RESET)
    
    # 6. Vulnerability Check
    vulns = check_vulnerabilities(host)
    if vulns:
        print(PURPLE + BOLD + "\n[!] POTENTIAL VULNERABILITIES" + RESET)
        print(PURPLE + "-"*40 + RESET)
        for v in vulns:
            print(BLUE + f"    [!] {v}" + RESET)
    else:
        print(PURPLE + "\n[+] No obvious vulnerabilities found" + RESET)
    
    print(PURPLE + BOLD + "\n" + "="*60 + RESET)
    print(PURPLE + BOLD + "  SCAN COMPLETE" + RESET)
    print(PURPLE + BOLD + "="*60 + "\n" + RESET)

def main():
    print(PURPLE + BOLD + """
    ╔═══════════════════════════════════════════════╗
    ║   VOID SCANNER v1.0 - Network Analyzer        ║
    ║   For educational and authorized testing only ║
    ╚═══════════════════════════════════════════════╝
    """ + RESET)
    
    if len(sys.argv) > 1:
        target = sys.argv[1]
    else:
        target = input(BLUE + "[?] Enter target domain: " + RESET).strip()
    
    if target:
        generate_report(target)
    else:
        print(PURPLE + "[-] No target specified." + RESET)

if __name__ == "__main__":
    main()