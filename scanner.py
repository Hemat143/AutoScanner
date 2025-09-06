#!/usr/bin/env python3

import subprocess
import sys
import re
import socket
import os
import time
import threading
import json
import shutil
import asyncio
from concurrent.futures import ThreadPoolExecutor
from texttable import Texttable
from tqdm import tqdm

# Enhanced configuration with firewall bypass and smart scanning options
CONFIG = {
    'threads': 50,
    'timeouts': {
        'nmap': 600,
        'gobuster': 300,
        'nuclei': 180,
        'cloudbrute': 240,
        'nikto': 300
    },
    'wordlists': {
        'gobuster': {
            'default': "/usr/share/wordlists/SecLists/Discovery/Web-Content/raft-large-directories.txt",
            'cms': {
                'wordpress': "/usr/share/wordlists/SecLists/Discovery/Web-Content/CMS/wordpress.txt",
                'joomla': "/usr/share/wordlists/SecLists/Discovery/Web-Content/CMS/joomla.txt",
                'drupal': "/usr/share/wordlists/SecLists/Discovery/Web-Content/CMS/drupal.txt"
            },
            'api': "/usr/share/wordlists/SecLists/Discovery/Web-Content/api/",
            'fuzz': "/usr/share/wordlists/SecLists/Discovery/Web-Content/raft-large-files.txt"
        },
        'nikto': {
            'default': "/usr/share/nikto/databases/plugins.db",
            'extended': "/usr/share/nikto/databases/plugins_extended.db",
            'vulnerabilities': "/usr/share/nikto/databases/vulnerabilities.db"
        }
    },
    'firewall_bypass': {
        'nmap': [
            "-f", "--mtu 24", "--badsum", "--data-length 100",
            "--scan-delay 5s", "--max-retries 3", "--source-port 53",
            "--spoof-mac 0", "--ttl 128", "--randomize-hosts"
        ],
        'timing': {
            'stealth': "-T1",
            'aggressive': "-T4",
            'insane': "-T5"
        }
    }
}

def print_banner():
    """Print the tool banner"""
    banner = """
    ███████╗ ██████╗ █████╗ ███╗   ██╗███╗   ██╗███████╗██████╗ 
    ██╔════╝██╔════╝██╔══██╗████╗  ██║████╗  ██║██╔════╝██╔══██╗
    ███████╗██║     ███████║██╔██╗ ██║██╔██╗ ██║█████╗  ██████╔╝
    ╚════██║██║     ██╔══██║██║╚██╗██║██║╚██╗██║██╔══╝  ██╔══██╗
    ███████║╚██████╗██║  ██║██║ ╚████║██║ ╚████║███████╗██║  ██║
    ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝
    """
    print(banner)
    print("Advanced Web Security Scanner".center(80))
    print("Version 2.0".center(80))
    print("="*80)
    print(Author bye : hanamanthpotaraddi)

def run_command(command, suppress_output=False):
    """Run a system command and return the output"""
    try:
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            stdin=subprocess.PIPE,
            universal_newlines=True
        )
        stdout, stderr = process.communicate()
        return stdout, stderr, process.returncode
    except Exception as e:
        if not suppress_output:
            print(f"[!] Error running command {' '.join(command)}: {str(e)}")
        return None, str(e), -1

def validate_target(target):
    """Validate the target input"""
    # Check if it's a URL
    if target.startswith(('http://', 'https://')):
        return "url"
    
    # Check if it's an IP address
    ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
    if re.match(ip_pattern, target):
        return "ip"
    
    # Check if it's a domain name
    domain_pattern = r'^[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}$'
    if re.match(domain_pattern, target):
        return "domain"
    
    return False

def extract_host_from_target(target):
    """Extract host from target URL or IP"""
    if target.startswith(('http://', 'https://')):
        return target.split('/')[2]
    return target

def is_port_open(host, port):
    """Check if a port is open"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except Exception:
        return False

def check_common_ports(target):
    """Check common ports quickly"""
    host = extract_host_from_target(target)
    common_ports = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 
                   993, 995, 1723, 3306, 3389, 5900, 8080, 8443]
    
    print("\n[+] Checking common ports...")
    open_ports = []
    
    with ThreadPoolExecutor(max_workers=CONFIG['threads']) as executor:
        futures = {executor.submit(is_port_open, host, port): port for port in common_ports}
        for future in futures:
            port = futures[future]
            if future.result():
                open_ports.append(port)
                print(f"  [+] Port {port} is open")
    
    return open_ports

def dns_enumeration(target):
    """Perform basic DNS enumeration"""
    if validate_target(target) != "domain":
        return
    
    print("\n[+] Performing DNS enumeration...")
    domain = extract_host_from_target(target)
    
    commands = [
        ["host", domain],
        ["dig", domain, "ANY"],
        ["dig", domain, "MX"],
        ["dig", domain, "TXT"],
        ["nslookup", "-type=any", domain]
    ]
    
    for cmd in commands:
        if shutil.which(cmd[0]):
            print(f"\n[*] Running {cmd[0]} {domain}...")
            stdout, stderr, _ = run_command(cmd)
            if stdout:
                print(stdout)

def passive_recon(domain):
    """Perform passive reconnaissance"""
    if not domain:
        return
    
    print("\n[+] Performing passive reconnaissance...")
    tools = [
        ["theHarvester", "-d", domain, "-b", "all"],
        ["dnsrecon", "-d", domain],
        ["sublist3r", "-d", domain]
    ]
    
    for tool in tools:
        if shutil.which(tool[0]):
            print(f"\n[*] Running {tool[0]}...")
            stdout, stderr, _ = run_command(tool)
            if stdout:
                print(stdout)

def enhanced_nmap_scan(target):
    """Advanced Nmap scan with firewall detection and bypass techniques"""
    print("\n" + "="*80)
    print(" ADVANCED NMAP SCANNING".center(80))
    print("="*80)
    print(f"[*] Target: {target}")
    print(f"[*] Initial Scan Type: Service Detection + Firewall Detection")
    print(f"[*] Ports: Top 1000 common ports")
    print("-" * 80)

    # Initial scan to detect firewall
    initial_command = [
        "nmap", "-Pn", "-n", "-sV", "--open",
        "--top-ports", "1000",
        "--script", "firewall-bypass",
        target
    ]

    print("[*] Running initial scan to detect firewall...")
    stdout, stderr, _ = run_command(initial_command, suppress_output=True)

    firewall_detected = False
    if stdout and ("firewall" in stdout.lower() or "filtered" in stdout.lower()):
        firewall_detected = True
        print("[!] Firewall detected. Applying bypass techniques...")

    # Determine scan strategy based on firewall detection
    if firewall_detected:
        scan_command = [
            "nmap", "-Pn", "-n", "-sV", "-sC", "--open",
            "--top-ports", "1000",
            "--min-rate", "1000",
            "--version-intensity", "6",
            "--script-timeout", "30s"
        ]

        # Add firewall bypass techniques
        scan_command.extend(CONFIG['firewall_bypass']['nmap'])
        scan_command.append("--script")
        scan_command.append("firewall-bypass,http-waf-detect")
        scan_command.append(target)

        print("[*] Using advanced firewall bypass techniques:")
        print(" ├─ Fragmented packets")
        print(" ├─ Bad checksums")
        print(" ├─ Random source ports")
        print(" └─ Timing variations")
    else:
        scan_command = [
            "nmap", "-Pn", "-n", "-sV", "-sC", "--open",
            "--top-ports", "1000",
            "--min-rate", "1000",
            "--version-intensity", "6",
            "--script-timeout", "30s",
            target
        ]
        print("[*] No firewall detected. Running standard scan...")

    print("-" * 80)
    stdout, stderr, _ = run_command(scan_command, suppress_output=True)

    if stdout:
        print("\n[+] Scan Results:")
        print(stdout)
    else:
        print("[!] No output received from Nmap scan")

    print("[+] NMAP SCAN COMPLETED WITH FIREWALL BYPASS TECHNIQUES" if firewall_detected else "[+] NMAP SCAN COMPLETED")
    print("="*80)

def whatweb_quick_check(url):
    """Quick WhatWeb check to determine server technology"""
    if not shutil.which("whatweb"):
        return None

    command = ["whatweb", "-a", "1", "--color=never", url]
    stdout, _, _ = run_command(command, suppress_output=True)
    return stdout

def whatweb_scan(url):
    """Perform WhatWeb scan"""
    if not shutil.which("whatweb"):
        print("[!] WhatWeb not found, skipping...")
        return

    print("\n[+] Running WhatWeb scan...")
    command = ["whatweb", "-a", "3", url]
    stdout, stderr, _ = run_command(command)
    if stdout:
        print(stdout)

def wafw00f_scan(url):
    """Detect WAF protection"""
    if not shutil.which("wafw00f"):
        print("[!] wafw00f not found, skipping...")
        return

    print("\n[+] Running WAF detection...")
    command = ["wafw00f", url]
    stdout, stderr, _ = run_command(command)
    if stdout:
        print(stdout)

def smart_gobuster_scan(target):
    """Intelligent Gobuster scan with automatic wordlist selection"""
    url = target if target.startswith("http") else f"http://{target}"

    # First detect server technology
    whatweb_output = whatweb_quick_check(url)
    wordlist = CONFIG['wordlists']['gobuster']['default']
    extensions = "php,html,htm,asp,aspx,jsp,js,txt,xml,json,bak,old,config,log"

    if whatweb_output:
        if 'wordpress' in whatweb_output.lower():
            wordlist = CONFIG['wordlists']['gobuster']['cms']['wordpress']
            extensions = "php,html,js,css"
            print("[*] WordPress detected. Using WordPress-specific wordlist")
        elif 'joomla' in whatweb_output.lower():
            wordlist = CONFIG['wordlists']['gobuster']['cms']['joomla']
            print("[*] Joomla detected. Using Joomla-specific wordlist")
        elif 'drupal' in whatweb_output.lower():
            wordlist = CONFIG['wordlists']['gobuster']['cms']['drupal']
            print("[*] Drupal detected. Using Drupal-specific wordlist")
        elif 'api' in whatweb_output.lower() or 'json' in whatweb_output.lower():
            wordlist = CONFIG['wordlists']['gobuster']['api']
            extensions = "json,xml"
            print("[*] API detected. Using API-specific wordlist")

    if not os.path.isfile(wordlist):
        print(f"[!] Selected wordlist not found: {wordlist}")
        wordlist = CONFIG['wordlists']['gobuster']['default']

    print("\n" + "="*80)
    print(" INTELLIGENT GOBUSTER SCAN".center(80))
    print("="*80)
    print(f"[*] Target URL: {url}")
    print(f"[*] Selected Wordlist: {os.path.basename(wordlist)}")
    print(f"[*] Extensions: {extensions}")
    print(f"[*] Threads: 100 | Timeout: 8s")
    print("-" * 80)

    command = [
        "gobuster", "dir",
        "-u", url,
        "-w", wordlist,
        "-t", "100",
        "-x", extensions,
        "-k",
        "-q",
        "--timeout", "8s",
        "--random-agent",
        "--no-error",
        "-r",
        "--wildcard"
    ]

    stdout, stderr, _ = run_command(command)
    if stdout:
        print("\n[+] Gobuster results:")
        print(stdout)
    else:
        print("[!] No output received from Gobuster scan")

    print("="*80)

def smart_nikto_scan(target):
    """Advanced Nikto scan with intelligent vulnerability detection"""
    url = target if target.startswith("http") else f"http://{target}"

    if not shutil.which("nikto"):
        print("[!] Nikto not found, skipping...")
        return

    print("\n" + "="*80)
    print(" ADVANCED NIKTO VULNERABILITY SCAN".center(80))
    print("="*80)
    print(f"[*] Target URL: {url}")
    print(f"[*] Scan Type: Intelligent Web Application Security Assessment")
    print(f"[*] Database: Extended vulnerability checks with false-positive reduction")
    print("-" * 80)

    # Determine which wordlists to use based on initial detection
    whatweb_output = whatweb_quick_check(url)
    extended_scan = False
    cms_detected = False

    if whatweb_output:
        if any(x in whatweb_output.lower() for x in ['wordpress', 'joomla', 'drupal']):
            cms_detected = True
            print("[*] CMS detected. Using extended CMS-specific checks...")
            extended_scan = True
        elif any(x in whatweb_output.lower() for x in ['apache', 'nginx', 'iis']):
            print("[*] Standard web server detected. Using comprehensive checks...")
            extended_scan = True

    # Build Nikto command
    command = [
        "nikto", "-h", url,
        "-Format", "txt",
        "-nointeractive",
        "-timeout", str(CONFIG['timeouts']['nikto']),
        "-Tuning", "x5678"  # Enable all checks except DoS
    ]

    if extended_scan:
        command.extend(["-plugins", "+ALL"])
        if cms_detected:
            command.extend(["-db", CONFIG['wordlists']['nikto']['extended']])
        else:
            command.extend(["-db", CONFIG['wordlists']['nikto']['vulnerabilities']])

    stdout, stderr, _ = run_command(command, suppress_output=True)

    if stdout:
        # Enhanced vulnerability filtering
        critical_vulns = []
        high_vulns = []
        medium_vulns = []
        info_findings = []

        for line in stdout.split('\n'):
            line = line.strip().lower()
            if not line:
                continue

            # Critical vulnerabilities
            if any(x in line for x in ['remote code execution', 'sql injection', 'command injection',
                                      'file inclusion', 'authenticat bypass', 'rce']):
                critical_vulns.append(line)
            # High severity
            elif any(x in line for x in ['xss', 'csrf', 'directory traversal', 'information disclosure',
                                        'server-side request forgery', 'xxe']):
                high_vulns.append(line)
            # Medium severity
            elif any(x in line for x in ['misconfiguration', 'outdated', 'deprecated', 'verbose error']):
                medium_vulns.append(line)
            # Informational
            else:
                info_findings.append(line)

        # Print categorized results
        if critical_vulns:
            print("\n[!] CRITICAL VULNERABILITIES FOUND:")
            for vuln in critical_vulns:
                print(f" - {vuln}")
        if high_vulns:
            print("\n[!] HIGH SEVERITY FINDINGS:")
            for vuln in high_vulns:
                print(f" - {vuln}")
        if medium_vulns:
            print("\n[!] MEDIUM SEVERITY FINDINGS:")
            for vuln in medium_vulns:
                print(f" - {vuln}")
        if info_findings and extended_scan:
            print("\n[+] INFORMATIONAL FINDINGS:")
            for finding in info_findings:
                print(f" - {finding}")

        # False positive reduction
        if not any([critical_vulns, high_vulns, medium_vulns]):
            print("[+] No significant vulnerabilities found (with false positive reduction)")
    else:
        print("[!] No output received from Nikto scan")

    print("="*80)

def enhanced_fuzz_scan(url):
    """Enhanced fuzzing scan"""
    if not shutil.which("ffuf"):
        print("[!] ffuf not found, skipping...")
        return

    print("\n[+] Running enhanced fuzzing scan...")
    wordlist = CONFIG['wordlists']['gobuster']['fuzz']
    
    if not os.path.isfile(wordlist):
        print(f"[!] Wordlist not found: {wordlist}")
        return

    command = [
        "ffuf",
        "-u", f"{url}/FUZZ",
        "-w", wordlist,
        "-t", "100",
        "-p", "0.1",
        "-o", "fuzz_results.json",
        "-of", "json",
        "-ac"
    ]

    stdout, stderr, _ = run_command(command)
    if os.path.exists("fuzz_results.json"):
        with open("fuzz_results.json") as f:
            results = json.load(f)
            for result in results['results']:
                if result['status'] == 200:
                    print(f"Found: {result['url']} (Status: {result['status']})")
        os.remove("fuzz_results.json")

def nuclei_scan(url):
    """Run Nuclei vulnerability scan"""
    if not shutil.which("nuclei"):
        print("[!] Nuclei not found, skipping...")
        return

    print("\n[+] Running Nuclei scan...")
    command = [
        "nuclei",
        "-u", url,
        "-t", "cves/",
        "-t", "default-logins/",
        "-t", "exposures/",
        "-t", "misconfiguration/",
        "-t", "vulnerabilities/",
        "-timeout", str(CONFIG['timeouts']['nuclei']),
        "-rate-limit", "100",
        "-bulk-size", "25"
    ]

    stdout, stderr, _ = run_command(command)
    if stdout:
        print(stdout)

def kiterunner_scan(url):
    """Run Kiterunner API scan"""
    if not shutil.which("kr"):
        print("[!] Kiterunner not found, skipping...")
        return

    print("\n[+] Running Kiterunner API scan...")
    command = [
        "kr",
        "scan",
        url,
        "-w", "/usr/share/wordlists/SecLists/Discovery/Web-Content/api/",
        "-x", "20",
        "-j", "100"
    ]

    stdout, stderr, _ = run_command(command)
    if stdout:
        print(stdout)

def js_analysis(url):
    """Perform JavaScript analysis"""
    if not shutil.which("linkfinder"):
        print("[!] LinkFinder not found, skipping JavaScript analysis...")
        return

    print("\n[+] Running JavaScript analysis...")
    command = [
        "linkfinder",
        "-i", url,
        "-o", "js_analysis.txt"
    ]

    stdout, stderr, _ = run_command(command)
    if os.path.exists("js_analysis.txt"):
        with open("js_analysis.txt") as f:
            print(f.read())
        os.remove("js_analysis.txt")

def graphql_scan(url):
    """Perform GraphQL endpoint scanning"""
    if not shutil.which("graphqlmap"):
        print("[!] GraphQLMap not found, skipping GraphQL scan...")
        return

    print("\n[+] Running GraphQL scan...")
    command = [
        "graphqlmap",
        "-u", f"{url}/graphql",
        "--dump-schema"
    ]

    stdout, stderr, _ = run_command(command)
    if stdout:
        print(stdout)

def ssl_scan(url):
    """Perform SSL/TLS scan"""
    if not shutil.which("testssl"):
        print("[!] testssl not found, skipping SSL scan...")
        return

    host = extract_host_from_target(url)
    print("\n[+] Running SSL/TLS scan...")
    command = [
        "testssl",
        "--quiet",
        "--color", "0",
        host
    ]

    stdout, stderr, _ = run_command(command)
    if stdout:
        print(stdout)

def print_table(title, headers, rows):
    """Print data in table format"""
    print(f"\n{title}:")
    table = Texttable()
    table.set_cols_align(["l"] * len(headers))
    table.set_cols_valign(["m"] * len(headers))
    table.add_rows([headers] + rows)
    print(table.draw())

def main():
    """Main execution function with enhanced workflow"""
    print_banner()

    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <target_ip_or_domain>")
        print("Examples:")
        print(f"  {sys.argv[0]} 192.168.1.1")
        print(f"  {sys.argv[0]} example.com")
        print(f"  {sys.argv[0]} https://example.com")
        sys.exit(1)

    target = sys.argv[1].strip()
    if not validate_target(target):
        print("[!] Invalid target format. Provide a valid IP, domain, or URL.")
        sys.exit(1)

    print(f"[+] Starting advanced reconnaissance on: {target}")
    print(f"[+] Scan started at: {time.strftime('%Y-%m-%d %H:%M:%S')}")

    # Phase 1: Basic reconnaissance
    print("\n" + "="*80)
    print("PHASE 1: BASIC RECONNAISSANCE".center(80))
    print("="*80)

    open_ports = check_common_ports(target)
    dns_enumeration(target)

    if validate_target(target) == "domain":
        passive_recon(extract_host_from_target(target))

    # Phase 2: Advanced Network scanning
    print("\n" + "="*80)
    print("PHASE 2: ADVANCED NETWORK SCANNING".center(80))
    print("="*80)

    enhanced_nmap_scan(target)

    # Phase 3: Intelligent Web application testing
    host = extract_host_from_target(target)
    http_open = is_port_open(host, 80) or is_port_open(host, 8080)
    https_open = is_port_open(host, 443) or is_port_open(host, 8443)

    if http_open or https_open:
        print("\n" + "="*80)
        print("PHASE 3: INTELLIGENT WEB APPLICATION TESTING".center(80))
        print("="*80)

        web_target = ""
        if https_open and not target.startswith("http"):
            web_target = f"https://{host}"
        elif http_open and not target.startswith("http"):
            web_target = f"http://{host}"
        else:
            web_target = target

        whatweb_scan(web_target)
        wafw00f_scan(web_target)
        smart_gobuster_scan(web_target)
        smart_nikto_scan(web_target)
        enhanced_fuzz_scan(web_target)
        nuclei_scan(web_target)
        kiterunner_scan(web_target)
        js_analysis(web_target)
        graphql_scan(web_target)

        if https_open:
            ssl_scan(web_target)
    else:
        print("\n[*] No web services detected; skipping web-based scans.")

    print("\n" + "="*80)
    print("SCAN COMPLETED".center(80))
    print("="*80)
    print(f"[+] Scan finished at: {time.strftime('%Y-%m-%d %H:%M:%S')}")

if _name_ == "_main_":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n[!] Critical error: {str(e)}"https://github.com/Hemat143/Python-)
        sys.exit(1)
