import os
import sys
import json
import re
import socket
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
import requests
from colorama import Fore, Style, init
from tqdm import tqdm

init(autoreset=True)

class TurboScan:
    def __init__(self):
        self.target = ""
        self.proxy = None
        self.threads = 90  # زيادة عدد الخيوط لتحسين السرعة
        self.timeout = 5  # تقليل وقت الانتظار
        self.results = {
            "basic_info": {},
            "directories": [],
            "vulnerabilities": {
                "critical": [],
                "high": [],
                "medium": [],
                "low": []
            },
            "cve": [],
            "tools_output": {}
        }
        self.user_agents = self.load_user_agents()
        self.payloads = self.load_payloads()
        self.directories = self.load_directories()
        self.setup_environment()

    def setup_environment(self):
        """Initialize environment and check dependencies"""
        os.makedirs("reports", exist_ok=True)
        if sys.platform == "win32":
            self.check_windows_tools()

    def check_windows_tools(self):
        """Verify Windows tool availability"""
        required_tools = ["nmap", "nikto", "sqlmap"]
        for tool in required_tools:
            if not os.path.exists(f"tools/{tool}.exe"):
                print(f"{Fore.RED}[-] {tool} not found in tools directory!")
                sys.exit(1)

    def load_user_agents(self):
        """Load multiple user agents for evasion"""
        return [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
            "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0"
        ]

    def load_payloads(self):
        """Load optimized payloads for speed"""
        try:
            with open('payloads.txt', 'r') as f:
                return [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            return self.create_default_payloads()

    def create_default_payloads(self):
        """Generate optimized payload list"""
        return [
            "' OR 1=1--", 
            "<script>alert('xss')</script>",
            "../../../etc/passwd",
            "UNION SELECT null,@@version--",
            "admin'--",
            "SLEEP(5)--",
            "<?php phpinfo(); ?>"
        ]

    def load_directories(self):
        """Load optimized directory list"""
        try:
            with open('directories.txt', 'r') as f:
                return [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            return ["admin", "wp-content", "backup", "config", "robots.txt"]

    def get_random_header(self):
        """Generate random headers for evasion"""
        return {
            "User-Agent": self.user_agents[hash(datetime.now().microsecond) % len(self.user_agents)],
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Connection": "keep-alive"
        }

    def scan_basic_info(self):
        """Quick basic information gathering"""
        try:
            parsed = urlparse(self.target)
            self.results["basic_info"]["domain"] = parsed.netloc
            self.results["basic_info"]["ip"] = socket.gethostbyname(parsed.netloc)
        except Exception as e:
            print(f"{Fore.RED}[-] Basic info scan error: {e}")

    def directory_scan(self):
        """Optimized multithreaded directory scan"""
        def scan_url(url):
            try:
                response = requests.get(
                    url,
                    headers=self.get_random_header(),
                    proxies=self.proxy,
                    timeout=self.timeout,
                    verify=False
                )
                if response.status_code == 200:
                    self.results["directories"].append(url)
                    return url
            except:
                return None

        print(f"{Fore.YELLOW}[*] Starting directory scan with {self.threads} threads...")
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = [
                executor.submit(scan_url, urljoin(self.target, directory))
                for directory in self.directories
            ]
            for future in tqdm(as_completed(futures), total=len(self.directories), desc="Scanning"):
                future.result()

    def scan_xss(self):
        """Optimized XSS scan with context detection"""
        def test_xss(url):
            try:
                response = requests.get(
                    url,
                    headers=self.get_random_header(),
                    proxies=self.proxy,
                    timeout=self.timeout,
                    verify=False
                )
                for payload in self.payloads:
                    if payload.encode() in response.content:
                        context = "DOM" if "document" in payload else "Reflected"
                        self.results["vulnerabilities"]["medium"].append({
                            "type": "XSS",
                            "url": url,
                            "payload": payload,
                            "context": context
                        })
                        return url
            except:
                return None

        print(f"{Fore.YELLOW}[*] Starting XSS scan...")
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = [executor.submit(test_xss, url) for url in self.generate_test_urls()]
            for future in tqdm(as_completed(futures), total=len(self.payloads)*len(self.directories), desc="XSS Scan"):
                future.result()

    def scan_sqli(self):
        """Optimized SQLi scan with error detection"""
        def test_sqli(url):
            try:
                response = requests.get(
                    url,
                    headers=self.get_random_header(),
                    proxies=self.proxy,
                    timeout=self.timeout,
                    verify=False
                )
                for db, pattern in self.get_sql_patterns().items():
                    if re.search(pattern, response.text):
                        self.results["vulnerabilities"]["critical"].append({
                            "type": "SQLi",
                            "url": url,
                            "dbms": db
                        })
                        return url
            except:
                return None

        print(f"{Fore.YELLOW}[*] Starting SQLi scan...")
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = [executor.submit(test_sqli, url) for url in self.generate_test_urls()]
            for future in tqdm(as_completed(futures), total=len(self.payloads)*len(self.directories), desc="SQLi Scan"):
                future.result()

    def scan_cve(self):
        """Optimized CVE scan using Nmap"""
        try:
            print(f"{Fore.YELLOW}[*] Starting CVE scan...")
            target_ip = self.results["basic_info"]["ip"]
            command = [
                "nmap", "-sV", "--script=vulners", "--script-args", "mincvss=7.0",
                "-p", "80,443,8080", "-T4", "-oN", "reports/nmap_cve.txt", target_ip
            ]
            result = subprocess.run(command, capture_output=True, text=True)
            
            cve_pattern = re.compile(r'(CVE-\d{4}-\d{4,7})')
            self.results["cve"] = list(set(cve_pattern.findall(result.stdout)))
        except Exception as e:
            print(f"{Fore.RED}[-] CVE scan error: {e}")

    def generate_test_urls(self):
        """Generate URLs for vulnerability testing"""
        return [
            f"{urljoin(self.target, directory)}?param={payload}"
            for directory in self.directories
            for payload in self.payloads
        ]

    def get_sql_patterns(self):
        """Return optimized SQL error patterns"""
        return {
            "MySQL": r"SQL syntax.*MySQL",
            "PostgreSQL": r"PostgreSQL.*ERROR",
            "MSSQL": r"Unclosed quotation mark.*SQL Server",
            "Oracle": r"ORA-[0-9]{5}",
            "SQLite": r"SQLite/JDBCDriver"
        }

    def generate_report(self):
        """Generate optimized report"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_file = f"reports/turboscan_report_{timestamp}.json"
        
        try:
            with open(report_file, "w") as f:
                json.dump(self.results, f, indent=2)
            print(f"{Fore.GREEN}[+] Report saved to {report_file}")
        except Exception as e:
            print(f"{Fore.RED}[-] Report generation failed: {e}")

    def show_menu(self):
        """Display optimized menu"""
        while True:
            os.system('cls' if os.name == 'nt' else 'clear')
            print(f"""{Fore.BLUE}
 _____ _____ _____ _____ 
|     |   __|   __|  _  |
| | | |   __|__   |   __|
|_|_|_|_____|_____|__|   v4.0

{Fore.WHITE}Turbo Security Scanner - Optimized for Speed
{Fore.YELLOW}Created by YourName
""")
            print(f"""{Fore.CYAN}
[01] Full Scan (5x Faster)
[02] Quick Scan (10x Faster)
[03] CVE Scan
[04] Generate Report
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
                self.generate_report()
            elif choice == "00":
                sys.exit()
            else:
                print(f"{Fore.RED}[-] Invalid choice!")
                time.sleep(1)

    def run_full_scan(self):
        """Execute optimized full scan"""
        self.target = input(f"{Fore.CYAN}[?] Enter target URL: ").strip()
        self.proxy = input(f"{Fore.CYAN}[?] Proxy (http://ip:port): ").strip() or None
        self.threads = int(input(f"{Fore.CYAN}[?] Threads [50]: ") or 50)
        
        print(f"{Fore.YELLOW}[*] Starting full scan on {self.target}...")
        self.scan_basic_info()
        self.directory_scan()
        self.scan_xss()
        self.scan_sqli()
        self.scan_cve()
        self.generate_report()

    def run_quick_scan(self):
        """Execute ultra-fast scan"""
        self.target = input(f"{Fore.CYAN}[?] Enter target URL: ").strip()
        self.scan_basic_info()
        self.directory_scan()
        self.generate_report()

    def run_cve_scan(self):
        """Execute dedicated CVE scan"""
        self.target = input(f"{Fore.CYAN}[?] Enter target URL: ").strip()
        self.scan_basic_info()
        self.scan_cve()
        self.generate_report()

if __name__ == "__main__":
    scanner = TurboScan()
    scanner.show_menu()
