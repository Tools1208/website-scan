import requests
from bs4 import BeautifulSoup
import socket
import threading
import json
import re
import os
from urllib.parse import urljoin
from colorama import Fore, init

init(autoreset=True)

class WebScanner:
    def __init__(self, target, proxy=None, threads=10):
        self.target = self.ensure_http(target)
        self.proxy = proxy
        self.threads = threads
        self.results = {
            "target": self.target,
            "ip_info": {},
            "server_info": {},
            "vulnerabilities": {
                "xss": [],
                "sqli": [],
                "sensitive_data": []
            },
            "directories": [],
            "internal_links": []
        }
        
        self.load_payloads()
        self.session = requests.Session()
        if proxy:
            self.session.proxies = {"http": proxy, "https": proxy}

    def ensure_http(self, url):
        return url if url.startswith(('http://', 'https://')) else f"http://{url}"

    def load_payloads(self):
        with open('payloads.txt', 'r') as f:
            self.payloads = [line.strip() for line in f if line.strip()]

    def get_ip_info(self):
        try:
            ip = socket.gethostbyname(self.target.split('//')[1])
            self.results['ip_info']['ip'] = ip
            self.results['ip_info']['hostname'] = socket.gethostbyaddr(ip)[0]
        except Exception as e:
            print(f"{Fore.RED}[-] Error getting IP info: {e}")

    def check_server_status(self):
        try:
            response = self.session.get(self.target)
            self.results['server_info']['status_code'] = response.status_code
            self.results['server_info']['server_header'] = response.headers.get('Server', '')
        except Exception as e:
            print(f"{Fore.RED}[-] Server check failed: {e}")

    def scan_xss(self):
        print(f"{Fore.YELLOW}[*] Starting XSS scan...")
        try:
            forms = self.get_forms()
            for form in forms:
                for payload in self.payloads:
                    response = self.submit_form(form, payload)
                    if payload.encode() in response.content:
                        self.results['vulnerabilities']['xss'].append({
                            "form": str(form),
                            "payload": payload
                        })
                        print(f"{Fore.GREEN}[+] XSS vulnerability found with payload: {payload}")
        except Exception as e:
            print(f"{Fore.RED}[-] XSS scan error: {e}")

    def get_forms(self):
        response = self.session.get(self.target)
        soup = BeautifulSoup(response.content, 'html.parser')
        return soup.find_all('form')

    def submit_form(self, form, payload):
        action = form.get('action')
        method = form.get('method', 'get').lower()
        inputs = form.find_all('input')
        data = {}
        
        for input_field in inputs:
            name = input_field.get('name')
            value = input_field.get('value', '')
            if name:
                data[name] = payload if input_field.get('type') != 'submit' else value
        
        url = urljoin(self.target, action)
        return self.session.request(method, url, data=data)

    def scan_sqli(self):
        print(f"{Fore.YELLOW}[*] Starting SQLi scan...")
        try:
            paths = [''] + [f'/{d}' for d in self.results['directories']]
            for path in paths:
                url = urljoin(self.target, path)
                for payload in self.payloads:
                    test_url = f"{url}?id={payload}"
                    response = self.session.get(test_url)
                    errors = ['SQL syntax', 'mysql_fetch', 'You have an error in your SQL syntax']
                    if any(error in response.text for error in errors):
                        self.results['vulnerabilities']['sqli'].append({
                            "url": test_url,
                            "payload": payload
                        })
                        print(f"{Fore.GREEN}[+] SQLi vulnerability found at: {test_url}")
        except Exception as e:
            print(f"{Fore.RED}[-] SQLi scan error: {e}")

    def dir_scan(self):
        print(f"{Fore.YELLOW}[*] Starting directory scan...")
        directories = []
        with open('directories.txt', 'r') as f:
            directories = [line.strip() for line in f if line.strip()]

        def scan_chunk(chunk):
            for dir in chunk:
                url = urljoin(self.target, dir)
                try:
                    response = self.session.get(url)
                    if response.status_code == 200:
                        self.results['directories'].append(url)
                        print(f"{Fore.GREEN}[+] Found directory: {url}")
                except:
                    continue

        chunks = [directories[i::self.threads] for i in range(self.threads)]
        threads = []
        for chunk in chunks:
            t = threading.Thread(target=scan_chunk, args=(chunk,))
            threads.append(t)
            t.start()
        for t in threads:
            t.join()

    def extract_sensitive_data(self):
        print(f"{Fore.YELLOW}[*] Extracting sensitive data...")
        try:
            response = self.session.get(self.target)
            content = response.text

            # Extract emails
            emails = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', content)
            if emails:
                self.results['vulnerabilities']['sensitive_data'].extend(
                    [{"type": "email", "data": email} for email in emails]
                )

            # Extract potential passwords
            password_patterns = [
                r'password\s*[=:]\s*[\'"]?(\w+)[\'"]?',
                r'pwd\s*[=:]\s*[\'"]?(\w+)[\'"]?',
                r'passwd\s*[=:]\s*[\'"]?(\w+)[\'"]?'
            ]
            for pattern in password_patterns:
                passwords = re.findall(pattern, content, re.IGNORECASE)
                if passwords:
                    self.results['vulnerabilities']['sensitive_data'].extend(
                        [{"type": "password", "data": pwd} for pwd in passwords]
                    )

        except Exception as e:
            print(f"{Fore.RED}[-] Sensitive data extraction error: {e}")

    def analyze_internal_links(self):
        print(f"{Fore.YELLOW}[*] Analyzing internal links...")
        try:
            response = self.session.get(self.target)
            soup = BeautifulSoup(response.content, 'html.parser')
            links = [a['href'] for a in soup.find_all('a', href=True)]
            for link in links:
                full_url = urljoin(self.target, link)
                if self.target in full_url:
                    self.results['internal_links'].append(full_url)
        except Exception as e:
            print(f"{Fore.RED}[-] Link analysis error: {e}")

    def generate_report(self, format='json'):
        try:
            if format == 'json':
                with open('report.json', 'w') as f:
                    json.dump(self.results, f, indent=4)
                print(f"{Fore.GREEN}[+] Report saved to report.json")
            else:
                with open('report.txt', 'w') as f:
                    for key, value in self.results.items():
                        f.write(f"{key.upper()}\n")
                        f.write(f"{value}\n\n")
                print(f"{Fore.GREEN}[+] Report saved to report.txt")
        except Exception as e:
            print(f"{Fore.RED}[-] Report generation failed: {e}")

    def run_full_scan(self):
        self.get_ip_info()
        self.check_server_status()
        self.dir_scan()
        self.scan_xss()
        self.scan_sqli()
        self.extract_sensitive_data()
        self.analyze_internal_links()

def print_banner():
    os.system('cls' if os.name == 'nt' else 'clear')
    banner = f"""
{Fore.BLUE} _____ _____ _____ _____ 
|     |   __|   __|  _  |
| | | |   __|__   |   __|
|_|_|_|_____|_____|__|   v1.0

{Fore.WHITE}Advanced Web Vulnerability Scanner
{Fore.YELLOW}Created by YourName
"""
    print(banner)

def main():
    print_banner()
    
    # تحميل الملفات تلقائيًا
    required_files = ['directories.txt', 'payloads.txt']
    for file in required_files:
        if not os.path.exists(file):
            print(f"{Fore.RED}[-] Missing {file}! Creating default file...")
            with open(file, 'w') as f:
                if file == 'directories.txt':
                    f.write("admin\nwp-content\nuploads\nconfig\nbackup\n")
                elif file == 'payloads.txt':
                    f.write("' OR 1=1--\n<script>alert('xss')</script>\n")

    target = input(f"{Fore.CYAN}[?] Enter target URL: ")
    proxy = input(f"{Fore.CYAN}[?] Enter proxy (http://ip:port) [Optional]: ") or None
    threads = int(input(f"{Fore.CYAN}[?] Enter number of threads [10]: ") or 10)
    
    scanner = WebScanner(target, proxy, threads)
    
    print(f"\n{Fore.WHITE}Select scan type:")
    print(f"{Fore.GREEN}[01] Full Scan")
    print(f"{Fore.RED}[00] Exit")
    
    choice = input(f"{Fore.CYAN}\n[?] Enter choice: ")
    
    if choice == '01':
        print(f"{Fore.YELLOW}\n[*] Starting full scan on {target}...\n")
        scanner.run_full_scan()
        report_format = input("\n[?] Save report as [json/txt]: ").lower()
        scanner.generate_report(report_format)
    elif choice == '00':
        print(f"{Fore.RED}[-] Exiting...")
        exit()
    else:
        print(f"{Fore.RED}[-] Invalid choice!")
        exit()

if __name__ == "__main__":
    main()
