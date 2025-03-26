import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import requests
import socket
import whois
import threading
from bs4 import BeautifulSoup
from colorama import Fore, init
import json
import os
import re
from urllib.parse import urlparse, urljoin
from datetime import datetime
from sklearn.ensemble import RandomForestClassifier
from requests_html import HTMLSession
import websocket
import ssl
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import numpy as np

init(autoreset=True)

class MLModel:
    def __init__(self):
        self.model = RandomForestClassifier()
        self._train()

    def _train(self):
        X = [[1500, 1], [500, 0]]
        y = [1, 0]
        self.model.fit(X, y)

    def predict(self, response_length, has_error):
        return self.model.predict([[response_length, has_error]])[0]

class WebScannerPro:
    def __init__(self):
        self.headers = {'User-Agent': 'Mozilla/5.0'}
        self.proxy = None
        self.timeout = 10
        self.wordlist = ['admin', 'login', 'config']
        self.xss_payloads = ["<script>alert('xss')</script>"]
        self.sqli_payloads = ["' OR 1=1--"]
        self.cors_origins = ["https://evil.com", "null"]
        self.ml_model = MLModel()

    def scan_websocket(self, url):
        results = []
        try:
            if not url.startswith(('ws://', 'wss://')):
                url = 'ws://' + url.split('://')[-1]

            def on_message(ws, message):
                results.append(f"Received: {message}")

            def on_error(ws, error):
                results.append(f"Error: {error}")

            def on_close(ws, close_status_code, close_msg):
                results.append("WebSocket closed")

            ws = websocket.WebSocketApp(url,
                on_message=on_message,
                on_error=on_error,
                on_close=on_close)
            
            if url.startswith('ws://'):
                results.append({"type": "WebSocket", "severity": "Critical", "desc": "[!] Insecure WebSocket connection (ws://)"})

            ws.run_forever(sslopt={"cert_reqs": ssl.CERT_NONE})
            ws.send("test_payload")
            
        except Exception as e:
            results.append(f"WebSocket Error: {str(e)}")
        return results

    def scan_vulns(self, url):
        vulns = []
        try:
            # XSS Test
            for payload in self.xss_payloads:
                test_url = f"{url}?search={payload}"
                response = requests.get(test_url, timeout=self.timeout)
                if payload in response.text:
                    vulns.append({
                        "type": "XSS",
                        "severity": "Critical",
                        "desc": f"XSS Found: {payload}"
                    })
            
            # SQLi Test
            for payload in self.sqli_payloads:
                test_url = f"{url}?id={payload}"
                response = requests.get(test_url, timeout=self.timeout)
                if "error" in response.text.lower():
                    vulns.append({
                        "type": "SQLi",
                        "severity": "High",
                        "desc": f"SQLi Found: {payload}"
                    })
        except Exception as e:
            vulns.append({
                "type": "Error",
                "severity": "Medium",
                "desc": f"Scan Error: {str(e)}"
            })
        return vulns

    def scan_cors(self, url):
        results = []
        try:
            for origin in self.cors_origins:
                headers = {'Origin': origin}
                response = requests.get(url, headers=headers, timeout=self.timeout)
                acao = response.headers.get('Access-Control-Allow-Origin', '')
                
                if acao == '*' or acao == origin:
                    results.append({
                        "type": "CORS",
                        "severity": "High",
                        "desc": f"CORS Misconfiguration: {origin} allowed"
                    })
                
                if 'Access-Control-Allow-Credentials' in response.headers:
                    results.append({
                        "type": "CORS",
                        "severity": "Medium",
                        "desc": f"Credentials allowed with {origin}"
                    })
        except Exception as e:
            results.append({
                "type": "CORS",
                "severity": "Low",
                "desc": f"CORS Scan Error: {str(e)}"
            })
        return results

class App:
    def __init__(self, root):
        self.root = root
        self.root.title("WebScannerPro v6.0")
        self.root.geometry("1400x900")
        self.root.configure(bg='#2c2c2c')
        self.scanner = WebScannerPro()

        # Style configuration
        self.style = ttk.Style()
        self.style.theme_use('clam')
        self.style.configure('TFrame', background='#2c2c2c')
        self.style.configure('TLabel', background='#2c2c2c', foreground='white')
        self.style.configure('TButton', background='#4CAF50', foreground='white')
        self.style.map('TButton', background=[('active', '#45a049')])
        self.style.configure('TEntry', fieldbackground='#444', foreground='white')

        # Banner
        self.banner = tk.Label(root, text="WebScannerPro", font=('Arial', 24, 'bold'),
                              fg='#4CAF50', bg='#2c2c2c')
        self.banner.pack(pady=20)

        # Notebook
        self.notebook = ttk.Notebook(root)
        self.notebook.pack(fill='both', expand=True, padx=10, pady=10)

        # Output Tab
        self.output_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.output_tab, text='Text Results')

        # Charts Tab
        self.charts_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.charts_tab, text='Visualizations')

        # Input Frame
        self.input_frame = ttk.Frame(root)
        self.input_frame.pack(pady=10, fill='x')

        ttk.Label(self.input_frame, text="URL:").pack(side=tk.LEFT, padx=5)
        self.url_entry = ttk.Entry(self.input_frame, width=60)
        self.url_entry.pack(side=tk.LEFT, padx=5)
        self.url_entry.insert(0, "http://example.com")

        # Scan Type Frame
        self.scan_type_frame = ttk.Frame(root)
        self.scan_type_frame.pack(pady=10)

        self.scan_type = tk.StringVar(value="basic")
        scan_types = [
            ("Basic Scan", "basic"),
            ("Vuln Scan", "vuln"),
            ("CORS Scan", "cors"),
            ("ML Scan", "ml"),
            ("WebSocket Scan", "websocket")
        ]
        for text, value in scan_types:
            ttk.Radiobutton(self.scan_type_frame, text=text, variable=self.scan_type, value=value).pack(side=tk.LEFT, padx=10)

        # Controls Frame
        self.controls_frame = ttk.Frame(root)
        self.controls_frame.pack(pady=10)

        self.start_btn = ttk.Button(self.controls_frame, text="Start Scan", command=self.start_scan)
        self.start_btn.pack(side=tk.LEFT, padx=5)

        # Output Text
        self.output_text = scrolledtext.ScrolledText(self.output_tab, width=130, height=30, bg='#1e1e1e', fg='#d4d4d4')
        self.output_text.pack(padx=5, pady=5, fill='both', expand=True)
        self.output_text.tag_config('critical', foreground='red')
        self.output_text.tag_config('high', foreground='orange')
        self.output_text.tag_config('medium', foreground='yellow')
        self.output_text.tag_config('low', foreground='#4CAF50')

        # Charts Frame
        self.charts_frame = ttk.Frame(self.charts_tab)
        self.charts_frame.pack(pady=20)

        # Pie Chart Frame
        self.pie_frame = ttk.Frame(self.charts_frame)
        self.pie_frame.pack(side=tk.LEFT, padx=20)

        # Bar Chart Frame
        self.bar_frame = ttk.Frame(self.charts_frame)
        self.bar_frame.pack(side=tk.LEFT, padx=20)

    def start_scan(self):
        url = self.url_entry.get().strip()
        scan_type = self.scan_type.get()
        
        if not url:
            messagebox.showerror("Error", "URL cannot be empty")
            return

        if not url.startswith(('http://', 'https://', 'ws://', 'wss://')):
            url = 'http://' + url

        self.output_text.delete(1.0, tk.END)
        self.output_text.insert(tk.END, f"[*] Starting {scan_type.upper()} scan on {url}\n", 'info')

        # Clear previous charts
        for widget in self.pie_frame.winfo_children():
            widget.destroy()
        for widget in self.bar_frame.winfo_children():
            widget.destroy()

        thread = threading.Thread(target=self.run_scan, args=(url, scan_type))
        thread.start()

    def run_scan(self, url, scan_type):
        try:
            if scan_type == "basic":
                results = self.scanner.scan_basic_info(url)
                self.display_results(results)
            
            elif scan_type == "vuln":
                vulns = self.scanner.scan_vulns(url)
                cors = self.scanner.scan_cors(url)
                ml = self.scanner.ml_scan(url)
                self.display_results({
                    'vulnerabilities': vulns,
                    'cors': cors,
                    'ml_prediction': ml
                })
            
            elif scan_type == "cors":
                results = self.scanner.scan_cors(url)
                self.display_results({'cors': results})
            
            elif scan_type == "ml":
                results = self.scanner.ml_scan(url)
                self.display_results({'ml_prediction': results})
            
            elif scan_type == "websocket":
                results = self.scanner.scan_websocket(url)
                self.display_results({'websocket': results}, severity='critical')
            
            else:
                self.output_text.insert(tk.END, "[-] Invalid scan type\n", 'warning')
        except Exception as e:
            self.output_text.insert(tk.END, f"[-] Scan Error: {str(e)}\n", 'critical')

    def display_results(self, results, severity='info'):
        vuln_stats = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}
        type_stats = {}

        for key, value in results.items():
            self.output_text.insert(tk.END, f"\n--- {key.upper()} ---\n", 'warning')
            
            if isinstance(value, list):
                for item in value:
                    if isinstance(item, dict) and 'severity' in item:
                        severity_level = item['severity']
                        vuln_type = item.get('type', 'Other')
                        vuln_stats[severity_level] = vuln_stats.get(severity_level, 0) + 1
                        type_stats[vuln_type] = type_stats.get(vuln_type, 0) + 1

                        tag = severity_level.lower()
                        self.output_text.insert(tk.END, f"- {item['desc']}\n", tag)
                    else:
                        self.output_text.insert(tk.END, f"- {item}\n", severity)
            else:
                self.output_text.insert(tk.END, f"{value}\n", severity)

        self.generate_charts(vuln_stats, type_stats)

    def generate_charts(self, vuln_stats, type_stats):
        # Pie Chart for Vulnerability Types
        if type_stats:
            fig_pie, ax_pie = plt.subplots(figsize=(6, 4))
            ax_pie.pie(type_stats.values(), labels=type_stats.keys(), autopct='%1.1f%%', startangle=90)
            ax_pie.set_title('Vulnerability Type Distribution')
            canvas_pie = FigureCanvasTkAgg(fig_pie, master=self.pie_frame)
            canvas_pie.draw()
            canvas_pie.get_tk_widget().pack(side=tk.TOP, fill=tk.BOTH, expand=1)

        # Bar Chart for Severity Levels
        if vuln_stats:
            fig_bar, ax_bar = plt.subplots(figsize=(6, 4))
            severities = ['Critical', 'High', 'Medium', 'Low']
            counts = [vuln_stats.get(s, 0) for s in severities]
            ax_bar.bar(severities, counts, color=['red', 'orange', 'yellow', 'green'])
            ax_bar.set_title('Vulnerability Severity Levels')
            ax_bar.set_ylabel('Count')
            canvas_bar = FigureCanvasTkAgg(fig_bar, master=self.bar_frame)
            canvas_bar.draw()
            canvas_bar.get_tk_widget().pack(side=tk.TOP, fill=tk.BOTH, expand=1)

if __name__ == "__main__":
    root = tk.Tk()
    app = App(root)
    root.mainloop()
