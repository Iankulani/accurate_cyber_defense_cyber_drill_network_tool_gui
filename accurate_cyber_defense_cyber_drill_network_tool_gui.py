import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import socket
import threading
import time
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import subprocess
import psutil
import netifaces
import dns.resolver
import platform
import datetime
from scapy.all import sniff, IP, TCP, UDP, ICMP
import pandas as pd
import numpy as np

class CyberSecurityTool:
    def __init__(self, root):
        self.root = root
        self.root.title("Accurate Cyber Defense Cyber Drill Network Tool")
        self.root.geometry("1200x800")
        self.root.configure(bg='black')
        
        # Variables
        self.monitoring = False
        self.target_ip = tk.StringVar()
        self.packet_count = 0
        self.threat_data = {
            'DDOS': 0,
            'DOS': 0,
            'UDP Flood': 0,
            'HTTPS Flood': 0,
            'Other': 0
        }
        self.network_data = []
        self.create_widgets()
        
    def create_widgets(self):
        # Menu Bar
        self.menu_bar = tk.Menu(self.root)
        
        # File Menu
        self.file_menu = tk.Menu(self.menu_bar, tearoff=0, bg='black', fg='green')
        self.file_menu.add_command(label="Exit", command=self.root.quit)
        self.menu_bar.add_cascade(label="File", menu=self.file_menu)
        
        # Tools Menu
        self.tools_menu = tk.Menu(self.menu_bar, tearoff=0, bg='black', fg='green')
        self.tools_menu.add_command(label="Network Scanner", command=self.show_network_scanner)
        self.tools_menu.add_command(label="Port Scanner", command=self.show_port_scanner)
        self.menu_bar.add_cascade(label="Tools", menu=self.tools_menu)
        
        # View Menu
        self.view_menu = tk.Menu(self.menu_bar, tearoff=0, bg='black', fg='green')
        self.view_menu.add_command(label="Dark Theme", command=self.set_dark_theme)
        self.view_menu.add_command(label="Light Theme", command=self.set_light_theme)
        self.menu_bar.add_cascade(label="View", menu=self.view_menu)
        
        # Help Menu
        self.help_menu = tk.Menu(self.menu_bar, tearoff=0, bg='black', fg='green')
        self.help_menu.add_command(label="About", command=self.show_about)
        self.help_menu.add_command(label="Documentation", command=self.show_docs)
        self.menu_bar.add_cascade(label="Help", menu=self.help_menu)
        
        self.root.config(menu=self.menu_bar)
        
        # Main Frame
        self.main_frame = ttk.Frame(self.root)
        self.main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Left Panel
        self.left_panel = ttk.Frame(self.main_frame, width=300)
        self.left_panel.pack(side=tk.LEFT, fill=tk.Y, padx=5, pady=5)
        
        # IP Entry
        ttk.Label(self.left_panel, text="Enter IP Address:", foreground='green', background='black').pack(pady=5)
        self.ip_entry = ttk.Entry(self.left_panel, textvariable=self.target_ip)
        self.ip_entry.pack(pady=5, fill=tk.X)
        
        # Buttons
        self.start_btn = ttk.Button(self.left_panel, text="Start Monitoring", command=self.start_monitoring)
        self.start_btn.pack(pady=5, fill=tk.X)
        
        self.stop_btn = ttk.Button(self.left_panel, text="Stop Monitoring", command=self.stop_monitoring, state=tk.DISABLED)
        self.stop_btn.pack(pady=5, fill=tk.X)
        
        # Threat Stats
        self.stats_frame = ttk.LabelFrame(self.left_panel, text="Threat Statistics")
        self.stats_frame.pack(pady=10, fill=tk.X)
        
        for threat in self.threat_data:
            ttk.Label(self.stats_frame, text=f"{threat}: {self.threat_data[threat]}").pack(anchor=tk.W)
        
        # Right Panel
        self.right_panel = ttk.Frame(self.main_frame)
        self.right_panel.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)
        
        # Notebook for tabs
        self.notebook = ttk.Notebook(self.right_panel)
        self.notebook.pack(fill=tk.BOTH, expand=True)
        
        # Dashboard Tab
        self.dashboard_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.dashboard_tab, text="Dashboard")
        
        # Create charts
        self.create_charts()
        
        # Terminal Tab
        self.terminal_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.terminal_tab, text="Terminal")
        
        self.terminal_output = scrolledtext.ScrolledText(
            self.terminal_tab, wrap=tk.WORD, width=80, height=20,
            bg='black', fg='green', insertbackground='green'
        )
        self.terminal_output.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.terminal_input = ttk.Entry(self.terminal_tab)
        self.terminal_input.pack(fill=tk.X, padx=5, pady=5)
        self.terminal_input.bind("<Return>", self.process_terminal_command)
        
        # Network Traffic Tab
        self.traffic_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.traffic_tab, text="Network Traffic")
        
        self.traffic_text = scrolledtext.ScrolledText(
            self.traffic_tab, wrap=tk.WORD, width=80, height=20,
            bg='black', fg='green', insertbackground='green'
        )
        self.traffic_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Status Bar
        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        self.status_bar = ttk.Label(self.root, textvariable=self.status_var, relief=tk.SUNKEN)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)
        
        # Print welcome message
        self.print_terminal("Cyber Security Monitoring Tool initialized. Type 'help' for commands.")
    
    def create_charts(self):
        # Create figure for charts
        self.figure = plt.Figure(figsize=(8, 6), dpi=100, facecolor='black')
        
        # Threat Distribution Pie Chart
        self.pie_ax = self.figure.add_subplot(121)
        self.pie_ax.set_title("Threat Distribution", color='green')
        self.figure.patch.set_facecolor('black')
        self.pie_ax.set_facecolor('black')
        self.pie_ax.tick_params(colors='green')
        
        # Traffic Over Time Bar Chart
        self.bar_ax = self.figure.add_subplot(122)
        self.bar_ax.set_title("Traffic Over Time", color='green')
        self.bar_ax.set_facecolor('black')
        self.bar_ax.tick_params(colors='green')
        
        # Create canvas
        self.chart_canvas = FigureCanvasTkAgg(self.figure, self.dashboard_tab)
        self.chart_canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        
        # Initial empty charts
        self.update_charts()
    
    def update_charts(self):
        # Update pie chart
        self.pie_ax.clear()
        labels = list(self.threat_data.keys())
        sizes = list(self.threat_data.values())
        
        if sum(sizes) > 0:
            self.pie_ax.pie(sizes, labels=labels, autopct='%1.1f%%', 
                           textprops={'color': 'green'})
            self.pie_ax.set_title("Threat Distribution", color='green')
        
        # Update bar chart
        self.bar_ax.clear()
        if len(self.network_data) > 0:
            df = pd.DataFrame(self.network_data[-10:], columns=['Time', 'Packets'])
            self.bar_ax.bar(df['Time'], df['Packets'], color='green')
            self.bar_ax.set_title("Traffic Over Time", color='green')
            self.bar_ax.set_ylabel("Packets/sec", color='green')
            self.bar_ax.tick_params(axis='x', rotation=45, colors='green')
            self.bar_ax.tick_params(axis='y', colors='green')
        
        self.figure.tight_layout()
        self.chart_canvas.draw()
    
    def start_monitoring(self):
        ip = self.target_ip.get()
        if not ip:
            messagebox.showerror("Error", "Please enter an IP address")
            return
        
        try:
            socket.inet_aton(ip)
        except socket.error:
            messagebox.showerror("Error", "Invalid IP address")
            return
        
        self.monitoring = True
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.status_var.set(f"Monitoring {ip}...")
        
        # Start packet capture in a separate thread
        self.capture_thread = threading.Thread(
            target=self.capture_packets,
            args=(ip,),
            daemon=True
        )
        self.capture_thread.start()
        
        # Start traffic monitoring
        self.traffic_thread = threading.Thread(
            target=self.monitor_traffic,
            daemon=True
        )
        self.traffic_thread.start()
        
        self.print_terminal(f"Started monitoring on {ip}")
    
    def stop_monitoring(self):
        self.monitoring = False
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.status_var.set("Monitoring stopped")
        self.print_terminal("Stopped monitoring")
    
    def capture_packets(self, target_ip):
        def packet_callback(packet):
            if not self.monitoring:
                return False  # Stop sniffing
            
            self.packet_count += 1
            
            if IP in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                
                # Check if packet is related to our target IP
                if src_ip == target_ip or dst_ip == target_ip:
                    self.process_packet(packet)
            
            # Update UI in main thread
            self.root.after(0, self.update_ui)
            
            return True  # Continue sniffing
        
        sniff(prn=packet_callback, store=0, filter=f"host {target_ip}")
    
    def process_packet(self, packet):
        now = datetime.datetime.now().strftime("%H:%M:%S")
        
        # Detect threats
        if TCP in packet:
            if packet[TCP].flags == 'S':  # SYN flood (DOS)
                self.threat_data['DOS'] += 1
                self.traffic_text.insert(tk.END, f"[{now}] DOS attack detected from {packet[IP].src}\n")
            elif packet[TCP].dport == 443:  # HTTPS flood
                self.threat_data['HTTPS Flood'] += 1
                self.traffic_text.insert(tk.END, f"[{now}] HTTPS Flood detected from {packet[IP].src}\n")
        elif UDP in packet:
            self.threat_data['UDP Flood'] += 1
            self.traffic_text.insert(tk.END, f"[{now}] UDP Flood detected from {packet[IP].src}\n")
        elif ICMP in packet:
            self.threat_data['DDOS'] += 1
            self.traffic_text.insert(tk.END, f"[{now}] DDOS attack detected from {packet[IP].src}\n")
        else:
            self.threat_data['Other'] += 1
        
        # Auto-scroll traffic text
        self.traffic_text.see(tk.END)
    
    def monitor_traffic(self):
        prev_count = self.packet_count
        
        while self.monitoring:
            time.sleep(1)
            current_count = self.packet_count
            packets_per_sec = current_count - prev_count
            prev_count = current_count
            
            now = datetime.datetime.now().strftime("%H:%M:%S")
            self.network_data.append((now, packets_per_sec))
            
            # Keep only last 10 entries
            if len(self.network_data) > 10:
                self.network_data.pop(0)
            
            # Update charts
            self.root.after(0, self.update_charts)
    
    def update_ui(self):
        # Update threat statistics
        for i, (threat, count) in enumerate(self.threat_data.items()):
            self.stats_frame.winfo_children()[i].config(text=f"{threat}: {count}")
    
    def process_terminal_command(self, event):
        cmd = self.terminal_input.get().strip()
        self.terminal_input.delete(0, tk.END)
        
        self.print_terminal(f"> {cmd}")
        
        if not cmd:
            return
        
        parts = cmd.split()
        command = parts[0].lower()
        
        try:
            if command == "help":
                self.show_help()
            elif command == "ping" and len(parts) > 1:
                self.ping(parts[1])
            elif command == "dnslookup" and len(parts) > 1:
                self.dns_lookup(parts[1])
            elif command == "traceroute" and len(parts) > 1:
                self.traceroute(parts[1])
            elif command == "start" and len(parts) > 2 and parts[1] == "monitoring":
                self.target_ip.set(parts[2])
                self.start_monitoring()
            elif command == "stop":
                self.stop_monitoring()
            elif command == "ifconfig" and len(parts) > 1 and parts[1] == "/all":
                self.ifconfig_all()
            elif command == "tree":
                self.tree()
            elif command == "netstat":
                self.netstat()
            elif command == "netsh" and len(parts) > 4 and parts[1] == "wlan" and parts[2] == "show" and parts[3] == "profile":
                self.show_wifi_password(parts[4])
            else:
                self.print_terminal("Unknown command. Type 'help' for available commands.")
        except Exception as e:
            self.print_terminal(f"Error: {str(e)}")
    
    def print_terminal(self, message):
        self.terminal_output.insert(tk.END, message + "\n")
        self.terminal_output.see(tk.END)
    
    def show_help(self):
        help_text = """
Available Commands:
  help                         - Show this help message
  ping <IP/hostname>           - Ping a host
  dnslookup <domain>           - Perform DNS lookup
  traceroute <IP/hostname>     - Trace route to host
  start monitoring <IP>        - Start monitoring an IP address
  stop                         - Stop monitoring
  ifconfig /all                - Show network interface information
  tree                         - Show directory tree
  netstat                      - Show network statistics
  netsh wlan show profile name="NETWORK_NAME" key=clear - Show WiFi password
"""
        self.print_terminal(help_text)
    
    def ping(self, target):
        param = "-n" if platform.system().lower() == "windows" else "-c"
        count = "4"
        
        try:
            output = subprocess.check_output(["ping", param, count, target], stderr=subprocess.STDOUT, text=True)
            self.print_terminal(output)
        except subprocess.CalledProcessError as e:
            self.print_terminal(e.output)
    
    def dns_lookup(self, domain):
        try:
            answers = dns.resolver.resolve(domain, 'A')
            for rdata in answers:
                self.print_terminal(f"{domain} has address {rdata.address}")
        except Exception as e:
            self.print_terminal(f"DNS lookup failed: {str(e)}")
    
    def traceroute(self, target):
        try:
            if platform.system().lower() == "windows":
                output = subprocess.check_output(["tracert", target], stderr=subprocess.STDOUT, text=True)
            else:
                output = subprocess.check_output(["traceroute", target], stderr=subprocess.STDOUT, text=True)
            self.print_terminal(output)
        except subprocess.CalledProcessError as e:
            self.print_terminal(e.output)
    
    def ifconfig_all(self):
        try:
            interfaces = netifaces.interfaces()
            for iface in interfaces:
                addrs = netifaces.ifaddresses(iface)
                self.print_terminal(f"\nInterface: {iface}")
                
                if netifaces.AF_INET in addrs:
                    self.print_terminal("IPv4 Addresses:")
                    for addr in addrs[netifaces.AF_INET]:
                        for key, val in addr.items():
                            self.print_terminal(f"  {key}: {val}")
                
                if netifaces.AF_LINK in addrs:
                    self.print_terminal("MAC Address:")
                    for addr in addrs[netifaces.AF_LINK]:
                        self.print_terminal(f"  addr: {addr['addr']}")
        except Exception as e:
            self.print_terminal(f"Error getting interface info: {str(e)}")
    
    def tree(self):
        try:
            if platform.system().lower() == "windows":
                output = subprocess.check_output(["tree"], stderr=subprocess.STDOUT, text=True, shell=True)
            else:
                output = subprocess.check_output(["tree"], stderr=subprocess.STDOUT, text=True)
            self.print_terminal(output)
        except subprocess.CalledProcessError as e:
            self.print_terminal(e.output)
    
    def netstat(self):
        try:
            output = subprocess.check_output(["netstat", "-ano"], stderr=subprocess.STDOUT, text=True)
            self.print_terminal(output)
        except subprocess.CalledProcessError as e:
            self.print_terminal(e.output)
    
    def show_wifi_password(self, ssid):
        try:
            if platform.system().lower() == "windows":
                command = f'netsh wlan show profile name="{ssid}" key=clear'
                output = subprocess.check_output(command, stderr=subprocess.STDOUT, text=True, shell=True)
                self.print_terminal(output)
            else:
                self.print_terminal("This command is only available on Windows")
        except subprocess.CalledProcessError as e:
            self.print_terminal(e.output)
    
    def show_network_scanner(self):
        self.print_terminal("Network scanner functionality would go here")
        # Implement actual network scanning using nmap or similar
    
    def show_port_scanner(self):
        self.print_terminal("Port scanner functionality would go here")
        # Implement actual port scanning
    
    def set_dark_theme(self):
        self.root.configure(bg='black')
        self.terminal_output.configure(bg='black', fg='green')
        self.traffic_text.configure(bg='black', fg='green')
        self.print_terminal("Switched to dark theme")
    
    def set_light_theme(self):
        self.root.configure(bg='white')
        self.terminal_output.configure(bg='white', fg='black')
        self.traffic_text.configure(bg='white', fg='black')
        self.print_terminal("Switched to light theme")
    
    def show_about(self):
        about_text = """
Accurate Cyber Defense Cyber Drill Network Tool Gui
Version 7.0
Author:Ian Carter Kulani
E-mail:iancarterkulani@gmail.com
phone:+265(0)988061969

A comprehensive tool for monitoring network traffic and detecting security threats.
Features include:
- Real-time packet capture and analysis
- Threat detection (DDOS, DOS, UDP/HTTPS floods)
- Network diagnostic tools
- Visual analytics
"""
        messagebox.showinfo("About", about_text)
    
    def show_docs(self):
        docs_text = """
Documentation:

1. Getting Started:
   - Enter an IP address and click "Start Monitoring" to begin
   - Use the terminal for advanced commands

2. Threat Detection:
   - The tool automatically detects common network threats
   - Statistics are shown in the left panel and charts

3. Terminal Commands:
   - Type 'help' for a list of available commands
   - Commands include ping, traceroute, DNS lookup, etc.

4. Charts:
   - Threat distribution (pie chart)
   - Traffic over time (bar chart)
"""
        messagebox.showinfo("Documentation", docs_text)

if __name__ == "__main__":
    root = tk.Tk()
    style = ttk.Style()
    style.theme_use('clam')
    style.configure('.', background='black', foreground='green')
    style.configure('TFrame', background='black')
    style.configure('TLabel', background='black', foreground='green')
    style.configure('TButton', background='black', foreground='green')
    style.configure('TEntry', fieldbackground='black', foreground='green')
    style.configure('TNotebook', background='black')
    style.configure('TNotebook.Tab', background='black', foreground='green')
    
    app = CyberSecurityTool(root)
    root.mainloop()