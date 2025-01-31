import tkinter as tk
from tkinter import ttk, scrolledtext
from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP, ICMP
import psutil
import threading
import time

class NetworkAnalyzer:
    def __init__(self, root):
        self.root = root
        self.root.title("Interactive Network Traffic Analyzer")
        self.root.geometry("1400x900")  # Larger window size
        self.sniffer = None
        self.is_sniffing = False
        self.packets = []
        self.protocol_counts = {'TCP': 0, 'UDP': 0, 'ICMP': 0, 'Other': 0}
        self.update_interval = 2  # Seconds
        
        self.create_widgets()
        self.list_interfaces()

    def create_widgets(self):
        # Create the top-level frame for Network Interfaces
        self.interface_frame = ttk.LabelFrame(self.root, text="Network Interfaces", padding=10)
        self.interface_frame.pack(fill=tk.X, padx=10, pady=5)

        self.interface_combo = ttk.Combobox(self.interface_frame, state="readonly", width=30)
        self.interface_combo.pack(padx=5, pady=5)
        
        # Control Buttons
        self.control_frame = ttk.Frame(self.root)
        self.control_frame.pack(fill=tk.X, padx=10, pady=5)

        self.start_btn = ttk.Button(self.control_frame, text="Start Sniffing", command=self.start_sniffing)
        self.start_btn.pack(side=tk.LEFT, padx=10)

        self.stop_btn = ttk.Button(self.control_frame, text="Stop Sniffing", command=self.stop_sniffing, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=10)

        # Packet List Frame
        self.packet_frame = ttk.LabelFrame(self.root, text="Captured Packets", padding=10)
        self.packet_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        self.packet_list = ttk.Treeview(self.packet_frame, columns=('Time', 'Source', 'Destination', 'Protocol', 'Length', 'Packet Name'), show="headings")
        self.packet_list.pack(fill=tk.BOTH, expand=True)

        # Column headers
        for col in ('Time', 'Source', 'Destination', 'Protocol', 'Length', 'Packet Name'):
            self.packet_list.heading(col, text=col)
            self.packet_list.column(col, width=150, anchor="center")
        
        # Scrollbars for packet list
        self.packet_list_scrollbar = ttk.Scrollbar(self.packet_frame, orient="vertical", command=self.packet_list.yview)
        self.packet_list_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.packet_list.configure(yscrollcommand=self.packet_list_scrollbar.set)

        # Packet Details Section
        self.detail_frame = ttk.LabelFrame(self.root, text="Packet Details", padding=10)
        self.detail_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        self.detail_text = scrolledtext.ScrolledText(self.detail_frame, wrap=tk.WORD, width=80, height=15, state=tk.DISABLED)
        self.detail_text.pack(fill=tk.BOTH, expand=True)

        # Statistics Section
        self.stats_frame = ttk.LabelFrame(self.root, text="Statistics", padding=10)
        self.stats_frame.pack(fill=tk.X, padx=10, pady=5)

        self.stats_labels = {
            'TCP': ttk.Label(self.stats_frame, text="TCP: 0", width=20),
            'UDP': ttk.Label(self.stats_frame, text="UDP: 0", width=20),
            'ICMP': ttk.Label(self.stats_frame, text="ICMP: 0", width=20),
            'Other': ttk.Label(self.stats_frame, text="Other: 0", width=20)
        }

        for label in self.stats_labels.values():
            label.pack(side=tk.LEFT, padx=10)

    def list_interfaces(self):
        interfaces = psutil.net_if_addrs().keys()
        self.interface_combo['values'] = list(interfaces)
        if interfaces:
            self.interface_combo.current(0)

    def start_sniffing(self):
        iface = self.interface_combo.get()
        if not iface:
            return

        self.is_sniffing = True
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)

        # Start sniffing with AsyncSniffer
        self.sniffer = AsyncSniffer(iface=iface, prn=self.process_packet, store=False)
        self.sniffer.start()

        # Start the stats update thread
        self.stats_thread = threading.Thread(target=self.update_stats, daemon=True)
        self.stats_thread.start()

    def stop_sniffing(self):
        self.is_sniffing = False
        if self.sniffer:
            self.sniffer.stop()
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)

    def process_packet(self, packet):
        if not self.is_sniffing:
            return

        current_time = time.strftime("%H:%M:%S", time.localtime())
        protocol = "Other"
        packet_name = "Unknown"
        length = len(packet)

        if packet.haslayer(IP):
            src = packet[IP].src
            dst = packet[IP].dst
            if packet.haslayer(TCP):
                protocol = "TCP"
                packet_name = f"TCP {packet[TCP].sport} -> {packet[TCP].dport}"
            elif packet.haslayer(UDP):
                protocol = "UDP"
                packet_name = f"UDP {packet[UDP].sport} -> {packet[UDP].dport}"
            elif packet.haslayer(ICMP):
                protocol = "ICMP"
                packet_name = "ICMP Echo Request/Reply"
        else:
            src = "N/A"
            dst = "N/A"

        self.protocol_counts[protocol] += 1
        packet_info = (current_time, src, dst, protocol, str(length), packet_name)

        # Update GUI in main thread
        self.root.after(0, self.update_packet_list, packet_info)
        self.root.after(0, self.update_packet_details, packet)

    def update_packet_list(self, packet_info):
        self.packet_list.insert('', tk.END, values=packet_info)

    def update_packet_details(self, packet):
        self.detail_text.config(state=tk.NORMAL)
        self.detail_text.delete(1.0, tk.END)
        self.detail_text.insert(tk.END, packet.show(dump=True))
        self.detail_text.config(state=tk.DISABLED)

    def update_stats(self):
        while self.is_sniffing:
            time.sleep(self.update_interval)
            self.root.after(0, self._update_stats_gui)

    def _update_stats_gui(self):
        for proto, label in self.stats_labels.items():
            label.config(text=f"{proto}: {self.protocol_counts[proto]}")

if __name__ == "__main__":
    root = tk.Tk()
    app = NetworkAnalyzer(root)
    root.mainloop()
