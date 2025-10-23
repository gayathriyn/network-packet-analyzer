# network_packet_analyzer_final.py

from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP
import pandas as pd
from datetime import datetime
from colorama import Fore, Style, init

init(autoreset=True)

# --- Settings ---
LOG_FILE = "packet_log.csv"
SUSPICIOUS_PORTS = [4444, 5555, 6667, 23, 135, 139]
packet_data = []

# Create CSV file with headers if it doesn't exist
try:
    df = pd.read_csv(LOG_FILE)
except FileNotFoundError:
    df = pd.DataFrame(columns=["Timestamp", "Source IP", "Destination IP", "Protocol", "Source Port", "Destination Port", "Suspicious"])
    df.to_csv(LOG_FILE, index=False)

# --- Packet analysis function ---
def analyze_packet(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = packet[IP].proto
        proto_name = {6: "TCP", 17: "UDP"}.get(proto, str(proto))
        src_port = dst_port = None
        suspicious = False

        if TCP in packet or UDP in packet:
            src_port = packet.sport
            dst_port = packet.dport
            if src_port in SUSPICIOUS_PORTS or dst_port in SUSPICIOUS_PORTS:
                suspicious = True

        # Print colored output
        color = Fore.RED if suspicious else Fore.GREEN
        print(color + f"[{datetime.now().strftime('%H:%M:%S')}] {src_ip}:{src_port} -> {dst_ip}:{dst_port} | {proto_name}" + Style.RESET_ALL)

        # Append to buffer
        packet_data.append({
            "Timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            "Source IP": src_ip,
            "Destination IP": dst_ip,
            "Protocol": proto_name,
            "Source Port": src_port,
            "Destination Port": dst_port,
            "Suspicious": suspicious
        })

        # Write to CSV every 10 packets
        if len(packet_data) >= 10:
            df_append = pd.DataFrame(packet_data)
            df_append.to_csv(LOG_FILE, mode='a', header=False, index=False)
            packet_data.clear()

# --- Start sniffing ---
print(Fore.CYAN + "Starting network packet capture... Press Ctrl+C to stop." + Style.RESET_ALL)
sniff(prn=analyze_packet, store=False)
