import socket
import struct
import threading
import time
import psutil

# Banner drucken
def print_banner():
    print(r"""
                                   Created by
  _       _________ _                            _______  __    ______   ______  
 ( \      \__   __/( (    /||\     /||\     /|  (  ____ \/  \  (  __  \ / ___  \ 
 | (         ) (   |  \  ( || )   ( |( \   / )  | (    \/\/) ) | (  \  )\/   \  \
 | |         | |   |   \ | || |   | | \ (_) /   | |        | | | |   ) |   ___) /
 | |         | |   | (\ \) || |   | |  ) _ (    | |        | | | |   | |  (___ ( 
 | |         | |   | | \   || |   | | / ( ) \   | |        | | | |   ) |      ) \
 | (____/\___) (___| )  \  || (___) |( /   \ )  | (____/\__) (_| (__/  )/\___/  /
 (_______/\_______/|/    )_)(_______)|/     \|  (_______/\____/(______/ \______/ 
""")

# Funktion zur Erkennung des aktiven Interfaces
def get_active_interface():
    # Liste aller Netzwerkinterfaces abrufen
    for interface, addrs in psutil.net_if_addrs().items():
        # Überprüfen, ob es sich um ein physisches (nicht Loopback) Interface handelt
        if interface != 'lo':  # 'lo' ist das Loopback-Interface, das wir nicht verwenden wollen
            for addr in addrs:
                if addr.family == socket.AF_INET:  # IPv4-Adresse gefunden
                    return interface
    return None  # Kein aktives Interface gefunden

# Angriffsschwelle für DDoS
ATTACK_THRESHOLD = 100  # Schwellenwert für die Pakete

# Globale Zähler
tcp_count = 0
udp_count = 0
syn_count = 0
rst_count = 0
fin_count = 0
ack_count = 0
packet_count = 0
spoofed_ips = set()
attack_detected = False

# Netzwerkinterface ermitteln
INTERFACE = get_active_interface()
if INTERFACE is None:
    raise Exception("Kein aktives Netzwerkinterface gefunden!")

print(f"Erkanntes Netzwerkinterface: {INTERFACE}")

# Funktion zur Überwachung des Netzwerkverkehrs
def monitor_traffic():
    global packet_count, attack_detected

    while True:
        # Anzeige der aktuellen Statistiken
        print("\r📊 TCP: {:<5} | UDP: {:<5} | SYN: {:<5} | RST: {:<5} | FIN: {:<5} | ACK: {:<5} | AMPS: {:<5} | TOTAL: {:<5} | ATTACK: {}".format(
            tcp_count, udp_count, syn_count, rst_count, fin_count, ack_count, len(spoofed_ips), packet_count,
            "⚠️ YES" if attack_detected else "NO"
        ), end="")

        # Zurücksetzen der Zähler nach der Anzeige
        reset_counts()

        time.sleep(1)  # Alle 1 Sekunde aktualisieren

# Funktion zum Zurücksetzen der Zähler
def reset_counts():
    global tcp_count, udp_count, syn_count, rst_count, fin_count, ack_count, packet_count, spoofed_ips

    tcp_count = 0
    udp_count = 0
    syn_count = 0
    rst_count = 0
    fin_count = 0
    ack_count = 0
    packet_count = 0
    spoofed_ips.clear()  # Leeren der Spoofed IPs (AMPS)

# Funktion zur Analyse eingehender Pakete
def analyze_packets():
    global tcp_count, udp_count, syn_count, rst_count, fin_count, ack_count, packet_count, spoofed_ips, attack_detected

    # Raw Socket für alle Pakete öffnen
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    s.bind((INTERFACE, 0))

    while True:
        raw_data, addr = s.recvfrom(65535)
        packet_count += 1  # Jedes Paket mitzählen

        # Ethernet-Header (ersten 14 Bytes)
        eth_proto = struct.unpack("!H", raw_data[12:14])[0]

        # Prüfen, ob es sich um ein IPv4-Paket handelt
        if eth_proto == 0x0800:
            # IP-Header (20 Bytes nach Ethernet-Header)
            ip_header = struct.unpack("!BBHHHBBH4s4s", raw_data[14:34])
            protocol = ip_header[6]
            src_ip = socket.inet_ntoa(ip_header[8])

            # TCP
            if protocol == 6:
                tcp_count += 1
                tcp_header = struct.unpack("!HHLLBBHHH", raw_data[34:54])
                flags = tcp_header[5]

                if flags & 0x02:  # SYN
                    syn_count += 1
                if flags & 0x04:  # RST
                    rst_count += 1
                if flags & 0x01:  # FIN
                    fin_count += 1
                if flags & 0x10:  # ACK
                    ack_count += 1

            # UDP
            elif protocol == 17:
                udp_count += 1

            # Spoofed IPs (AMPS-Erkennung)
            if is_spoofed_ip(src_ip):
                spoofed_ips.add(src_ip)

        # Wenn die Gesamtzahl der Pakete einen Schwellenwert überschreitet, markiere es als Angriff
        if packet_count > ATTACK_THRESHOLD:
            attack_detected = True
        else:
            attack_detected = False

# Funktion zur Erkennung von Spoofed IPs
def is_spoofed_ip(ip):
    private_ranges = [
        ("10.0.0.0", "10.255.255.255"),
        ("172.16.0.0", "172.31.255.255"),
        ("192.168.0.0", "192.168.255.255"),
        ("127.0.0.0", "127.255.255.255"),
        ("169.254.0.0", "169.254.255.255")
    ]
    for start, end in private_ranges:
        if ip_in_range(ip, start, end):
            return False
    return True  # IP ist öffentlich, könnte Spoofed sein

# Hilfsfunktion zur Überprüfung von IP-Bereichen
def ip_in_range(ip, start, end):
    ip_int = struct.unpack("!I", socket.inet_aton(ip))[0]
    start_int = struct.unpack("!I", socket.inet_aton(start))[0]
    end_int = struct.unpack("!I", socket.inet_aton(end))[0]
    return start_int <= ip_int <= end_int

# Hauptfunktion
def main():
    # Banner drucken
    print_banner()

    # Netzwerküberwachung starten
    threading.Thread(target=monitor_traffic, daemon=True).start()

    # Paketanalyse starten
    analyze_packets()

# Starten des Skripts
if __name__ == "__main__":
    main()