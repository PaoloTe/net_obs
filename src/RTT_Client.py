import socket
import threading
import time
from scapy.all import sniff, IP, UDP, Raw
import pyshark
import sys
import mysql.connector
from mysql.connector import Error


IP =socket.gethostbyname('server')
SERVER_IP = IP

# SERVER_IP = '37.179.114.120'
INTERFACE = 'eth0'

UDP_PORT = 5052
PACKET_COUNT = 10
listening_time = 60 #secondi

# if len(sys.argv) != 4:  #python3 RTT_Client.py #pkt #listening_time #UDP_PORT |------>Eseguire da linea di cmd
#     sys.exit(1)
# PACKET_COUNT = int(sys.argv[1])
# listening_time = float(sys.argv[2])
# UDP_PORT = int(sys.argv[3])
TOS = 0x10

rtt_socket = [0.0] * PACKET_COUNT
rtt_scapy = [0.0] * PACKET_COUNT
rtt_pyshark = [0.0] * PACKET_COUNT
send_times = [0.0] * PACKET_COUNT

received_socket = 0
received_scapy = 0
received_pyshark = 0

DB_CONFIG = {
    "host": "database",
    "port": "3306",
    "user": "user",
    "password": "test",
    "database": "network_performance"
}

def init_db():
    """Crea la tabella se non esiste."""
    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS rtt_results (
                id INT AUTO_INCREMENT PRIMARY KEY,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                packet_count INT,
                listening_time FLOAT,
                udp_port INT,
                avg_socket_ms FLOAT,
                avg_scapy_ms FLOAT,
                avg_pyshark_ms FLOAT,
                lost_socket INT,
                lost_scapy INT,
                lost_pyshark INT
            )
        """)
        conn.commit()
        cursor.close()
        conn.close()
        print("[DB] Tabella 'rtt_results' pronta")
    except Error as e:
        print(f"[DB] Errore durante la creazione della tabella: {e}")

def save_results(packet_count, listening_time, udp_port,
                 avg_socket, avg_scapy, avg_pyshark,
                 lost_socket, lost_scapy, lost_pyshark):
    """Salva i risultati nel database."""
    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor()
        query = """
            INSERT INTO rtt_results (
                packet_count, listening_time, udp_port,
                avg_socket_ms, avg_scapy_ms, avg_pyshark_ms,
                lost_socket, lost_scapy, lost_pyshark
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
        """
        data = (
            packet_count, listening_time, udp_port,
            avg_socket * 1000, avg_scapy * 1000, avg_pyshark * 1000,
            lost_socket, lost_scapy, lost_pyshark
        )
        cursor.execute(query, data)
        conn.commit()
        cursor.close()
        conn.close()
        print("[DB] Risultati salvati correttamente nel database ")
    except Error as e:
        print(f"[DB] Errore durante il salvataggio dei risultati: {e}")


def send_packets():
    global received_socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_TOS, TOS)

    for i in range(PACKET_COUNT):
        message = str(i).encode()
        send_times[i] = time.time()
        sock.sendto(message, (SERVER_IP, UDP_PORT))
        try:
            sock.settimeout(2)
            data, _ = sock.recvfrom(1024)
            rtt_socket[i] = time.time() - send_times[i]
            received_socket += 1
            # print('SOCKET time')
            # print(time.time())
            # print(send_times[i])
            # print(data)
            print(f"[SOCKET] Pacchetto {i} RTT: {rtt_socket[i]*1000:.2f} ms")
        except socket.timeout:
            print(f"[SOCKET] Pacchetto {i} PERSO")

def scapy_sniffer():
    def process_packet(pkt):
        global received_scapy
        # Controlla se il pacchetto ha UDP e Raw
        if pkt.haslayer(UDP) and pkt.haslayer(Raw):
            try:
                payload = pkt[Raw].load.decode(errors="ignore")
                if payload.isdigit():
                    pkt_id = int(payload)
                    if (
                        0 <= pkt_id < PACKET_COUNT
                        and send_times[pkt_id] != 0
                        and rtt_scapy[pkt_id] == 0
                    ):
                        rtt_scapy[pkt_id] = pkt.time - send_times[pkt_id]
                        #print('SCAPY time')
                        #print(pkt.time)
                        #print(send_times[pkt_id])
                        received_scapy += 1
                        print(f"[SCAPY] Pacchetto {pkt_id} RTT: {rtt_scapy[pkt_id]*1000:.2f} ms")
            except Exception as e:
                # Ignora errori di decodifica o parsing
                pass
    sniff(
        iface=INTERFACE,
        filter=f"udp and dst host {SERVER_IP} and port {UDP_PORT}",
        prn=process_packet,
        timeout=listening_time,
        store=False
    )

def pyshark_sniffer():
    global received_pyshark
    capture = pyshark.LiveCapture(
        interface=INTERFACE,
        display_filter=f"ip.dst == {SERVER_IP} and udp.port == {UDP_PORT}")
    for packet in capture.sniff_continuously():
        try:
            payload = bytes.fromhex(packet.udp.payload.replace(":", "")).decode()
            pkt_id = int(payload)
            #print(pkt_id)
            if 0 <= pkt_id < PACKET_COUNT and send_times[pkt_id] != 0 and rtt_pyshark[pkt_id] == 0:
                recv_time = float(packet.sniff_timestamp)
                rtt_pyshark[pkt_id] = recv_time - send_times[pkt_id]
                received_pyshark += 1
                # print('PYSHARK SNIFFER')
                # print(recv_time)
                # print(send_times[pkt_id])
                print(f"[PYSHARK] Pacchetto {pkt_id} RTT: {rtt_pyshark[pkt_id]*1000:} ms")
            if received_pyshark >= PACKET_COUNT:
                break
        except Exception:
            continue
if __name__ == "__main__":
    init_db()  # <-- Crea la tabella se non esiste

    # Start sniffer threads
    threading.Thread(target=scapy_sniffer, daemon=True).start()
    threading.Thread(target=pyshark_sniffer, daemon=True).start()
    time.sleep(2)
    send_packets()
    time.sleep(5)

    print("\n===== RISULTATI FINALI (ms) =====")
    for i in range(PACKET_COUNT):
        print(f"Pkt {i} | socket: {rtt_socket[i]*1000:} | scapy: {rtt_scapy[i]*1000:} | pyshark: {rtt_pyshark[i]*1000:}")

    avg_sock = sum([r for r in rtt_socket if r > 0]) / (len([r for r in rtt_socket if r > 0]) or 1)
    avg_scapy = sum([r for r in rtt_scapy if r > 0]) / (len([r for r in rtt_scapy if r > 0]) or 1)
    avg_pyshark = sum([r for r in rtt_pyshark if r > 0]) / (len([r for r in rtt_pyshark if r > 0]) or 1)

    lost_socket = PACKET_COUNT - received_socket
    lost_scapy = PACKET_COUNT - received_scapy
    lost_pyshark = PACKET_COUNT - received_pyshark

    print(f"\nMedia RTT (ms) | socket: {avg_sock*1000:} | scapy: {avg_scapy*1000:} | pyshark: {avg_pyshark*1000:}")
    print(f"Packet persi   | socket: {lost_socket} | scapy: {lost_scapy} | pyshark: {lost_pyshark}")

    # Salva nel DB
    save_results(PACKET_COUNT, listening_time, UDP_PORT,
                 avg_sock, avg_scapy, avg_pyshark,
                 lost_socket, lost_scapy, lost_pyshark)
