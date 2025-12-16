import socket
import sys

#UDP_PORT = 5055
BUFFER_SIZE = 1024

if len(sys.argv) != 2:
    sys.exit(1)
#python3 RTT_Server.py #UDP_PORT |------> Eseguire da linea di cmd
UDP_PORT = int(sys.argv[1])

def start_server():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", UDP_PORT))
    print(f"[Server] In ascolto su UDP {UDP_PORT}")

    while True:
        data, addr = sock.recvfrom(BUFFER_SIZE)
        print(f"[Server] Ricevuto da {addr}: {data}")
        sock.sendto(data, addr)

if __name__ == "__main__":
    start_server()
