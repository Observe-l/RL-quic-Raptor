import socket

def start_receiver(listen_ip, listen_port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # 绑定到接收端的 IP (192.168.100.2)
    sock.bind((listen_ip, listen_port))
    
    print(f"[Receiver] Listening on {listen_ip}:{listen_port}...")
    
    while True:
        data, addr = sock.recvfrom(1024) # 缓冲区大小
        print(f"[Receiver] Received from {addr}: {data.decode()}")

if __name__ == "__main__":
    # 必须绑定 0.0.0.0 或者 192.168.100.2
    LISTEN_IP = "192.168.100.2" 
    LISTEN_PORT = 4433
    start_receiver(LISTEN_IP, LISTEN_PORT)