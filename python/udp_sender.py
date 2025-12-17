import socket
import time

def send_udp_packet(ip, port, message):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # 【修改点】这里之前写的是 '10.0.0.2'，现在改为使用传入的 ip 变量
        sock.sendto(message.encode(), (ip, port))
        print(f"[Sender] Sent packet to {ip}:{port} | Content: {message}")
    except Exception as e:
        print(f"Error sending packet: {e}")
    finally:
        sock.close()

if __name__ == "__main__":
    TARGET_IP = "192.168.100.2" # 这是接收端 receiver_ns 的 IP
    TARGET_PORT = 4433           # 目标端口
    
    # 为了演示卫星效果，建议发送多个包，观察是否有丢包
    print(f"Start sending to satellite link ({TARGET_IP})...")
    
    for i in range(1, 6):
        msg = f"Hello Satellite Packet #{i}"
        send_udp_packet(TARGET_IP, TARGET_PORT, msg)
        time.sleep(1) # 每隔1秒发一个