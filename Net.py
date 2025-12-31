from scapy.all import ARP, Ether, srp
import socket, threading
def __init__(self):
    self.hostname = socket.gethostname()
    self.local_ip = socket.gethostbyname(self.hostname)
    self.target_range = f"{self.local_ip}/24"
def scan(name):
    target_to_scan = name
    packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=target_to_scan)
    answered_list = srp(packet, timeout=2, verbose=False)[0]
    print("IP Address\t\tMAC Address")
    print("-" * 45)
    for sent, received in answered_list:
        print(f"{received.psrc}\t\t{received.hwsrc}")
def Network(name):
    target = name
    IP = socket.gethostbyname(target)
    print(IP)
def ip():
    s = socket.gethostbyname(socket.gethostname())
    print(s)
def name():
    A = socket.gethostname()
    print(A)
def ip_scan(name):
    target = name
    def scan_port(port):    
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)
            if s.connect_ex((target, port)) == 0:
                print(f'[+]Port {port} is OPEN')
            s.close
        except:
            pass
    for port in range(1, 65000):
        thread = threading.Thread(target=scan_port, args=(port,))
        thread.start()
    

