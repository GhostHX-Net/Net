from scapy.all import ARP, Ether, srp
import socket, threading
def __init__(self):
    self.hostname = socket.gethostname()
    self.local_ip = socket.gethostbyname(self.hostname)
    self.target_range = f"{self.local_ip}/24"
def scan(name):#thsi scanes ip for more ips you have to do input like ip_scan(user) user is a input
    target_to_scan = name
    packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=target_to_scan)
    answered_list = srp(packet, timeout=2, verbose=False)[0]
    print("IP Address\t\tMAC Address")
    print("-" * 45)
    for sent, received in answered_list:
        print(f"{received.psrc}\t\t{received.hwsrc}")
def Network(name):#this give a website ip you have to use input ike ip_scan(user) user is a input
    target = name
    IP = socket.gethostbyname(target)
    print(IP)
def ip():#thsi gives you your ip
    s = socket.gethostbyname(socket.gethostname())
    print(s)
def name():#thsi gives you your name you have to do input like ip_scan(user) user is a input
    A = socket.gethostname()
    print(A)
def ip_scan(name):#this is a port scanner you have to do input like ip_scan(user) user is a input
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
