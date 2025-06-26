from PyQt6.QtCore import QThread, pyqtSignal
from scapy.all import sniff, IP, TCP, UDP
import socket

class NetworkSnifferThread(QThread):
    network_activity = pyqtSignal(str)
    
    def __init__(self):
        super().__init__()
        self._running = True
        
    def run(self):
        def packet_handler(pkt):
            if IP in pkt:
                src = pkt[IP].src
                dst = pkt[IP].dst
                proto = pkt[IP].proto
                
                if proto == 6 and TCP in pkt:  # TCP
                    info = f"TCP {src}:{pkt[TCP].sport} -> {dst}:{pkt[TCP].dport}"
                elif proto == 17 and UDP in pkt:  # UDP
                    info = f"UDP {src}:{pkt[UDP].sport} -> {dst}:{pkt[UDP].dport}"
                else:
                    info = f"IP {src} -> {dst} Proto:{proto}"
                
                try:
                    hostname = socket.gethostbyaddr(dst)[0]
                    info += f" ({hostname})"
                except:
                    pass
                
                self.network_activity.emit(info)
        
        sniff(prn=packet_handler, store=0, timeout=30)
    
    def stop(self):
        self._running = False