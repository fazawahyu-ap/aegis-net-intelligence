import socket
from concurrent.futures import ThreadPoolExecutor

class AegisScanner:
    def __init__(self, target):
        self.target = target

    def scan_single_port(self, port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1.0)
            result = sock.connect_ex((self.target, port))
            
            if result == 0:
                banner = ""
                has_data = False
                
                try:
                    if port in [80, 443, 8080]:
                        sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
                    else:
                        sock.send(b"Hello\r\n")
                    
                    banner = sock.recv(1024).decode().strip()
                    if banner: 
                        has_data = True
                except:
                    pass
                
                sock.close()

                # Filter Ghost Ports (WAF Protection)
                major_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 3306, 5432, 8080]
                
                if port in major_ports or has_data:
                    return {"port": port, "banner": banner}
                
        except:
            pass
        return None

    def start_scan(self, port_range):
        print(f"[*] Scanning {self.target} (Port {port_range[0]}-{port_range[-1]})...")
        
        results = []
        with ThreadPoolExecutor(max_workers=100) as executor:
            scan_results = list(executor.map(self.scan_single_port, port_range))
            
            for res in scan_results:
                if res:
                    results.append(res)
        
        return sorted(results, key=lambda x: x['port'])