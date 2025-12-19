import socket
from concurrent.futures import ThreadPoolExecutor

class AegisScanner:
    def __init__(self, target):
        self.target = target
        self.open_ports = []

    def scan_single_port(self, port):
        """
        Fungsi untuk scan satu port dengan filter 'Anti-Firewall'.
        Hanya mengembalikan hasil jika port benar-benar mengirim data
        atau merupakan port standar yang dikenal.
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1.0) # Timeout cepat
            result = sock.connect_ex((self.target, port))
            
            if result == 0:
                banner = ""
                has_data = False
                
                # Coba memancing respon (Banner Grabbing)
                try:
                    # Pancingan berbeda untuk HTTP/HTTPS
                    if port in [80, 443, 8080]:
                        sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
                    else:
                        sock.send(b"Hello\r\n")
                    
                    # Coba baca balasan
                    banner = sock.recv(1024).decode().strip()
                    if banner: 
                        has_data = True # Ada balasan teks, berarti port ASLI
                except:
                    pass
                
                sock.close()

                # --- LOGIKA FILTER PORT PALSU (GHOST PORTS) ---
                # Port dianggap valid HANYA jika:
                # 1. Port standar industri (Web, Mail, DB, SSH)
                # 2. ATAU Port tersebut memberikan balasan banner (has_data = True)
                
                major_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 3306, 5432, 8080]
                
                # Jika port ada di daftar umum ATAU port memberikan respon nyata
                if port in major_ports or has_data:
                    return {"port": port, "banner": banner}
                
                # Jika connect sukses tapi port aneh (misal port 2) dan diam saja,
                # kita anggap itu False Positive dari Firewall Vercel/Cloudflare.
                
        except:
            pass
        return None

    def start_scan(self, port_range):
        """
        Fungsi untuk menjalankan scan banyak port sekaligus (Multi-threading).
        Fungsi ini yang dicari oleh main.py!
        """
        print(f"[*] Scanning {self.target} (Port {port_range[0]}-{port_range[-1]})...")
        
        # Menggunakan 100 'pekerja' sekaligus agar cepat
        results = []
        with ThreadPoolExecutor(max_workers=100) as executor:
            # Jalankan scan_single_port untuk setiap angka di port_range
            scan_results = list(executor.map(self.scan_single_port, port_range))
            
            # Bersihkan hasil 'None' (port tertutup/palsu)
            for res in scan_results:
                if res:
                    results.append(res)
        
        # Urutkan hasil berdasarkan nomor port
        return sorted(results, key=lambda x: x['port'])