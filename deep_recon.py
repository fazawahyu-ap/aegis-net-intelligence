import requests

class AegisDeepRecon:
    def __init__(self, target_url):
        # Pastikan target_url memiliki format http:// atau https://
        self.target = target_url if target_url.startswith('http') else f"http://{target_url}"

    def check_sensitive_files(self):
        # Daftar "Harta Karun" bagi peneliti keamanan
        payloads = [
            '.env',               # Berisi password database/API Key
            '.git/config',        # Berisi histori kode dan kredensial
            'phpinfo.php',        # Membocorkan detail server lengkap
            'config.php.bak',     # Cadangan file konfigurasi
            '.vscode/sftp.json',  # Berisi login FTP ke server
            'backup.zip',         # File backup data lama
            'api/v1/users',       # Mencoba melihat endpoint API
            '.htaccess'           # Konfigurasi akses server
        ]

        results = []
        print(f"[*] Memulai Deep Reconnaissance pada: {self.target}")

        for path in payloads:
            url = f"{self.target}/{path}"
            try:
                # Kita gunakan HEAD atau GET dengan timeout singkat
                response = requests.get(url, timeout=3, allow_redirects=False)
                
                # Jika 200 OK, berarti file ada dan bisa dibaca!
                if response.status_code == 200:
                    print(f"[!!!] TEMUAN KRITIKAL: {url}")
                    results.append({"path": url, "status": "VULNERABLE", "code": 200})
                elif response.status_code == 403:
                    # Forbidden biasanya berarti file ada tapi diproteksi (masih info penting)
                    results.append({"path": url, "status": "PROTECTED", "code": 403})
            except:
                pass
        return results