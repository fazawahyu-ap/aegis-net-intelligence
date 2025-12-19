import requests

class AegisDeepRecon:
    def __init__(self, target_url):
        self.target = target_url if target_url.startswith('http') else f"http://{target_url}"

    def check_sensitive_files(self):
        payloads = [
            '.env',               
            '.git/config',        
            'phpinfo.php',        
            'config.php.bak',     
            '.vscode/sftp.json',  
            'backup.zip',         
            '.htaccess'           
        ]

        results = []
        print(f"[*] Starting Deep Reconnaissance on: {self.target}")

        for path in payloads:
            url = f"{self.target}/{path}"
            try:
                response = requests.get(url, timeout=3, allow_redirects=False)
                
                if response.status_code == 200:
                    results.append({"path": url, "status": "VULNERABLE", "code": 200})
                elif response.status_code == 403:
                    results.append({"path": url, "status": "PROTECTED", "code": 403})
            except:
                pass
        return results