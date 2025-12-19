import requests

class VulnAnalyzer:
    @staticmethod
    def fetch_cve(banner):
        # Ambil kata kunci utama, misal 'Apache' dari 'Apache/2.4.41'
        keyword = banner.split('/')[0].split(' ')[0]
        if len(keyword) < 3: return [] # Abaikan hasil yang tidak jelas
        
        url = f"https://cve.circl.lu/api/search/{keyword}"
        try:
            response = requests.get(url, timeout=5)
            if response.status_code == 200:
                # Ambil 3 celah keamanan paling relevan
                return response.json()[:3]
        except:
            return []
        return []