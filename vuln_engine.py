import requests

class VulnAnalyzer:
    @staticmethod
    def fetch_cve(banner):
        if not banner: return []
        
        # Extract main keyword, e.g., 'Apache' from 'Apache/2.4.41'
        keyword = banner.split('/')[0].split(' ')[0]
        if len(keyword) < 3: return []
        
        url = f"https://cve.circl.lu/api/search/{keyword}"
        try:
            response = requests.get(url, timeout=5)
            if response.status_code == 200:
                # Return top 3 results
                return response.json()[:3]
        except:
            return []
        return []