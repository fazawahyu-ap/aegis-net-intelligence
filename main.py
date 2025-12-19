from scanner import AegisScanner
from vuln_engine import VulnAnalyzer
from reporter import save_report
from deep_recon import AegisDeepRecon
from web_audit import AegisWebAuditor 

def main():
    print("="*60)
    print("        AEGIS NETWORK & WEB INTELLIGENCE SUITE v4.5        ")
    print("        Full-Stack Security Audit (Infra + Web App)        ")
    print("="*60)

    raw_target = input("[?] Masukkan IP/Domain Target: ")

    # --- PERBAIKAN LOGIKA INPUT (CRITICAL FIX) ---
    # 1. Bersihkan protokol (http/https)
    clean_step1 = raw_target.replace("https://", "").replace("http://", "")
    
    # 2. Bersihkan path belakang (misal /index.php)
    target_clean_full = clean_step1.split('/')[0]  # Contoh: "localhost:8080"
    
    # 3. Pisahkan HOSTNAME dan PORT (Ini perbaikan utamanya)
    if ":" in target_clean_full:
        target_host = target_clean_full.split(":")[0] # Ambil "localhost"
    else:
        target_host = target_clean_full # Ambil "dinus.ac.id"
        
    # 4. Tentukan URL Lengkap untuk Web Audit
    if raw_target.startswith("http"):
        target_url = raw_target
    else:
        # Gunakan target_clean_full agar port 8080 tetap terbawa di URL
        target_url = f"http://{target_clean_full}"
        
    print(f"[*] Target Host: {target_host}")
    print(f"[*] Target URL : {target_url}")
    
    # Range Port diperluas agar kena 8080, 8000, 8888, dll
    ports = range(1, 8200)

    # --- PHASE 1: INFRASTRUCTURE SCAN ---
    print(f"\n[STEP 1] Infrastructure & Port Scanning...")
    
    # PENTING: Gunakan 'target_host' (bersih tanpa port), bukan raw_target
    engine = AegisScanner(target_host) 
    discovered = engine.start_scan(ports)
    
    final_scan_results = []
    
    # Database Service diperbarui dengan port 8080
    common_services = {
        21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
        53: "dns", 80: "http", 110: "pop3", 143: "imap",
        443: "https", 3306: "mysql", 5432: "postgresql",
        8000: "http-alt", 8080: "http-proxy"
    }

    if discovered:
        print(f"[+] Terdeteksi {len(discovered)} port terbuka.")
        for item in discovered:
            service = item['banner']
            # Fallback service name jika banner kosong
            if not service or len(service) < 2 or "Service Detected" in service:
                service = common_services.get(item['port'], "Unknown Service")
            
            item['identified_service'] = service
            item['vulnerabilities'] = VulnAnalyzer.fetch_cve(service)
            final_scan_results.append(item)
    else:
        print("[-] Tidak ada port terbuka ditemukan (Pastikan target bisa di-ping).")

    # --- PHASE 2: DEEP RECON (SENSITIVE FILES) ---
    print(f"\n[STEP 2] Deep Sensitive File Discovery...")
    recon_engine = AegisDeepRecon(target_url)
    recon_results = recon_engine.check_sensitive_files()
    if recon_results:
        print(f"[!!!] Ditemukan {len(recon_results)} file sensitif!")
    else:
        print("[+] Deep Recon bersih.")

    # --- PHASE 3: WEB APP VULNERABILITY AUDIT ---
    print(f"\n[STEP 3] Web Application Logic Audit (SQLi & XSS)...")
    web_auditor = AegisWebAuditor(target_url)
    
    # Scan SQLi
    sqli_results = web_auditor.scan_sql_injection()
    if sqli_results:
        print(f"[!!!] CRITICAL: Ditemukan {len(sqli_results)} celah SQL Injection!")
    else:
        print("[+] SQL Injection: Aman (Tidak ditemukan celah dasar).")
        
    # Scan XSS
    xss_results = web_auditor.scan_xss()
    if xss_results:
        print(f"[!!!] HIGH: Ditemukan {len(xss_results)} celah XSS!")
    else:
        print("[+] XSS Check: Aman (Tidak ada pantulan script).")

    # --- PHASE 4: REPORTING ---
    web_findings = sqli_results + xss_results
    
    report_data = {
        "scan_results": final_scan_results,
        "deep_recon": recon_results,
        "web_vulns": web_findings
    }

    if final_scan_results or recon_results or web_findings:
        save_report(report_data)
        print(f"\n[DONE] Audit Selesai. Cek laporan untuk detail.")
    else:
        print(f"\n[DONE] Audit Selesai. Tidak ada temuan signifikan.")

if __name__ == "__main__":
    main()