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

    raw_target = input("[?] Enter Target IP/Domain: ")

    # Input parsing and cleaning
    clean_step1 = raw_target.replace("https://", "").replace("http://", "")
    target_clean_full = clean_step1.split('/')[0]
    
    if ":" in target_clean_full:
        target_host = target_clean_full.split(":")[0]
    else:
        target_host = target_clean_full
        
    if raw_target.startswith("http"):
        target_url = raw_target
    else:
        target_url = f"http://{target_clean_full}"
        
    print(f"[*] Target Host: {target_host}")
    print(f"[*] Target URL : {target_url}")
    
    ports = range(1, 8200)

    # --- PHASE 1: INFRASTRUCTURE SCAN ---
    print(f"\n[STEP 1] Infrastructure & Port Scanning...")
    engine = AegisScanner(target_host) 
    discovered = engine.start_scan(ports)
    
    final_scan_results = []
    
    common_services = {
        21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
        53: "dns", 80: "http", 110: "pop3", 143: "imap",
        443: "https", 3306: "mysql", 5432: "postgresql",
        8000: "http-alt", 8080: "http-proxy"
    }

    if discovered:
        print(f"[+] Detected {len(discovered)} open ports.")
        for item in discovered:
            service = item['banner']
            if not service or len(service) < 2 or "Service Detected" in service:
                service = common_services.get(item['port'], "Unknown Service")
            
            item['identified_service'] = service
            item['vulnerabilities'] = VulnAnalyzer.fetch_cve(service)
            final_scan_results.append(item)
    else:
        print("[-] No open ports found.")

    # --- PHASE 2: DEEP RECON ---
    print(f"\n[STEP 2] Deep Sensitive File Discovery...")
    recon_engine = AegisDeepRecon(target_url)
    recon_results = recon_engine.check_sensitive_files()
    if recon_results:
        print(f"[!!!] Found {len(recon_results)} sensitive files!")
    else:
        print("[+] Deep Recon clean.")

    # --- PHASE 3: WEB APP AUDIT ---
    print(f"\n[STEP 3] Web Application Logic Audit (SQLi & XSS)...")
    web_auditor = AegisWebAuditor(target_url)
    
    sqli_results = web_auditor.scan_sql_injection()
    if sqli_results:
        print(f"[!!!] CRITICAL: Found {len(sqli_results)} SQL Injection vulnerabilities!")
    else:
        print("[+] SQL Injection: Clean.")
        
    xss_results = web_auditor.scan_xss()
    if xss_results:
        print(f"[!!!] HIGH: Found {len(xss_results)} XSS vulnerabilities!")
    else:
        print("[+] XSS Check: Clean.")

    # --- PHASE 4: REPORTING ---
    web_findings = sqli_results + xss_results
    
    report_data = {
        "scan_results": final_scan_results,
        "deep_recon": recon_results,
        "web_vulns": web_findings
    }

    if final_scan_results or recon_results or web_findings:
        save_report(report_data)
        print(f"\n[DONE] Audit Complete. Check 'report.html' for details.")
    else:
        print(f"\n[DONE] Audit Complete. No significant findings.")

if __name__ == "__main__":
    main()