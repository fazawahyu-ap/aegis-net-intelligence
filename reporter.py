import json
import datetime

def save_report(data, filename="report.html"):
    # Parsing Data
    if isinstance(data, dict):
        scan_results = data.get('scan_results', [])
        deep_recon = data.get('deep_recon', [])
        web_vulns = data.get('web_vulns', [])
    else:
        scan_results = data if isinstance(data, list) else []
        deep_recon = []
        web_vulns = []

    # Backup JSON
    with open("scan_results.json", 'w') as f:
        json.dump(data, f, indent=4)
    
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # --- CSS YANG SANGAT SEDERHANA & BERSIH ---
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Scan Log: {timestamp}</title>
        <style>
            body {{
                background-color: #111; /* Hitam Doff */
                color: #ddd; /* Abu-abu terang (tidak bikin sakit mata) */
                font-family: 'Consolas', 'Monaco', monospace; /* Font Coding */
                font-size: 13px;
                padding: 30px;
                line-height: 1.5;
            }}
            h1 {{
                font-size: 18px;
                border-bottom: 1px solid #444;
                padding-bottom: 10px;
                margin-bottom: 20px;
                color: #fff;
            }}
            h2 {{
                font-size: 14px;
                color: #888; /* Warna abu-abu untuk sub-judul */
                margin-top: 40px;
                text-transform: uppercase;
                letter-spacing: 1px;
            }}
            .entry {{
                margin-bottom: 15px;
                padding-left: 15px;
                border-left: 2px solid #333; /* Garis tepi tipis */
            }}
            .danger {{ color: #ff5555; font-weight: bold; }} /* Merah Soft */
            .safe {{ color: #50fa7b; }} /* Hijau Soft */
            .info {{ color: #8be9fd; }} /* Biru Soft */
            
            pre {{
                background-color: #1a1a1a;
                padding: 10px;
                border-radius: 4px;
                color: #aaa;
                overflow-x: auto;
            }}
            a {{ color: #8be9fd; text-decoration: none; border-bottom: 1px dotted #555; }}
        </style>
    </head>
    <body>
        <h1>AEGIS SCAN REPORT // {timestamp}</h1>

        <h2>[01] Web Application Audit</h2>
    """

    if web_vulns:
        for item in web_vulns:
            html_content += f"""
            <div class="entry" style="border-left-color: #ff5555;">
                <div><span class="danger">[CRITICAL]</span> {item['type']}</div>
                <div>Location: {item['location']}</div>
                <div>Payload: <code>{item['payload'].replace('<', '&lt;').replace('>', '&gt;')}</code></div>
            </div>
            """
    else:
        html_content += """<div class="entry"><span class="safe">[OK]</span> No automated vulnerabilities (SQLi/XSS) found.</div>"""

    # --- BAGIAN 2: DEEP RECON ---
    html_content += """
        <h2>[02] Sensitive File Recon</h2>
    """
    
    if deep_recon:
        for item in deep_recon:
            status_class = "danger" if item['code'] == 200 else "info"
            html_content += f"""
            <div class="entry">
                <span class="{status_class}">[{item['code']}]</span> <a href="{item['path']}">{item['path']}</a>
            </div>
            """
    else:
        html_content += """<div class="entry"><span class="safe">[OK]</span> No sensitive files exposed.</div>"""

    # --- BAGIAN 3: NETWORK SCAN ---
    html_content += """
        <h2>[03] Network Infrastructure</h2>
    """

    if scan_results:
        for item in scan_results:
            vulns = item.get('vulnerabilities', [])
            status_label = f"<span class='danger'>VULNERABLE ({len(vulns)} CVEs)</span>" if vulns else "<span class='safe'>SECURE</span>"
            
            html_content += f"""
            <div class="entry">
                <div>Port <strong>{item['port']}</strong> <span class="info">({item.get('identified_service', 'Unknown')})</span> : {status_label}</div>
            """
            
            if vulns:
                html_content += "<div style='margin-left:10px; color:#aaa; font-size:12px;'>"
                for v in vulns:
                    html_content += f"- {v['id']}: {v.get('summary', 'No desc')[:90]}...<br>"
                html_content += "</div>"
            
            # Tampilkan banner hanya jika ada isinya
            if item.get('banner'):
                html_content += f"<pre>{item['banner']}</pre>"
            
            html_content += "</div>"
    else:
        html_content += """<div class="entry">[-] No open ports detected.</div>"""

    html_content += """
    </body>
    </html>
    """

    with open(filename, "w") as f:
        f.write(html_content)
    
    print(f"\n[✔] Laporan Simpel berhasil dibuat: {filename}")