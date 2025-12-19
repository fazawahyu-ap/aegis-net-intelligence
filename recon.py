import requests

def brute_force_dir(target_url):
    # Daftar folder sensitif yang sering lupa ditutup
    sensitive_paths = [
        '.env', '.git/', 'phpinfo.php', 'config.php.bak', 
        'admin/', 'wp-admin/', 'backup.sql', '.ssh/id_rsa'
    ]
    
    print(f"[*] Memulai Deep Directory Scan pada {target_url}...")
    found_paths = []
    
    for path in sensitive_paths:
        url = f"{target_url}/{path}"
        try:
            # Kita hanya mengecek status code tanpa download filenya (agar tetap etis)
            r = requests.get(url, timeout=2, allow_redirects=False)
            if r.status_code == 200:
                print(f"[!!!] SANGAT BERBAHAYA: Folder sensitif ditemukan: {url}")
                found_paths.append(url)
        except:
            pass
    return found_paths