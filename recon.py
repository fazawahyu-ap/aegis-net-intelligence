import requests

def brute_force_dir(target_url):
    # Common sensitive paths often left exposed
    sensitive_paths = [
        '.env', '.git/', 'phpinfo.php', 'config.php.bak', 
        'admin/', 'wp-admin/', 'backup.sql', '.ssh/id_rsa'
    ]
    
    print(f"[*] Starting Deep Directory Scan on {target_url}...")
    found_paths = []
    
    for path in sensitive_paths:
        url = f"{target_url}/{path}"
        try:
            # Check status code without downloading content
            r = requests.get(url, timeout=2, allow_redirects=False)
            if r.status_code == 200:
                print(f"[!!!] CRITICAL EXPOSURE: Sensitive path found: {url}")
                found_paths.append(url)
        except:
            pass
    return found_paths