#!/usr/bin/env python3
"""
W3Scan Advanced - Modern Reconnaissance Tool
Versi upgrade dengan performa tinggi, akurat, dan aman.
Dependensi eksternal: dnsx, httpx, ffuf, nmap, wafw00f (opsional)
"""

import argparse
import json
import os
import subprocess
import sys
import threading
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

# Warna output
GREEN = '\033[92m'
YELLOW = '\033[93m'
RED = '\033[91m'
BLUE = '\033[94m'
NC = '\033[0m'

REQUIRED_TOOLS = ["dnsx", "httpx", "ffuf", "nmap"]
OPTIONAL_TOOLS = ["wafw00f"]

def check_dependencies():
    missing = []
    for tool in REQUIRED_TOOLS:
        if subprocess.call(["which", tool], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) != 0:
            missing.append(tool)
    if missing:
        print(f"{RED}[!] Tools berikut tidak ditemukan: {', '.join(missing)}{NC}")
        print(f"{YELLOW}    Install dengan:{NC}")
        print(f"    go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest")
        print(f"    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest")
        print(f"    go install -v github.com/ffuf/ffuf/v2@latest")
        print(f"    sudo apt install nmap  # atau equivalent")
        sys.exit(1)
    print(f"{GREEN}[+] Semua dependencies terpenuhi.{NC}")

def run_command(cmd, timeout=300):
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return result.stdout.strip(), result.stderr.strip(), result.returncode
    except subprocess.TimeoutExpired:
        return "", "Timeout", 1
    except Exception as e:
        return "", str(e), 1

def enumerate_subdomains(domain, wordlist=None):
    print(f"{BLUE}[+] Enumerasi subdomain untuk {domain}{NC}")
    found = []
    temp_wordlist = f"/tmp/sublist_{os.getpid()}.txt"

    if wordlist and os.path.isfile(wordlist):
        # Brute force dengan dnsx (super cepat)
        cmd = f"cat '{wordlist}' | sed 's/$/.{domain}/' | dnsx -silent -resp-only"
        out, err, rc = run_command(cmd)
        if rc == 0 and out:
            subs = out.splitlines()
            found.extend(subs)
            print(f"    {GREEN}Ditemukan {len(subs)} subdomain via brute-force{NC}")

        # Cleanup
        if os.path.exists(temp_wordlist):
            os.remove(temp_wordlist)
    else:
        print(f"{YELLOW}    Wordlist tidak ada → hanya resolve common subdomain{NC}")
        # Fallback: common subdomains
        common = ["www", "mail", "ftp", "admin", "test", "dev", "api", "staging", "beta"]
        cmd = f"echo '{chr(10).join(common)}' | sed 's/$/.{domain}/' | dnsx -silent"
        out, _, _ = run_command(cmd)
        if out:
            found = out.splitlines()

    # Validasi live dengan httpx
    if found:
        live_subs = []
        input_file = f"/tmp/live_subs_{os.getpid()}.txt"
        with open(input_file, "w") as f:
            f.write("\n".join(found))
        cmd = f"httpx -list {input_file} -silent -title -status-code -tech-detect -json"
        out, _, _ = run_command(cmd)
        os.remove(input_file)

        for line in out.splitlines():
            if line.strip():
                try:
                    data = json.loads(line)
                    live_subs.append({
                        "host": data.get("host", ""),
                        "url": data.get("url", ""),
                        "status": data.get("status_code", 0),
                        "title": data.get("title", "No title"),
                        "tech": data.get("technologies", [])
                    })
                    print(f"     [LIVE] {data['url']} [{data['status_code']}] {data.get('title', '')}")
                except:
                    continue
        return live_subs

    return []

def scan_ports(ip):
    print(f"{BLUE}[+] Port scan (top 1000 + service detection) pada {ip}{NC}")
    cmd = f"nmap -T4 -sV --top-ports 1000 {ip} -oG -"
    out, _, _ = run_command(cmd)
    open_ports = []
    for line in out.splitlines():
        if "Ports:" in line:
            ports_part = line.split("Ports:")[1].strip()
            for port_info in ports_part.split(", "):
                if "/open/" in port_info:
                    port, service = port_info.split("/", 1)[0:2]
                    open_ports.append({"port": int(port), "service": service})
                    print(f"     [OPEN] {port}/tcp → {service}")
    return open_ports

def check_takeover(subdomains):
    print(f"{BLUE}[+] Cek subdomain takeover (CNAME dangling){NC}")
    vulnerable = []
    input_file = f"/tmp/takeover_{os.getpid()}.txt"
    with open(input_file, "w") as f:
        f.write("\n".join([s["host"] for s in subdomains]))
    cmd = f"dnsx -list {input_file} -cname -silent"
    out, _, _ = run_command(cmd)
    os.remove(input_file)

    cnames = {}
    for line in out.splitlines():
        if "->" in line:
            sub, cname = line.split(" -> ")
            cnames[sub] = cname.strip()

    # Simple known vulnerable fingerprints
    vulnerable_fingerprints = ["amazonaws.com", "heroku", "github.io", "shopify", "wordpress", "azure", "cloudfront"]
    for sub, cname in cnames.items():
        if any(fp in cname.lower() for fp in vulnerable_fingerprints):
            # Check if resolve to IP
            try:
                socket.gethostbyname(sub)
            except:
                vulnerable.append({"subdomain": sub, "cname": cname})
                print(f"     {RED}[POTENTIAL TAKEOVER] {sub} → {cname}{NC}")
    return vulnerable

def directory_bruteforce(url, wordlist):
    print(f"{BLUE}[+] Directory bruteforce pada {url}{NC}")
    if not wordlist or not os.path.isfile(wordlist):
        print(f"{YELLOW}    Wordlist tidak ada → skip directory scan{NC}")
        return []
    found = []
    cmd = (f"ffuf -u {url}/FUZZ -w '{wordlist}' -mc 200,301,302,403 -fw 0 "
           f"-t 50 -timeout 10 -o /tmp/ffuf_temp.json -of json -silent")
    run_command(cmd, timeout=600)
    
    json_file = "/tmp/ffuf_temp.json"
    if os.path.exists(json_file):
        try:
            with open(json_file) as f:
                data = json.load(f)
            for result in data.get("results", []):
                found_url = result["input"]["FUZZ"] + " → " + result["url"]
                status = result["status"]
                size = result["length"]
                print(f"     [FOUND] {result['url']} [{status}] ({size} bytes)")
                found.append({"url": result["url"], "status": status, "size": size})
            os.remove(json_file)
        except:
            pass
    return found

def detect_waf(domain):
    print(f"{BLUE}[+] Deteksi WAF pada {domain}{NC}")
    if subprocess.call(["which", "wafw00f"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0:
        cmd = f"wafw00f https://{domain} -o /tmp/waf_temp.txt"
        run_command(cmd)
        if os.path.exists("/tmp/waf_temp.txt"):
            with open("/tmp/waf_temp.txt") as f:
                content = f.read()
            if "is behind a WAF" in content:
                waf_name = content.split("behind")[-1].split("WAF")[0].strip()
                print(f"     {RED}WAF Terdeteksi: {waf_name}{NC}")
                os.remove("/tmp/waf_temp.txt")
                return waf_name
    print(f"{GREEN}    Tidak ada WAF terdeteksi (atau wafw00f tidak terinstall){NC}")
    return "None"

def main():
    parser = argparse.ArgumentParser(description="W3Scan Advanced - Modern Recon Tool")
    parser.add_argument("--domain", required=True, help="Domain target (contoh: example.com)")
    parser.add_argument("--wordlist", help="Wordlist untuk subdomain & directory brute")
    parser.add_argument("--output", default=None, help="File output JSON")
    args = parser.parse_args()

    domain = args.domain.lower().replace("https://", "").replace("http://", "").strip("/")
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    results = {
        "target": domain,
        "timestamp": timestamp,
        "subdomains": [],
        "live_subdomains": [],
        "open_ports": [],
        "takeover_vulnerable": [],
        "directories": [],
        "waf": "Unknown"
    }

    check_dependencies()

    # 1. Subdomain enumeration
    live_subs = enumerate_subdomains(domain, args.wordlist)
    results["live_subdomains"] = live_subs
    results["subdomains"] = [s["host"] for s in live_subs]

    # 2. Port scan pada domain utama
    try:
        ip = socket.gethostbyname(domain)
        print(f"{GREEN}IP utama: {ip}{NC}")
        results["ip"] = ip
        results["open_ports"] = scan_ports(ip)
    except:
        print(f"{RED}Tidak bisa resolve IP utama{NC}")

    # 3. Subdomain takeover check
    if live_subs:
        results["takeover_vulnerable"] = check_takeover(live_subs)

    # 4. Directory bruteforce pada domain utama (HTTPS dulu)
    main_url = f"https://{domain}"
    results["directories"] = directory_bruteforce(main_url, args.wordlist)

    # 5. WAF detection
    results["waf"] = detect_waf(domain)

    # Simpan hasil
    output_file = args.output or f"w3scan_results_{domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(output_file, "w") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)

    print(f"\n{GREEN}[+] Scan selesai! Hasil disimpan di: {output_file}{NC}")

if __name__ == "__main__":
    main()
