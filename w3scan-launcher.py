#!/usr/bin/env python3
import subprocess
import argparse
import json
import os
import socket
import ssl
import re

def run_cmd(cmd):
    try:
        result = subprocess.check_output(cmd, stderr=subprocess.STDOUT, shell=True, text=True)
        return result.strip()
    except subprocess.CalledProcessError as e:
        return e.output

def scan_subdomains(domain, wordlist=None):
    print(f"[+] Mulai subdomain scanning untuk {domain}")
    found_subdomains = []
    # Jika wordlist ada, brute force subdomain sederhana
    if wordlist and os.path.isfile(wordlist):
        with open(wordlist, "r") as f:
            for sub in f.read().splitlines():
                subdomain = f"{sub}.{domain}"
                try:
                    socket.gethostbyname(subdomain)
                    print(f"    [OK] {subdomain}")
                    found_subdomains.append(subdomain)
                except socket.gaierror:
                    pass
    else:
        print("[!] Wordlist tidak ditemukan, melewati subdomain brute-force")
    return found_subdomains

def scan_ports(domain, ports="80,443,8080,8443"):
    print(f"[+] Scan port terbuka di {domain}")
    open_ports = []
    # Cek port terbuka secara sederhana
    for port in ports.split(","):
        port = int(port)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        try:
            sock.connect((domain, port))
            print(f"    [OPEN] Port {port}")
            open_ports.append(port)
        except:
            pass
        finally:
            sock.close()
    return open_ports

def check_ssl(domain):
    print(f"[+] Cek sertifikat SSL/TLS {domain}")
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(3)
            s.connect((domain, 443))
            cert = s.getpeercert()
            print(f"    Issuer: {cert.get('issuer')}")
            print(f"    Valid from: {cert.get('notBefore')}")
            print(f"    Valid until: {cert.get('notAfter')}")
            return cert
    except Exception as e:
        print(f"    Tidak bisa cek SSL: {e}")
        return None

def check_waf(domain):
    print(f"[+] Cek WAF di {domain}")
    # Simple cek header waf via curl
    try:
        result = run_cmd(f"curl -sI https://{domain}")
        waf_signs = ["cloudflare", "sucuri", "incapsula", "akamai", "f5-big-ip", "mod_security"]
        for line in result.splitlines():
            for waf in waf_signs:
                if waf in line.lower():
                    print(f"    WAF terdeteksi: {waf} ({line.strip()})")
                    return waf
        print("    Tidak ada WAF terdeteksi")
        return None
    except Exception as e:
        print(f"    Error cek WAF: {e}")
        return None

def directory_bruteforce(domain, wordlist):
    print(f"[+] Directory bruteforce untuk {domain}")
    found_dirs = []
    if not wordlist or not os.path.isfile(wordlist):
        print("[!] Wordlist tidak ditemukan, melewati directory bruteforce")
        return found_dirs

    with open(wordlist, "r") as f:
        for dir_ in f.read().splitlines():
            url = f"http://{domain}/{dir_}"
            code = run_cmd(f"curl -s -o /dev/null -w '%{{http_code}}' {url}")
            if code == "200":
                print(f"    [FOUND] {url}")
                found_dirs.append(url)
    return found_dirs

def param_fuzz(domain):
    print(f"[+] Param fuzzing dan bypass untuk {domain}")
    params = ["id", "page", "cat", "search", "q"]
    payloads = ["'", "\"", "<script>alert(1)</script>", "../../etc/passwd"]

    vulnerable = []
    for param in params:
        for payload in payloads:
            url = f"http://{domain}/?{param}={payload}"
            res = run_cmd(f"curl -s -i '{url}'")
            if re.search(r"alert\(1\)|syntax error|mysql", res, re.I):
                print(f"    Possible vuln param: {url}")
                vulnerable.append(url)
    return vulnerable

def main():
    parser = argparse.ArgumentParser(description="W3Scan Launcher - Bug Hunting & Cybersecurity Tool")
    parser.add_argument("--d", required=True, help="Domain target (tanpa https://)")
    parser.add_argument("--wordlist", help="Wordlist untuk subdomain dan directory bruteforce")
    parser.add_argument("--output", help="File JSON untuk simpan hasil")
    args = parser.parse_args()

    domain = args.d.replace("https://", "").replace("http://", "").strip("/")
    results = {}

    # Scan subdomain
    subs = scan_subdomains(domain, args.wordlist)
    results["subdomains"] = subs

    # Scan port
    ports = scan_ports(domain)
    results["open_ports"] = ports

    # SSL Cert
    cert = check_ssl(domain)
    results["ssl_cert"] = cert

    # WAF detection
    waf = check_waf(domain)
    results["waf"] = waf

    # Directory bruteforce
    dirs = directory_bruteforce(domain, args.wordlist)
    results["dirs_found"] = dirs

    # Parameter fuzzing
    vuln_params = param_fuzz(domain)
    results["vulnerable_params"] = vuln_params

    if args.output:
        with open(args.output, "w") as f:
            json.dump(results, f, indent=2)
        print(f"[+] Hasil disimpan di {args.output}")

if __name__ == "__main__":
    main()
