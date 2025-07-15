#!/usr/bin/env python3
import argparse
import requests
import threading
import time

# ==== Subdomain Scan ====

def scan_subdomains(domain, wordlist_file):
    print(f"[Subdomain Scan] Memindai {domain} dengan wordlist {wordlist_file}")
    try:
        with open(wordlist_file, "r") as f:
            subdomains = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print("[!] Wordlist tidak ditemukan, menggunakan default list")
        subdomains = ["www", "mail", "ftp", "test", "admin"]

    found = []
    for sub in subdomains:
        url = f"http://{sub}.{domain}"
        try:
            r = requests.get(url, timeout=2)
            if r.status_code < 400:
                print(f"  [+] Ditemukan subdomain: {url}")
                found.append(url)
        except requests.RequestException:
            pass
    print(f"[Subdomain Scan] Selesai. Ditemukan {len(found)} subdomain.\n")
    return found

# ==== Recon URL ====

COMMON_PATHS = [
    "/", "/admin", "/login", "/backup", "/test", "/config", "/.git/", "/.env", "/phpinfo.php"
]

def recon_urls(domain):
    print(f"[Recon URL] Memindai paths di {domain}")
    found = []
    for path in COMMON_PATHS:
        url = f"http://{domain}{path}"
        try:
            r = requests.get(url, timeout=3)
            if r.status_code < 400:
                print(f"  [+] URL valid: {url} (Status: {r.status_code})")
                found.append(url)
        except requests.RequestException:
            pass
    print(f"[Recon URL] Selesai. Ditemukan {len(found)} URL valid.\n")
    return found

# ==== Parameter Bypass Test ====

def test_bypass(domain):
    print(f"[Param Bypass] Mencoba bypass parameter di {domain}")
    test_urls = [
        f"http://{domain}/?id=1' OR '1'='1",
        f"http://{domain}/?search=<script>alert(1)</script>",
        f"http://{domain}/?redirect=http://evil.com"
    ]

    for url in test_urls:
        try:
            r = requests.get(url, timeout=3)
            if "error" in r.text.lower() or r.status_code >= 400:
                print(f"  [-] Parameter terlihat aman: {url}")
            else:
                print(f"  [!] Parameter rawan: {url}")
        except requests.RequestException:
            print(f"  [-] Gagal mengakses: {url}")

    print("[Param Bypass] Selesai.\n")

# ==== Main launcher ====

def main(domain, wordlist):
    print(f"Mulai scan untuk domain: {domain}\n")

    # Jalankan subdomain scan
    scan_subdomains(domain, wordlist)

    # Jalankan recon URL
    recon_urls(domain)

    # Jalankan parameter bypass test
    test_bypass(domain)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="w3scan-launcher gabungan sederhana")
    parser.add_argument("--d", required=True, help="Target domain, contoh: example.com")
    parser.add_argument("--wordlist", default="wordlist.txt", help="File wordlist subdomain (default: wordlist.txt)")
    args = parser.parse_args()

    main(args.d, args.wordlist)
