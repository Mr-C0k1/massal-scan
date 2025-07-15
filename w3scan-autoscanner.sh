#!/bin/bash
# w3scan-autoscanner.sh
# Jalankan script ini untuk memindai semua domain dalam daftar secara otomatis

# === Konfigurasi ===
DOMAIN_LIST="/opt/w3scan/targets.txt"
WORDLIST="/opt/w3scan/subdomain-wordlist.txt"
OUTPUT_DIR="/opt/w3scan/reports"
LOGFILE="/opt/w3scan/logs/scan.log"

# === Pastikan direktori ada ===
mkdir -p "$OUTPUT_DIR"
mkdir -p "$(dirname $LOGFILE)"

# === Loop setiap domain ===
while read -r domain; do
  if [[ -z "$domain" ]]; then continue; fi

  echo "[+] Memindai: $domain" | tee -a "$LOGFILE"
  python3 /opt/w3scan/w3scan_launcher.py --d "$domain" \
    --wordlist "$WORDLIST" \
    --output "$OUTPUT_DIR/scan_${domain}.json" \
    >> "$LOGFILE" 2>&1
  echo "[-] Selesai $domain" | tee -a "$LOGFILE"
  echo "" | tee -a "$LOGFILE"
done < "$DOMAIN_LIST"
