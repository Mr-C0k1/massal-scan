#!/bin/bash
# w3scan-autoscanner.sh

# === Konfigurasi ===
DOMAIN_LIST="/opt/w3scan/targets.txt"
WORDLIST="/opt/w3scan/subdomain-wordlist.txt"
OUTPUT_DIR="/opt/w3scan/reports"
LOGFILE="/opt/w3scan/logs/scan.log"

# === Pastikan direktori ada ===
mkdir -p "$OUTPUT_DIR"
mkdir -p "$(dirname "$LOGFILE")"

# === Gunakan argumen jika diberikan ===
if [[ $# -gt 0 ]]; then
  echo "[*] Menggunakan domain dari argumen..."
  DOMAIN_SOURCE="/tmp/domain_args_$$.txt"
  for domain in "$@"; do
    echo "$domain" >> "$DOMAIN_SOURCE"
  done
else
  DOMAIN_SOURCE="$DOMAIN_LIST"
fi

# === Cek file domain source ada ===
if [[ ! -f "$DOMAIN_SOURCE" ]]; then
  echo "[!] File domain tidak ditemukan: $DOMAIN_SOURCE"
  exit 1
fi

# === Loop setiap domain ===
while read -r domain; do
  domain=$(echo "$domain" | xargs)  # Trim spasi
  if [[ -z "$domain" ]]; then continue; fi

  echo "[+] Memindai: $domain" | tee -a "$LOGFILE"
  python3 /opt/w3scan/w3scan_launcher.py --d "$domain" \
    --wordlist "$WORDLIST" \
    --output "$OUTPUT_DIR/scan_${domain}.json" \
    >> "$LOGFILE" 2>&1

  if [[ $? -ne 0 ]]; then
    echo "[!] ERROR saat memindai: $domain" | tee -a "$LOGFILE"
  fi

  echo "[-] Selesai: $domain" | tee -a "$LOGFILE"
  echo "" | tee -a "$LOGFILE"
done < "$DOMAIN_SOURCE"

# Hapus file sementara jika pakai argumen
[[ -f "$DOMAIN_SOURCE" && "$DOMAIN_SOURCE" == /tmp/domain_args_* ]] && rm "$DOMAIN_SOURCE"
