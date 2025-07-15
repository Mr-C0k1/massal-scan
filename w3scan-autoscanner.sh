#!/bin/bash
# simple-domain-scanner.sh
# Pengganti sementara jika w3scan_launcher.py gagal

domain="$1"
if [[ -z "$domain" ]]; then
  echo "Gunakan: $0 domain.com"
  exit 1
fi

echo "[+] Memindai domain: $domain"

# Alamat IP
ip=$(dig +short "$domain" | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' | head -n 1)
if [[ -z "$ip" ]]; then
  echo "[!] Tidak bisa resolve IP"
  exit 1
fi
echo "    ↪ Alamat IP: $ip"

# Port Terbuka (21, 22, 80, 443, 3306)
echo "    ↪ Memindai port..."
open_ports=$(nmap -p 21,22,80,443,3306 "$domain" | grep "open" | awk '{print $1}')
echo "    ↪ Port terbuka: $open_ports"

# Cek apakah ada Gmail di MX
echo "    ↪ Mengecek MX record..."
mx=$(dig MX "$domain" +short | grep "google.com")
if [[ -n "$mx" ]]; then
  echo "    ↪ Domain menggunakan Gmail (Google Mail)"
else
  echo "    ↪ Domain tidak menggunakan Gmail"
fi

# Cek keamanan HTTPS
echo "    ↪ Mengecek HTTPS..."
http_status=$(curl -s -o /dev/null -w "%{http_code}" "https://$domain")
if [[ "$http_status" -lt 400 ]]; then
  echo "    ↪ Website menggunakan HTTPS dan respons normal ($http_status)"
else
  echo "    ↪ Website mungkin tidak aman atau tidak merespon HTTPS (Status $http_status)"
fi
