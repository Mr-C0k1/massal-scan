#!/bin/bash
# upgraded-domain-scanner.sh
# Versi upgrade dari simple-domain-scanner.sh dengan fitur lebih lengkap dan aman

# Warna untuk output (opsional)
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

domain="$1"
if [[ -z "$domain" ]]; then
  echo "Gunakan: $0 domain.com"
  exit 1
fi

echo -e "${GREEN}[+] Memindai domain: $domain${NC}"

# Cek dependencies
for cmd in dig nmap curl openssl; do
  if ! command -v "$cmd" &> /dev/null; then
    echo -e "${RED}[!] $cmd tidak terinstall. Install dulu: sudo apt install dnsutils nmap curl openssl${NC}"
    exit 1
  fi
done

# Resolve IP (A record)
ip=$(dig +short A "$domain" | head -n 1)
if [[ -z "$ip" ]]; then
  echo -e "${RED}[!] Tidak bisa resolve IP (A record)${NC}"
  exit 1
fi
echo -e " ↪ Alamat IP: ${GREEN}$ip${NC}"

# Port scan (top 1000 ports + version detection, faster)
echo " ↪ Memindai port terbuka (top 1000)..."
nmap_output=$(nmap -T4 --min-parallelism 100 -sV -p- "$ip" -oG - | grep "^Host")
open_ports=$(echo "$nmap_output" | awk '{print $4}' | tr '\n' ',' | sed 's/,$//')
services=$(nmap -T4 -sV -p- "$ip" --open | grep "^[0-9]" | awk '{print $1 " (" $3 " " $4 ")"}' | paste -sd "," -)

if [[ -z "$open_ports" ]]; then
  echo -e " ↪ ${YELLOW}Tidak ada port terbuka ditemukan${NC}"
else
  echo -e " ↪ Port terbuka: ${GREEN}$open_ports${NC}"
  echo -e " ↪ Service detail: $services"
fi

# MX records & provider detection
echo " ↪ Mengecek MX record..."
mx_records=$(dig MX "$domain" +short | sort -k1n)
if [[ -n "$mx_records" ]]; then
  echo "$mx_records"
  provider="Custom/Unknown"
  if echo "$mx_records" | grep -qi "google"; then provider="Google Workspace (Gmail)"; fi
  if echo "$mx_records" | grep -qi "outlook\|protection\.outlook\|mail\.protection"; then provider="Microsoft 365 / Outlook"; fi
  if echo "$mx_records" | grep -qi "zoho"; then provider="Zoho Mail"; fi
  if echo "$mx_records" | grep -qi "yahoo"; then provider="Yahoo Mail"; fi
  if echo "$mx_records" | grep -qi "secureserver\|godaddy"; then provider="GoDaddy Email"; fi
  
  echo -e " ↪ Provider email: ${GREEN}$provider${NC}"
else
  echo -e " ↪ ${YELLOW}Tidak ada MX record (domain tidak menerima email?)${NC}"
fi

# HTTPS/TLS check
echo " ↪ Mengecek HTTPS/TLS (port 443)..."
if nmap -p 443 "$ip" --open | grep -q "443/tcp open"; then
  # Cek cert validity & expiry
  cert_info=$(echo | openssl s_client -connect "$domain:443" -servername "$domain" 2>/dev/null | openssl x509 -noout -dates -issuer 2>/dev/null)
  if [[ -n "$cert_info" ]]; then
    expiry=$(echo "$cert_info" | grep notAfter | cut -d= -f2)
    issuer=$(echo "$cert_info" | grep Issuer | cut -d= -f2-)
    days_left=$(echo | openssl s_client -connect "$domain:443" -servername "$domain" 2>/dev/null | openssl x509 -noout -checkend 86400 2>/dev/null && echo "Valid" || echo "Expired")
    
    echo -e " ↪ ${GREEN}HTTPS aktif dengan certificate valid${NC}"
    echo "   ↳ Issuer: $issuer"
    echo "   ↳ Expiry: $expiry"
    if [[ "$days_left" == "Valid" ]]; then
      echo -e "   ↳ ${GREEN}Certificate masih valid (minimal 30 hari ke depan)${NC}"
    else
      echo -e "   ↳ ${RED}Certificate sudah expired atau akan expired dalam 30 hari!${NC}"
    fi
  else
    echo -e " ↪ ${YELLOW}HTTPS aktif tapi certificate tidak valid atau tidak bisa diambil${NC}"
  fi
  
  # HTTP title & server header
  title=$(curl -s -I -L "https://$domain" | grep -i "^server:" || echo "Unknown")
  page_title=$(curl -s "https://$domain" | grep -oP '<title>\K[^<]+' | head -n1 || echo "No title")
  echo "   ↳ Server header: $title"
  echo "   ↳ Page title: $page_title"
else
  echo -e " ↪ ${RED}Port 443 tidak terbuka (tidak ada HTTPS)${NC}"
  
  # Cek HTTP biasa (port 80)
  if nmap -p 80 "$ip" --open | grep -q "80/tcp open"; then
    http_code=$(curl -s -o /dev/null -w "%{http_code}" "http://$domain")
    echo -e " ↪ ${YELLOW}HTTP (port 80) aktif (kode $http_code) - sebaiknya redirect ke HTTPS!${NC}"
  fi
fi

echo -e "${GREEN}[+] Scan selesai!${NC}"
