#!/usr/bin/env bash
# Author: Strikoder
# dns_enum.sh — quick DNS enumeration with dig
# Usage: ./dns_enum.sh <DNS_SERVER_IP> <DOMAIN> [subdomain_wordlist.txt]
# Example: ./dns_enum.sh 10.10.16.40 thm.local subdomains.txt

set -euo pipefail

DNS_SERVER="${1:-}"
DOMAIN="${2:-}"
WORDLIST="${3:-}"

if ! command -v dig >/dev/null 2>&1; then
  echo "[!] 'dig' not found. Install bind-utils / dnsutils." >&2
  exit 1
fi
if [[ -z "$DNS_SERVER" || -z "$DOMAIN" ]]; then
  echo "Usage: $0 <DNS_SERVER_IP> <DOMAIN> [subdomain_wordlist.txt]" >&2
  exit 1
fi

divider(){ printf '\n===== %s =====\n' "$1"; }

q() { # query helper: q <TYPE> [name]
  local type="$1"; local name="${2:-$DOMAIN}"
  echo "\$ dig @${DNS_SERVER} ${name} ${type} +noall +answer"
  dig @"${DNS_SERVER}" "${name}" "${type}" +noall +answer || true
}

# 0) Quick banner
divider "DNS ENUM on ${DOMAIN} via ${DNS_SERVER}"

# 1) SOA + NS (authority & nameservers)
divider "SOA (Start of Authority)"
q SOA
divider "NS (Authoritative Nameservers)"
q NS

# 2) ANY (ask for everything server will reveal)
divider "ANY (may be restricted on hardened servers)"
q ANY

# 3) Core record types
divider "A (IPv4)"
q A
divider "AAAA (IPv6)"
q AAAA
divider "CNAME (Aliases)"
q CNAME
divider "MX (Mail Exchangers)"
q MX
divider "TXT (SPF/DMARC/Notes)"
q TXT

# 4) Useful SRV records (esp. for AD environments)
divider "SRV Records (common AD services if applicable)"
q SRV "_ldap._tcp.${DOMAIN}"
q SRV "_kerberos._tcp.${DOMAIN}"
q SRV "_kpasswd._tcp.${DOMAIN}"
q SRV "_ldap._tcp.dc._msdcs.${DOMAIN}"

# 5) Zone transfer attempt (AXFR)
divider "AXFR (Zone Transfer Attempt)"
echo "\$ dig AXFR ${DOMAIN} @${DNS_SERVER}"
dig AXFR "${DOMAIN}" @"${DNS_SERVER}" +nocookie +nsid || echo "[!] AXFR failed or not allowed."

# 6) Reverse lookup of the DNS server itself
divider "Reverse (PTR) of DNS server"
REV_ARPA=$(printf "%s" "$DNS_SERVER" | awk -F. '{print $4"."$3"."$2"."$1".in-addr.arpa"}')
echo "\$ dig -x ${DNS_SERVER} @${DNS_SERVER} +noall +answer"
dig -x "${DNS_SERVER}" @"${DNS_SERVER}" +noall +answer || true

# 7) Optional subdomain brute-force (if wordlist supplied)
if [[ -n "${WORDLIST:-}" && -r "$WORDLIST" ]]; then
  divider "Subdomain Brute (wordlist: ${WORDLIST})"
  while IFS= read -r sub || [[ -n "$sub" ]]; do
    [[ -z "$sub" || "$sub" =~ ^# ]] && continue
    dig @"${DNS_SERVER}" "${sub}.${DOMAIN}" A +short | awk -v s="$sub" '{print s"."ENVIRON["DOMAIN"]" -> "$0}'
    dig @"${DNS_SERVER}" "${sub}.${DOMAIN}" AAAA +short | awk -v s="$sub" '{print s"."ENVIRON["DOMAIN"]" -> "$0}'
  done < <(sed 's/\r$//' "$WORDLIST")
fi

# 8) Clean summary (quick hits)
divider "Summary (quick hits)"
echo "[+] NS:"
dig @"${DNS_SERVER}" "${DOMAIN}" NS +short || true
echo "[+] MX:"
dig @"${DNS_SERVER}" "${DOMAIN}" MX +short || true
echo "[+] TXT:"
dig @"${DNS_SERVER}" "${DOMAIN}" TXT +short || true
echo "[+] A (root):"
dig @"${DNS_SERVER}" "${DOMAIN}" A +short || true

echo
echo "[✓] Done."
