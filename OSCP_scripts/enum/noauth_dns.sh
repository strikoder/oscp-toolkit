#!/usr/bin/env bash
# File: noauth
# Author: strikoder
#
# Description:
#   Enhanced DNS enumeration script that works with or without a known domain.
#
# Usage:
#   ./noauth_dns <DNS_SERVER_IP> [DOMAIN] [subdomain_wordlist.txt]
#
# Examples:
#   ./noauth_dns 10.10.16.40
#   ./noauth_dns 10.10.16.40 htb.local
#   ./noauth_dns 10.10.16.40 htb.local subdomains.txt
#
# What it does:
#   1) SOA and NS queries (authority, nameservers)
#   2) ANY query (may be restricted)
#   3) Core record types: A, AAAA, CNAME, MX, TXT
#   4) Common AD SRV records (_ldap, _kerberos, _kpasswd, _msdcs)
#   5) Zone transfer attempt (AXFR)
#   6) Reverse lookup (PTR) for the DNS server
#   7) Brute-force subdomains with provided wordlist
#   8) Prints a short summary (NS, MX, TXT, A)
#
# Output:
#   Results are printed directly to console.
#   If a wordlist is supplied, discovered subdomains with resolved IPs are shown.


set -euo pipefail

DNS_SERVER="${1:-}"
DOMAIN="${2:-}"
WORDLIST="${3:-}"

if [[ -z "${DNS_SERVER}" ]]; then
  echo "Usage: $0 <DNS_SERVER_IP> [DOMAIN] [subdomain_wordlist.txt]" >&2
  exit 1
fi

# Setup log file and temp storage
SAFE_IP="$(echo "${DNS_SERVER}" | tr '.' '_')"
OUTPUT_FILE="noauth_dns_${SAFE_IP}.log"
> "${OUTPUT_FILE}"

TMP_DIR="$(mktemp -d)"
FOUND_SUBS="${TMP_DIR}/subdomains.txt"
FOUND_SRV="${TMP_DIR}/srv.txt"
FOUND_AXFR="${TMP_DIR}/axfr.txt"
FOUND_PTR="${TMP_DIR}/ptr.txt"
FOUND_NSEC="${TMP_DIR}/nsec.txt"
> "${FOUND_SUBS}" "${FOUND_SRV}" "${FOUND_AXFR}" "${FOUND_PTR}" "${FOUND_NSEC}"

# Logging function
log() {
  echo "$1" | tee -a "${OUTPUT_FILE}"
}

divider() {
  log ""
  log "===== $1 ====="
}

# Autodetect domain via SOA if not given
if [[ -z "${DOMAIN}" ]]; then
  DOMAIN="$(dig @"${DNS_SERVER}" -t SOA +short | awk '{print $1}' | sed 's/\.$//')"
  if [[ -z "${DOMAIN}" ]]; then
    log "[!] Could not autodetect domain. Please provide it."
    exit 1
  else
    log "[*] Autodetected domain: ${DOMAIN}"
  fi
fi

# Query helper
q() {
  local type="$1"
  local name="${2:-${DOMAIN}}"
  log "\$ dig @${DNS_SERVER} ${name} ${type} +noall +answer"
  dig @"${DNS_SERVER}" "${name}" "${type}" +noall +answer | tee -a "${OUTPUT_FILE}" || true
}

divider "DNS ENUMERATION on ${DOMAIN} via ${DNS_SERVER}"

# SOA and NS
divider "SOA (Start of Authority)"
q SOA
divider "NS (Authoritative Nameservers)"
q NS

# ANY query
divider "ANY Record (may be restricted)"
q ANY

# Core record types
for type in A AAAA CNAME MX TXT; do
  divider "${type} Records"
  q "${type}"
done

# AD SRV records
divider "SRV Records (Active Directory)"
for srv in "_ldap._tcp" "_kerberos._tcp" "_kpasswd._tcp" "_ldap._tcp.dc._msdcs"; do
  full_name="${srv}.${DOMAIN}"
  log "\$ dig @${DNS_SERVER} ${full_name} SRV +noall +answer"
  result="$(dig @"${DNS_SERVER}" "${full_name}" SRV +noall +answer)"
  if [[ -n "${result}" ]]; then
    echo "${result}" | tee -a "${OUTPUT_FILE}" | tee -a "${FOUND_SRV}"
  else
    log "[!] No SRV response for ${full_name}"
  fi
done

# AXFR zone transfer attempt
divider "AXFR (Zone Transfer Attempt)"
log "\$ dig AXFR ${DOMAIN} @${DNS_SERVER}"
AXFR_RESULT="$(dig AXFR "${DOMAIN}" @"${DNS_SERVER}" +nocookie +nsid +noall +answer)"
if [[ -n "${AXFR_RESULT}" ]]; then
  echo "${AXFR_RESULT}" | tee -a "${OUTPUT_FILE}" | tee -a "${FOUND_AXFR}"
else
  log "[!] AXFR failed or not allowed."
fi

# Reverse PTR lookup
divider "Reverse PTR Lookup of DNS Server"
REV_ARPA="$(echo "${DNS_SERVER}" | awk -F. '{print $4"."$3"."$2"."$1".in-addr.arpa"}')"
log "\$ dig -x ${DNS_SERVER} @${DNS_SERVER} +noall +answer"
PTR_RESULT="$(dig -x "${DNS_SERVER}" @"${DNS_SERVER}" +noall +answer)"
if [[ -n "${PTR_RESULT}" ]]; then
  echo "${PTR_RESULT}" | tee -a "${OUTPUT_FILE}" | tee -a "${FOUND_PTR}"
else
  log "[!] PTR lookup failed."
fi

# Subdomain brute-force
if [[ -n "${WORDLIST}" && -r "${WORDLIST}" ]]; then
  divider "Subdomain Brute-force (Wordlist: ${WORDLIST})"
  while IFS= read -r sub || [[ -n "${sub}" ]]; do
    [[ -z "${sub}" || "${sub}" =~ ^# ]] && continue
    fqdn="${sub}.${DOMAIN}"
    resolved="$(dig @"${DNS_SERVER}" "${fqdn}" A AAAA +short)"
    if [[ -n "${resolved}" ]]; then
      while IFS= read -r ip; do
        log "${fqdn} -> ${ip}"
        echo "${fqdn} -> ${ip}" >> "${FOUND_SUBS}"
      done <<< "${resolved}"
    fi
  done < <(sed 's/\r$//' "${WORDLIST}")
fi

# DNSSEC / NSEC zone walking test
divider "NSEC (DNSSEC Zone Walking)"
log "\$ dig @${DNS_SERVER} ${DOMAIN} NSEC +dnssec +noall +answer"
NSEC_RESULT="$(dig @"${DNS_SERVER}" "${DOMAIN}" NSEC +dnssec +noall +answer)"
if [[ -n "${NSEC_RESULT}" ]]; then
  echo "${NSEC_RESULT}" | tee -a "${OUTPUT_FILE}" | tee -a "${FOUND_NSEC}"
else
  log "[!] NSEC not supported or DNSSEC disabled."
fi

# Final Summary
divider "Summary of Findings"

log "[*] NS Records:"
dig @"${DNS_SERVER}" "${DOMAIN}" NS +short | tee -a "${OUTPUT_FILE}" || true

log "[*] MX Records:"
dig @"${DNS_SERVER}" "${DOMAIN}" MX +short | tee -a "${OUTPUT_FILE}" || true

log "[*] TXT Records:"
dig @"${DNS_SERVER}" "${DOMAIN}" TXT +short | tee -a "${OUTPUT_FILE}" || true

log "[*] A Records:"
dig @"${DNS_SERVER}" "${DOMAIN}" A +short | tee -a "${OUTPUT_FILE}" || true

log ""

if [[ -s "${FOUND_SRV}" ]]; then
  log "[+] Active Directory SRV Records:"
  cat "${FOUND_SRV}" | tee -a "${OUTPUT_FILE}"
else
  log "[!] No SRV records found."
fi

if [[ -s "${FOUND_AXFR}" ]]; then
  log "[+] Zone Transfer (AXFR) successful:"
  head -n 10 "${FOUND_AXFR}" | tee -a "${OUTPUT_FILE}"
  log "[...] Full AXFR shown above."
else
  log "[!] AXFR failed or not allowed."
fi

if [[ -s "${FOUND_PTR}" ]]; then
  log "[+] Reverse PTR result:"
  cat "${FOUND_PTR}" | tee -a "${OUTPUT_FILE}"
else
  log "[!] No PTR response."
fi

if [[ -s "${FOUND_SUBS}" ]]; then
  log "[+] Discovered Subdomains:"
  cat "${FOUND_SUBS}" | tee -a "${OUTPUT_FILE}"
else
  log "[!] No subdomains found (or none resolved)."
fi

if [[ -s "${FOUND_NSEC}" ]]; then
  log "[+] NSEC records found — DNSSEC likely enabled."
  cat "${FOUND_NSEC}" | tee -a "${OUTPUT_FILE}"
else
  log "[!] No NSEC records found."
fi

log ""
log "[✓] DNS enumeration complete. Results saved to: ${OUTPUT_FILE}"

echo
echo "[✓] Done."
