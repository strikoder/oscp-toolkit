#!/usr/bin/env bash
# File: no_auth_smb.sh
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
# Arguments:
#   <IP>   Target host (IP or hostname)
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
#   results_smb_noauth/
#     - ldap_usernames.txt    : usernames from RID brute
#     - downloads/*           : recursively pulled share contents
#   All command output is shown live in the terminal.
#
# Notes:
#   - Requires: nmblookup, nmap,

set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "Usage: $0 <IP>"; exit 1
fi

IP="$1"
OUT="results_smb_noauth"
mkdir -p "$OUT"
mkdir -p "$OUT/downloads"

log(){ echo -e "[*] $*"; }

log "Saving to $OUT"

# 1) NetBIOS names
log "nmblookup -A $IP"
nmblookup -A "$IP" || true
echo

# 2) SMB version & safe NSE
log "nmap safe SMB scripts"
nmap -Pn -p445 -sV --script "smb-protocols,smb2-time,smb2-security-mode,smb2-capabilities" "$IP" || true
echo

# 3) smbclient null session share list
log "smbclient -L (null)"
SMBCLIENT_L="$(smbclient -N -L "\\\\$IP\\")" || SMBCLIENT_L=""
echo "$SMBCLIENT_L"
echo

# Parse shares for later
readarray -t ALL_SHARES < <(printf "%s\n" "$SMBCLIENT_L" \
  | awk '/\s+Disk\s/ {print $1}' \
  | sed 's/^[[:space:]]*//; s/[[:space:]]*$//' \
  | sort -u)

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
log "NetExec RID brute (saving ONLY usernames.txt)"
RID_TMP="$(mktemp)"
trap 'rm -f "$RID_TMP"' EXIT

for USER in "" "anonymous"; do
  [[ -z "$USER" ]] && NAME="null" || NAME="$USER"
  log "  nxc smb $IP as '$NAME'"
  nxc smb "$IP" -u "$USER" -p '' --rid-brute >>"$RID_TMP" || true
done
awk '{print $6}' "$RID_TMP" | sort -u > "$OUT/usernames.txt"

# 5a) Run selected modules (always with -M)
MODULES=(gpp_password gpp_autologin smb_ghost printnightmare remove-mic nopac)

for m in "${MODULES[@]}"; do
  log "Module: $m"
  nxc smb "$IP" -u '' -p '' -M "$m" || true
  nxc smb "$IP" -u 'anonymous' -p '' -M "$m" || true
done
echo

# 5b) Password policy checks (no-auth variants)
log "NetExec --pass-pol"
nxc smb "$IP" -u '' -p '' --pass-pol || true
nxc smb "$IP" -u 'anonymous' -p '' --pass-pol || true
echo


# 6) enum4linux-ng
log "enum4linux-ng -A"
enum4linux-ng -A "$IP" || true
echo

# 7) smbmap
log "smbmap share perms"
smbmap -H "$IP" -u ' ' -p ' ' || true
echo

# 8) Full pulls via smbclient
log "Downloading everything possible via smbclient to: $OUT/downloads"
if [[ ${#ALL_SHARES[@]} -eq 0 ]]; then
  readarray -t ALL_SHARES < <(smbclient -N -L "\\\\$IP\\" \
    | awk '/\s+Disk\s/ {print $1}' | sort -u)
fi

for sh in "${ALL_SHARES[@]}"; do
  [[ "$sh" == "IPC$" ]] && continue
  safe_sh="${sh//\$}"
  target="$OUT/downloads/$safe_sh"
  mkdir -p "$target"
  for CREDS in "-N" "-U anonymous%"; do
    log "  //$IP/$sh with $CREDS"
    if smbclient $CREDS "//$IP/$sh" -c "lcd \"$target\"; recurse ON; prompt OFF; mget *"; then
      log "    Pulled to $target"
      break
    fi
  done
done


# 10) Summary
echo "Done. Review results in: $OUT/"
echo "Zerologon (lab only): nxc smb $IP -u '' or anonymous -p '' -M zerologon"

