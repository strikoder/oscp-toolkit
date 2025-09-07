#!/usr/bin/env bash
# Author: Strikoder
# File: no_auth_smb.sh
#
# Purpose:
#   Automated SMB enumeration with **no authentication** (null / anonymous / guest).
#   Collects information, lists accessible shares, and saves results in a single folder.
#
# Usage:
#   ./no_auth_smb.sh <IP>
#
# Output:
#   ./results_smb_noauth/ containing:
#     - usernames.txt           : Extracted usernames from RID brute
#     - downloads/*             : All files pulled recursively from accessible shares
#
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

# 1) NetBIOS names (if available)
if command -v nmblookup >/dev/null; then
  log "nmblookup -A"
  nmblookup -A "$IP" || true
fi

# 2) Version & safe SMB NSE
log "Version + safe SMB scripts"
nmap -Pn -p445 -sV --script "smb-protocols,smb2-time,smb2-security-mode,smb2-capabilities" "$IP"

# 3) smbclient null session share list
log "smbclient -L (null)"
SMBCLIENT_L="$(smbclient -N -L "\\\\$IP\\")"

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

# 5) NetExec RID brute
log "NetExec RID brute (saving ONLY usernames.txt)"
RID_TMP="$(mktemp)"
trap 'rm -f "$RID_TMP"' EXIT

if command -v nxc >/dev/null; then
  for USER in "" "anonymous" "guest"; do
    [[ -z "$USER" ]] && NAME="null" || NAME="$USER"
    log "  nxc smb $IP as '$NAME'"
    nxc smb "$IP" -u "$USER" -p '' --rid-brute >>"$RID_TMP" || true
  done
  awk '{print $6}' "$RID_TMP" | sort -u > "$OUT/usernames.txt"
else
  log "nxc not found in PATH, skipping RID brute"
  > "$OUT/usernames.txt"
fi

# 6) enum4linux-ng (optional)
if command -v enum4linux-ng >/dev/null; then
  log "enum4linux-ng -A"
  enum4linux-ng -A "$IP" || true
fi

# 7) smbmap (optional)
if command -v smbmap >/dev/null; then
  log "smbmap share perms"
  smbmap -H "$IP" -u ' ' -p ' ' || true
fi

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
  for CREDS in "-N" "-U anonymous%" "-U guest%"; do
    log "  //$IP/$sh with $CREDS"
    if smbclient $CREDS "//$IP/$sh" -c "lcd \"$target\"; recurse ON; prompt OFF; mget *"; then
      log "    Pulled to $target"
      break
    fi
  done
done

# 9) SMB dialect negotiation
log "SMB dialect negotiation"
smbclient -N -L "\\\\$IP\\" -m SMB3 || true
smbclient -N -L "\\\\$IP\\" -m SMB2 || true
smbclient -N -L "\\\\$IP\\" -m NT1  || true

# 10) Summary
log "Done. Review results in: $OUT/"
