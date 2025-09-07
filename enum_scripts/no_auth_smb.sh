#!/usr/bin/env bash
# Author: Strikoder
# File: no_auth_smb.sh
#
# Purpose:
#   Automated SMB enumeration with **no authentication** (null / anonymous / guest).
#   Collects information, lists accessible shares, and saves results in a timestamped folder.
#
# Usage:
#   ./no_auth_smb.sh <IP>
#
# Output:
#   results/<IP>_<timestamp>/ containing:
#     - nmap_smb_safe.*        : SMB version & safe scripts
#     - smbclient_L.txt        : Share list via smbclient (null)
#     - rpcclient.txt          : Basic RPC queries (null)
#     - nxc_null.txt           : NetExec (null)
#     - nxc_anonymous.txt      : NetExec (anonymous)
#     - nxc_guest.txt          : NetExec (guest)
#     - enum4linux-ng.txt      : Broad enum (if tool is installed)
#     - smbmap.txt             : Share perms (null, with space user)
#     - listings/*             : Recursive file listings from readable shares
#     - loot/*                 : Downloaded interesting files (*.txt, *.ini, *.cfg, *.conf, *.log, *.ps1, *.bat, *.kdbx, *.key, *.xml, *.csv, *.rdp, *.vbs)
#     - juicy_strings.txt      : Grep results for common credential/secret keywords
#     - smbclient_smb[2|3|nt1].txt : Dialect negotiation results
#     - summary.txt            : Quick recap (shares found, loot count, paths)
#
# Requirements:
#   - nmap
#   - smbclient (from samba package)
#   - rpcclient (from samba package)
#   - nxc (NetExec, successor of CrackMapExec)
#   - enum4linux-ng (optional, pipx install enum4linux-ng)
#   - smbmap
#   - smbget (optional, for auto-loot)
#
# Notes:
#   - Uses `-u ' ' -p ' '` for null sessions with smbmap (this is the correct syntax).
#   - Uses NetExec with three accounts: null, anonymous, guest.
#   - Always stores output to timestamped folder under ./results/.
#   - Greps listings for potential credential strings for quick wins.
#
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "Usage: $0 <IP>"; exit 1
fi

IP="$1"
TS="$(date +%F_%H-%M-%S)"
OUT="results/${IP}_${TS}"
mkdir -p "$OUT"
mkdir -p "$OUT/loot"        # ADD: ensure loot dir exists


log(){ echo -e "[*] $*"; }

log "Saving to $OUT"

# 1) NetBIOS names (if available)
if command -v nmblookup >/dev/null; then
  log "nmblookup -A"
  nmblookup -A "$IP" 2>&1 | tee "$OUT/nmblookup.txt" || true
fi

# 2) Version & safe SMB NSE
log "Version + safe SMB scripts"
nmap -Pn -p445 -sV --script "smb-protocols,smb2-time,smb2-security-mode,smb2-capabilities" "$IP" -oA "$OUT/nmap_smb_safe" >/dev/null || true

# 3) smbclient null session share list
log "smbclient -L (null)"
smbclient -N -L "\\\\$IP\\" | tee "$OUT/smbclient_L.txt" || true

# 4) rpcclient null session basics
log "rpcclient basics"
{
  echo "srvinfo"
  echo "lsaquery"
  echo "enumdomains"
  echo "querydominfo"
  echo "enumdomusers"
  echo "enumdomgroups"
} | rpcclient -U "" -N "$IP" 2>&1 | tee "$OUT/rpcclient.txt" || true

# 5) NetExec (nxc) recon with [empty, anonymous, guest] accounts
if command -v nxc >/dev/null; then
  for USER in "" "anonymous" "guest"; do
    [[ -z "$USER" ]] && NAME="null" || NAME="$USER"
    log "nxc smb $IP with user '$USER'"
    nxc smb "$IP" -u "$USER" -p '' --shares --users --groups --pass-pol --rid-brute 2>&1 | tee "$OUT/nxc_${NAME}.txt" || true
  done
else
  log "nxc not found in PATH, skipping NetExec recon"
fi

# 6) enum4linux-ng (broad, read-only)
if command -v enum4linux-ng >/dev/null; then
  log "enum4linux-ng -A"
  enum4linux-ng -A "$IP" 2>&1 | tee "$OUT/enum4linux-ng.txt" || true
fi

# 7) smbmap share perms + recursive listing of readable shares
READABLE_SHARES=()
if command -v smbmap >/dev/null; then
  log "smbmap share perms"
  smbmap -H "$IP" -u ' ' -p ' ' 2>&1 | tee "$OUT/smbmap.txt" || true

  # Parse shares with READ or READ/WRITE
  mapfile -t READABLE_SHARES < <(awk '/^\s*[A-Za-z0-9_\$\-]+/ && /READ/ {print $1}' "$OUT/smbmap.txt" | sed 's/^\s*//;s/\s*$//' | sort -u || true)

  if [[ ${#READABLE_SHARES[@]} -gt 0 ]]; then
    log "Listing files from readable shares (depth 3, size-limited)"
    for sh in "${READABLE_SHARES[@]}"; do
      [[ "$sh" == "IPC$" ]] && continue
      safe_sh=$(echo "$sh" | tr -d '$')
      mkdir -p "$OUT/listings/$safe_sh"
      # Recursive list up to depth 3
      smbmap -H "$IP" -u ' ' -p ' ' -r "$sh" --depth 3 2>&1 | tee "$OUT/listings/${safe_sh}_tree.txt" || true
    done
  fi
fi

# 8) Fallback: list each share with smbclient, try null/anonymous/guest
if [[ ${#READABLE_SHARES[@]} -eq 0 ]]; then
  log "Parsing shares from smbclient -L output"
  mapfile -t SHARES < <(awk '/Disk/ {print $1}' "$OUT/smbclient_L.txt" | sed 's/^\s*//;s/\s*$//' | sort -u || true)
  for sh in "${SHARES[@]}"; do
    [[ "$sh" == "IPC$" ]] && continue
    safe_sh=$(echo "$sh" | tr -d '$'); mkdir -p "$OUT/listings/$safe_sh"
    log "Listing //$IP/$sh (null)"
    smbclient -N "//$IP/$sh" -c 'recurse ON; ls' 2>&1 | tee "$OUT/listings/${safe_sh}_ls_null.txt" || true
    log "Listing //$IP/$sh (anonymous)"
    smbclient -U 'anonymous%' "//$IP/$sh" -c 'recurse ON; ls' 2>&1 | tee "$OUT/listings/${safe_sh}_ls_anon.txt" || true
    log "Listing //$IP/$sh (guest)"
    smbclient -U 'guest%' "//$IP/$sh" -c 'recurse ON; ls' 2>&1 | tee "$OUT/listings/${safe_sh}_ls_guest.txt" || true
  done
fi

# 8b) Auto-loot small interesting files if accessible
log "Attempting auto-loot (<=2MB) of interesting files"
INTEREST='*.txt,*.ini,*.cfg,*.conf,*.log,*.ps1,*.bat,*.kdbx,*.key,*.xml,*.csv,*.rdp,*.vbs'
if command -v smbget >/dev/null; then
  # Try with null, anonymous, guest
  for CREDS in "-N" "-U anonymous%" "-U guest%"; do
    for shpath in $(awk '/\s+Disk\s/ {print $1}' "$OUT/smbclient_L.txt" 2>/dev/null | sed 's/^\s*//;s/\s*$//' | sort -u); do
      [[ "$shpath" == "IPC$" ]] && continue
      log "smbget $CREDS //$IP/$shpath ($INTEREST)"
      # smbget has no --max-size, so rely on -R + include patterns and hope perms allow
      smbget -q -R $CREDS "smb://$IP/$shpath" --include="$INTEREST" -o "$OUT/loot" || true
    done
  done
fi

# 8c) Grep for juicy strings in listings (offline quick wins)
log "Scanning listings for juicy keywords"
grep -RinE 'pass(word)?|pwd|secret|key(?!board)|token|creds?|login|db_|connection|cnxn|aws_|azure_|account|pwd=' "$OUT/listings" \
  > "$OUT/juicy_strings.txt" 2>/dev/null || true

# 9) Bonus: check signing + dialects quickly with smbclient -m
log "SMB dialect negotiation (quick check)"
{ smbclient -N -L "\\\\$IP\\" -m SMB3 2>&1 || true; } | tee "$OUT/smbclient_smb3.txt" >/dev/null
{ smbclient -N -L "\\\\$IP\\" -m SMB2 2>&1 || true; } | tee "$OUT/smbclient_smb2.txt" >/dev/null
{ smbclient -N -L "\\\\$IP\\" -m NT1  2>&1 || true; } | tee "$OUT/smbclient_nt1.txt"  >/dev/null

# 10) Mini summary
{
  echo "Target: $IP"
  echo "Time:   $TS"
  echo "Readable shares (smbmap): ${#READABLE_SHARES[@]}"
  echo "Listings dir: $OUT/listings"
  echo "Loot dir:     $OUT/loot"
  echo "Juicy strings: $(wc -l < "$OUT/juicy_strings.txt" 2>/dev/null || echo 0) hits"

} | tee -a "$OUT/summary.txt"

echo; log "Done. Review: $OUT"
