#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

VERSION="0.2.1"
AUTHOR="h3st4k3r"
TOOL_NAME="WinRecon"
DESCRIPTION="Windows & Active Directory Initial Reconnaissance"
OUT_BASE="./winrecon-output"
INPUT_FILE=""
JOBS=4
RID_MAX=0
ENABLE_ASREP=0
ENABLE_UDP=1
FULL_PORTS=0
ASSUME_UP=0
COMMAND_TIMEOUT=45
NMAP_HOST_TIMEOUT="8m"
FULL_MIN_RATE=2000

PROFILE_TCP_PORTS="21,25,53,80,88,110,135,137,139,143,389,443,445,464,465,587,593,636,993,995,1433,3268,3269,3389,5985,5986,8080,8443,9389,47001"
PROFILE_UDP_PORTS="53,88,123,137,138,389,464"
NSE_SCRIPTS="banner,clock-skew,nbstat,smb-os-discovery,smb-protocols,smb-security-mode,smb2-security-mode,smb2-time,smb2-capabilities,smb-enum-domains,smb-enum-groups,smb-enum-shares,smb-enum-users,ldap-rootdse,dns-nsid,dns-recursion,ftp-anon,ftp-syst,http-title,http-server-header,http-headers,http-methods,http-ntlm-info,ssl-cert,ssl-enum-ciphers,rdp-enum-encryption,rdp-ntlm-info,ms-sql-info,ms-sql-ntlm-info"

SCOPES=()
RUN_DIR=""
NMAP_SCAN_TYPE="-sT"

banner() {
  local bold="" cyan="" reset=""

  if [[ -t 2 && -z "${NO_COLOR:-}" ]]; then
    bold=$'\033[1m'
    cyan=$'\033[36m'
    reset=$'\033[0m'
  fi

  cat >&2 <<BANNER
${cyan}${bold}  
                     ____
 \ \      / (_)_ __ |  _ \ ___  ___ ___  _ __
  \ \ /\ / /| | '_ \| |_) / _ \/ __/ _ \|  _  \
   \ V  V / | | | | |  _ <  __/ (_| (_) | | | |
    \_/\_/  |_|_| |_|_| \_\___|\___\___/|_| |_| ${reset}

${bold}${TOOL_NAME}${reset} — ${DESCRIPTION}
Author  : ${AUTHOR}
Version : ${VERSION}
BANNER
}

usage() {
  cat <<USAGE
winrecon.sh v${VERSION}

Initial reconnaissance collector for Windows and Active Directory networks.

Usage:
  $0 [options] NETWORK_OR_HOST [NETWORK_OR_HOST ...]
  $0 [options] -i scope.txt

Options:
  -i, --input FILE          File containing one host, range, or CIDR per line.
  -o, --output DIR          Base output directory. Default: ${OUT_BASE}
  -j, --jobs N              Hosts processed in parallel. Default: ${JOBS}
      --rid-max N           Run anonymous RID brute force up to N. 0 disables it.
      --asrep               Test AS-REP roasting against discovered users.
      --no-udp              Skip UDP checks for DNS/NTP/NetBIOS/Kerberos.
      --full-ports          Scan all TCP ports before service enumeration.
      --assume-up           Skip discovery and treat the entire scope as online.
      --timeout SEC         Timeout for auxiliary commands. Default: ${COMMAND_TIMEOUT}
      --host-timeout VALUE  Per-host Nmap timeout. Default: ${NMAP_HOST_TIMEOUT}
  -h, --help                Show this help message.

Examples:
  sudo $0 10.129.0.0/24
  sudo $0 -i networks.txt -o results -j 8 --rid-max 5000 --asrep
  sudo $0 10.10.10.10 10.10.20.0/24 --full-ports --assume-up
USAGE
}

log() {
  printf '[%s] %s\n' "$(date '+%H:%M:%S')" "$*" >&2
}

have() {
  command -v "$1" >/dev/null 2>&1
}

clean_ansi() {
  sed -r 's/\x1B\[[0-9;]*[mK]//g'
}

safe_name() {
  printf '%s' "$1" | tr ':/' '__' | tr -cd '[:alnum:]._-'
}

field() {
  printf '%s' "${1:-}" | tr '\t\r\n' '   '
}

run_limited() {
  local outfile="$1"
  local seconds="$2"
  shift 2

  {
    printf '$'
    printf ' %q' "$@"
    printf '\n\n'
    timeout --signal=TERM "${seconds}s" "$@"
  } >"$outfile" 2>&1 || true
}

port_open() {
  local host_dir="$1"
  local port="$2"
  local proto="${3:-tcp}"
  grep -qE "(^|[[:space:],])${port}/open/${proto}(/|[[:space:],])" \
    "$host_dir/nmap/services.gnmap" "$host_dir/nmap/udp.gnmap" 2>/dev/null
}

ports_from_gnmap() {
  local file="$1"
  grep -oE '[0-9]+/open/(tcp|udp)' "$file" 2>/dev/null \
    | awk -F/ '{print $1 "/" $3}' \
    | sort -t/ -k2,2 -k1,1n \
    | paste -sd, -
}

base_dn_to_domain() {
  printf '%s' "$1" \
    | sed -E 's/[[:space:]]//g; s/[dD][cC]=//g; s/,/./g' \
    | tr '[:upper:]' '[:lower:]'
}

collect_smb() {
  local ip="$1"
  local host_dir="$2"
  mkdir -p "$host_dir/smb"

  if ! port_open "$host_dir" 445 tcp && ! port_open "$host_dir" 139 tcp; then
    return
  fi

  if have nxc; then
    run_limited "$host_dir/smb/nxc-null.txt" "$COMMAND_TIMEOUT" nxc smb "$ip" -u '' -p ''
    clean_ansi <"$host_dir/smb/nxc-null.txt" >"$host_dir/smb/nxc-null.clean.txt" || true

    run_limited "$host_dir/smb/nxc-null-shares.txt" "$COMMAND_TIMEOUT" nxc smb "$ip" -u '' -p '' --shares
    run_limited "$host_dir/smb/nxc-null-users.txt" "$COMMAND_TIMEOUT" nxc smb "$ip" -u '' -p '' --users
    run_limited "$host_dir/smb/nxc-null-groups.txt" "$COMMAND_TIMEOUT" nxc smb "$ip" -u '' -p '' --groups
    run_limited "$host_dir/smb/nxc-null-policy.txt" "$COMMAND_TIMEOUT" nxc smb "$ip" -u '' -p '' --pass-pol

    run_limited "$host_dir/smb/nxc-guest.txt" "$COMMAND_TIMEOUT" nxc smb "$ip" -u guest -p ''
    run_limited "$host_dir/smb/nxc-guest-shares.txt" "$COMMAND_TIMEOUT" nxc smb "$ip" -u guest -p '' --shares

    if (( RID_MAX > 0 )); then
      run_limited "$host_dir/smb/nxc-rid-brute.txt" "$((COMMAND_TIMEOUT * 4))" \
        nxc smb "$ip" -u '' -p '' --rid-brute "$RID_MAX"
    fi
  fi

  if have smbclient; then
    run_limited "$host_dir/smb/smbclient-null-list.txt" "$COMMAND_TIMEOUT" \
      smbclient -N -L "//$ip"
    run_limited "$host_dir/smb/smbclient-guest-list.txt" "$COMMAND_TIMEOUT" \
      smbclient -L "//$ip" -U 'guest%'
  fi

  if have smbmap; then
    run_limited "$host_dir/smb/smbmap-null.txt" "$COMMAND_TIMEOUT" \
      smbmap -H "$ip" -u '' -p ''
    run_limited "$host_dir/smb/smbmap-guest.txt" "$COMMAND_TIMEOUT" \
      smbmap -H "$ip" -u guest -p ''
  fi

  if have rpcclient; then
    run_limited "$host_dir/smb/rpcclient-null.txt" "$((COMMAND_TIMEOUT * 2))" \
      rpcclient "$ip" -N -U '' -c \
      'querydominfo;lsaquery;enumdomains;enumdomusers;querydispinfo;enumdomgroups;getdompwinfo;netshareenumall'
  fi

  if have enum4linux-ng; then
    run_limited "$host_dir/smb/enum4linux-ng.txt" "$((COMMAND_TIMEOUT * 5))" \
      enum4linux-ng -A "$ip"
  elif have enum4linux; then
    run_limited "$host_dir/smb/enum4linux.txt" "$((COMMAND_TIMEOUT * 5))" \
      enum4linux -a "$ip"
  fi
}

ldap_query() {
  local outfile="$1"
  local uri="$2"
  shift 2

  {
    printf '$ LDAPTLS_REQCERT=never ldapsearch'
    printf ' %q' -x -LLL -o nettimeout=10 -H "$uri" "$@"
    printf '\n\n'
    LDAPTLS_REQCERT=never timeout --signal=TERM "${COMMAND_TIMEOUT}s" \
      ldapsearch -x -LLL -o nettimeout=10 -H "$uri" "$@"
  } >"$outfile" 2>&1 || true
}

collect_ldap() {
  local ip="$1"
  local host_dir="$2"
  local uri=""
  mkdir -p "$host_dir/ldap"

  if port_open "$host_dir" 389 tcp; then
    uri="ldap://$ip"
  elif port_open "$host_dir" 636 tcp; then
    uri="ldaps://$ip"
  else
    return
  fi

  ldap_query "$host_dir/ldap/rootdse.ldif" "$uri" \
    -s base -b '' \
    defaultNamingContext rootDomainNamingContext namingContexts \
    dnsHostName ldapServiceName currentTime supportedSASLMechanisms \
    supportedLDAPVersion domainFunctionality forestFunctionality

  local base_dn
  base_dn="$(sed -n 's/^defaultNamingContext: //p' "$host_dir/ldap/rootdse.ldif" | head -n1 || true)"
  printf '%s\n' "$base_dn" >"$host_dir/ldap/base_dn.txt"

  if [[ -z "$base_dn" ]]; then
    return
  fi

  ldap_query "$host_dir/ldap/users.ldif" "$uri" \
    -z 5000 -l 30 -b "$base_dn" \
    '(&(objectCategory=person)(objectClass=user))' \
    sAMAccountName userPrincipalName displayName description userAccountControl \
    servicePrincipalName memberOf pwdLastSet lastLogonTimestamp

  ldap_query "$host_dir/ldap/groups.ldif" "$uri" \
    -z 5000 -l 30 -b "$base_dn" \
    '(objectClass=group)' cn sAMAccountName description member memberOf groupType

  ldap_query "$host_dir/ldap/computers.ldif" "$uri" \
    -z 5000 -l 30 -b "$base_dn" \
    '(objectClass=computer)' sAMAccountName dNSHostName operatingSystem \
    operatingSystemVersion servicePrincipalName userAccountControl

  ldap_query "$host_dir/ldap/domain-policy.ldif" "$uri" \
    -z 50 -l 20 -b "$base_dn" \
    '(objectClass=domainDNS)' minPwdLength pwdHistoryLength lockoutThreshold \
    lockoutDuration lockoutObservationWindow maxPwdAge minPwdAge pwdProperties
}

derive_identity() {
  local ip="$1"
  local host_dir="$2"
  local hostname=""
  local domain=""
  local os=""
  local base_dn=""
  local nxc_file="$host_dir/smb/nxc-null.clean.txt"
  local nmap_file="$host_dir/nmap/services.nmap"

  if [[ -s "$host_dir/ldap/base_dn.txt" ]]; then
    base_dn="$(head -n1 "$host_dir/ldap/base_dn.txt" || true)"
    [[ -n "$base_dn" ]] && domain="$(base_dn_to_domain "$base_dn")"
  fi

  if [[ -s "$nxc_file" ]]; then
    hostname="$(sed -n 's/.*(name:\([^)]*\)).*/\1/p' "$nxc_file" | head -n1 || true)"
    [[ -z "$domain" ]] && domain="$(sed -n 's/.*(domain:\([^)]*\)).*/\1/p' "$nxc_file" | head -n1 | tr '[:upper:]' '[:lower:]' || true)"
    os="$(sed -n 's/.*\[\*\] \(.*\) (name:.*/\1/p' "$nxc_file" | head -n1 || true)"
  fi

  if [[ -s "$nmap_file" ]]; then
    [[ -z "$hostname" ]] && hostname="$(sed -nE 's/^.*(DNS_Computer_Name|Computer name):[[:space:]]*//p' "$nmap_file" | head -n1 | sed 's/\..*$//' || true)"
    [[ -z "$domain" ]] && domain="$(sed -nE 's/^.*(DNS_Domain_Name|Domain name):[[:space:]]*//p' "$nmap_file" | head -n1 | tr '[:upper:]' '[:lower:]' || true)"
    [[ -z "$os" ]] && os="$(sed -nE 's/^.*OS:[[:space:]]*//p' "$nmap_file" | head -n1 || true)"
  fi

  [[ "$domain" == "workgroup" || "$domain" == "WORKGROUP" ]] && domain=""
  [[ -z "$hostname" ]] && hostname="$ip"

  {
    printf 'ip\t%s\n' "$(field "$ip")"
    printf 'hostname\t%s\n' "$(field "$hostname")"
    printf 'domain\t%s\n' "$(field "$domain")"
    printf 'base_dn\t%s\n' "$(field "$base_dn")"
    printf 'os\t%s\n' "$(field "$os")"
  } >"$host_dir/identity.tsv"
}

identity_value() {
  local host_dir="$1"
  local key="$2"
  awk -F'\t' -v key="$key" '$1 == key {sub($1 FS, ""); print; exit}' "$host_dir/identity.tsv" 2>/dev/null || true
}

collect_dns() {
  local ip="$1"
  local host_dir="$2"
  local domain
  mkdir -p "$host_dir/dns"

  if ! port_open "$host_dir" 53 tcp && ! port_open "$host_dir" 53 udp; then
    return
  fi
  if ! have dig; then
    return
  fi

  domain="$(identity_value "$host_dir" domain)"

  run_limited "$host_dir/dns/reverse.txt" "$COMMAND_TIMEOUT" \
    dig "@$ip" -x "$ip" +time=3 +tries=1
  run_limited "$host_dir/dns/version-bind.txt" "$COMMAND_TIMEOUT" \
    dig "@$ip" version.bind CHAOS TXT +time=3 +tries=1

  if [[ -z "$domain" ]]; then
    local ptr ptr_host ptr_domain tmp_identity
    ptr="$(dig "@$ip" -x "$ip" +short +time=3 +tries=1 2>/dev/null | head -n1 | sed 's/\.$//' || true)"
    if [[ "$ptr" == *.* ]]; then
      ptr_host="${ptr%%.*}"
      ptr_domain="${ptr#*.}"
      tmp_identity="$host_dir/identity.tsv.tmp"
      awk -F'\t' -v OFS='\t' -v host="$ptr_host" -v dom="$ptr_domain" '
        $1 == "hostname" && ($2 == "" || $2 ~ /^[0-9.]+$/) {$2=host}
        $1 == "domain" && $2 == "" {$2=tolower(dom)}
        {print}
      ' "$host_dir/identity.tsv" >"$tmp_identity" && mv "$tmp_identity" "$host_dir/identity.tsv"
      domain="$(identity_value "$host_dir" domain)"
    fi
  fi

  if [[ -z "$domain" ]]; then
    return
  fi

  {
    for record in SOA NS A AAAA MX TXT; do
      printf '### %s %s\n' "$domain" "$record"
      dig "@$ip" "$domain" "$record" +time=3 +tries=1
      printf '\n'
    done

    for name in \
      "_ldap._tcp.$domain" \
      "_ldap._tcp.dc._msdcs.$domain" \
      "_ldap._tcp.pdc._msdcs.$domain" \
      "_kerberos._tcp.$domain" \
      "_kerberos._udp.$domain" \
      "_kpasswd._tcp.$domain" \
      "_gc._tcp.$domain"; do
      printf '### %s SRV\n' "$name"
      dig "@$ip" "$name" SRV +time=3 +tries=1
      printf '\n'
    done
  } >"$host_dir/dns/records.txt" 2>&1 || true

  run_limited "$host_dir/dns/axfr.txt" "$((COMMAND_TIMEOUT * 2))" \
    dig "@$ip" "$domain" AXFR +time=5 +tries=1
}

collect_clock() {
  local ip="$1"
  local host_dir="$2"
  local remote_time=""
  local remote_core=""
  local remote_epoch=""
  local local_epoch=""
  local skew=""
  local nmap_time=""
  local nmap_epoch=""
  local nmap_skew=""
  mkdir -p "$host_dir/clock"

  {
    printf 'local_utc\t%s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

    remote_time="$(sed -n 's/^currentTime: //p' "$host_dir/ldap/rootdse.ldif" 2>/dev/null | head -n1 || true)"
    printf 'ldap_currentTime\t%s\n' "$(field "$remote_time")"

    if [[ -n "$remote_time" ]]; then
      remote_core="${remote_time%%.*}"
      remote_core="${remote_core%Z}"
      if [[ "$remote_core" =~ ^[0-9]{14}$ ]]; then
        remote_epoch="$(date -u -d \
          "${remote_core:0:4}-${remote_core:4:2}-${remote_core:6:2} ${remote_core:8:2}:${remote_core:10:2}:${remote_core:12:2}" \
          +%s 2>/dev/null || true)"
        local_epoch="$(date -u +%s)"
        if [[ -n "$remote_epoch" ]]; then
          skew=$((remote_epoch - local_epoch))
          printf 'ldap_skew_seconds\t%s\n' "$skew"
        fi
      fi
    fi

    nmap_time="$(sed -nE 's/^.*(System_Time|date):[[:space:]]*//p' "$host_dir/nmap/services.nmap" 2>/dev/null | head -n1 || true)"
    printf 'nmap_remote_time\t%s\n' "$(field "$nmap_time")"
    if [[ -n "$nmap_time" ]]; then
      nmap_epoch="$(date -u -d "$nmap_time" +%s 2>/dev/null || true)"
      local_epoch="$(date -u +%s)"
      if [[ -n "$nmap_epoch" ]]; then
        nmap_skew=$((nmap_epoch - local_epoch))
        printf 'nmap_skew_seconds\t%s\n' "$nmap_skew"
      fi
    fi

    printf 'nmap_clock_lines\n'
    grep -Ei 'clock-skew|System_Time|smb2-time|date:' "$host_dir/nmap/services.nmap" 2>/dev/null || true
  } >"$host_dir/clock/clock.tsv"

  if have ntpdate && { port_open "$host_dir" 123 udp || port_open "$host_dir" 123 tcp; }; then
    run_limited "$host_dir/clock/ntpdate-query.txt" "$COMMAND_TIMEOUT" ntpdate -q "$ip"
  fi

  if have net && { port_open "$host_dir" 445 tcp || port_open "$host_dir" 139 tcp; }; then
    run_limited "$host_dir/clock/net-time.txt" "$COMMAND_TIMEOUT" net time -S "$ip"
  fi
}

collect_ftp() {
  local ip="$1"
  local host_dir="$2"
  mkdir -p "$host_dir/ftp"

  if ! port_open "$host_dir" 21 tcp; then
    return
  fi

  if have curl; then
    {
      printf '$ curl --user anonymous:anonymous --list-only ftp://%s/\n\n' "$ip"
      if timeout --signal=TERM "${COMMAND_TIMEOUT}s" \
        curl -sS --connect-timeout 8 --max-time "$COMMAND_TIMEOUT" \
        --user 'anonymous:anonymous' --list-only "ftp://$ip/"; then
        printf '\nFTP_ANON=allowed\n'
      else
        printf '\nFTP_ANON=denied_or_error\n'
      fi
    } >"$host_dir/ftp/anonymous-list.txt" 2>&1 || true
  fi
}

collect_web() {
  local ip="$1"
  local host_dir="$2"
  local port scheme
  mkdir -p "$host_dir/web"

  if ! have curl; then
    return
  fi

  for port in 80 443 8080 8443 5985 5986 47001; do
    port_open "$host_dir" "$port" tcp || continue
    case "$port" in
      443|8443|5986) scheme="https" ;;
      *) scheme="http" ;;
    esac

    run_limited "$host_dir/web/${scheme}-${port}-headers.txt" "$COMMAND_TIMEOUT" \
      curl -k -sS -i --connect-timeout 8 --max-time "$COMMAND_TIMEOUT" \
      "$scheme://$ip:$port/"
  done
}

collect_users() {
  local host_dir="$1"
  local out="$host_dir/users.txt"
  local tmp="$host_dir/.users.tmp"
  : >"$tmp"

  sed -n 's/.*user:\[\([^]]*\)\].*/\1/p' \
    "$host_dir/smb/rpcclient-null.txt" 2>/dev/null >>"$tmp" || true
  sed -n 's/^sAMAccountName: //p' \
    "$host_dir/ldap/users.ldif" 2>/dev/null >>"$tmp" || true
  grep -hoE '[[:alnum:]_.-]+\\[[:alnum:]_.\$-]+' \
    "$host_dir/nmap/services.nmap" 2>/dev/null \
    | awk -F'\\' '{print $2}' >>"$tmp" || true

  sed '/^[[:space:]]*$/d; /\$$/d' "$tmp" \
    | tr -d '\r' \
    | sort -fu >"$out"
  rm -f "$tmp"
}

collect_kerberos() {
  local ip="$1"
  local host_dir="$2"
  local domain
  mkdir -p "$host_dir/kerberos"

  if ! port_open "$host_dir" 88 tcp && ! port_open "$host_dir" 88 udp; then
    return
  fi

  domain="$(identity_value "$host_dir" domain)"
  collect_users "$host_dir"

  if (( ENABLE_ASREP == 0 )) || [[ -z "$domain" ]] || [[ ! -s "$host_dir/users.txt" ]]; then
    return
  fi

  if have impacket-GetNPUsers; then
    run_limited "$host_dir/kerberos/asrep.txt" "$((COMMAND_TIMEOUT * 4))" \
      impacket-GetNPUsers "${domain}/" -dc-ip "$ip" \
      -usersfile "$host_dir/users.txt" -no-pass -format hashcat \
      -outputfile "$host_dir/kerberos/asrep.hashes"
  elif have GetNPUsers.py; then
    run_limited "$host_dir/kerberos/asrep.txt" "$((COMMAND_TIMEOUT * 4))" \
      GetNPUsers.py "${domain}/" -dc-ip "$ip" \
      -usersfile "$host_dir/users.txt" -no-pass -format hashcat \
      -outputfile "$host_dir/kerberos/asrep.hashes"
  fi
}

summary_value() {
  local value="$1"
  [[ -n "$value" ]] && printf '%s' "$value" || printf 'unknown'
}

summarize_host() {
  local ip="$1"
  local host_dir="$2"
  local hostname domain os open_ports smb_null smb_guest rpc_null ldap_root ldap_dir
  local signing smb1 ftp_anon dns_axfr clock_skew users_count shares_count
  local nxc_file="$host_dir/smb/nxc-null.clean.txt"

  hostname="$(identity_value "$host_dir" hostname)"
  domain="$(identity_value "$host_dir" domain)"
  os="$(identity_value "$host_dir" os)"
  open_ports="$(ports_from_gnmap "$host_dir/nmap/services.gnmap")"
  if [[ -s "$host_dir/nmap/udp.gnmap" ]]; then
    local udp_ports
    udp_ports="$(ports_from_gnmap "$host_dir/nmap/udp.gnmap")"
    [[ -n "$udp_ports" ]] && open_ports="${open_ports:+$open_ports,}$udp_ports"
  fi

  smb_null="denied"
  if grep -qE 'Sharename|Anonymous login successful|\[\+\]' \
    "$host_dir/smb/smbclient-null-list.txt" "$host_dir/smb/nxc-null.txt" 2>/dev/null; then
    smb_null="allowed"
  fi

  smb_guest="denied"
  if grep -qE 'Sharename|\[\+\]' \
    "$host_dir/smb/smbclient-guest-list.txt" "$host_dir/smb/nxc-guest.txt" 2>/dev/null; then
    smb_guest="allowed"
  fi

  rpc_null="denied"
  if grep -qE 'user:\[|Domain:|domain sid:|Server role:' \
    "$host_dir/smb/rpcclient-null.txt" 2>/dev/null; then
    rpc_null="allowed"
  fi

  ldap_root="denied"
  grep -q '^defaultNamingContext:' "$host_dir/ldap/rootdse.ldif" 2>/dev/null && ldap_root="allowed"
  ldap_dir="denied"
  grep -q '^dn:' "$host_dir/ldap/users.ldif" 2>/dev/null && ldap_dir="allowed"

  signing="unknown"
  if grep -qiE '\(signing:True\)|Message signing enabled and required|message_signing:[[:space:]]*required' \
    "$nxc_file" "$host_dir/nmap/services.nmap" 2>/dev/null; then
    signing="required"
  elif grep -qiE '\(signing:False\)|Message signing enabled but not required' \
    "$nxc_file" "$host_dir/nmap/services.nmap" 2>/dev/null; then
    signing="not_required"
  fi

  smb1="unknown"
  if grep -qiE '\(SMBv1:True\)|NT LM 0\.12 \(SMBv1\)' \
    "$nxc_file" "$host_dir/nmap/services.nmap" 2>/dev/null; then
    smb1="enabled"
  elif grep -qiE '\(SMBv1:False\)|SMBv1: false' \
    "$nxc_file" "$host_dir/nmap/services.nmap" 2>/dev/null; then
    smb1="disabled"
  fi

  ftp_anon="not_tested"
  if port_open "$host_dir" 21 tcp; then
    ftp_anon="denied"
    grep -q 'FTP_ANON=allowed\|Anonymous FTP login allowed' \
      "$host_dir/ftp/anonymous-list.txt" "$host_dir/nmap/services.nmap" 2>/dev/null \
      && ftp_anon="allowed"
  fi

  dns_axfr="not_tested"
  if [[ -s "$host_dir/dns/axfr.txt" ]]; then
    dns_axfr="denied"
    grep -q 'XFR size:' "$host_dir/dns/axfr.txt" 2>/dev/null && dns_axfr="allowed"
  fi

  clock_skew="$(awk -F'\t' '
    $1 == "ldap_skew_seconds" {print $2; exit}
    $1 == "nmap_skew_seconds" && fallback == "" {fallback=$2}
    END {if (NR && fallback != "") print fallback}
  ' "$host_dir/clock/clock.tsv" 2>/dev/null | head -n1 || true)"
  [[ -z "$clock_skew" ]] && clock_skew="unknown"

  users_count=0
  [[ -s "$host_dir/users.txt" ]] && users_count="$(wc -l <"$host_dir/users.txt" | tr -d ' ')"

  shares_count=0
  if [[ -s "$host_dir/smb/smbclient-null-list.txt" ]]; then
    shares_count="$(awk '
      /^\t|^[[:space:]]+[A-Za-z0-9_.\$-]+[[:space:]]+(Disk|IPC|Printer)/ {count++}
      END {print count+0}
    ' "$host_dir/smb/smbclient-null-list.txt")"
  fi

  {
    field "$ip"; printf '\t'
    field "$hostname"; printf '\t'
    field "$domain"; printf '\t'
    field "$os"; printf '\t'
    field "$open_ports"; printf '\t'
    field "$smb_null"; printf '\t'
    field "$smb_guest"; printf '\t'
    field "$rpc_null"; printf '\t'
    field "$ldap_root"; printf '\t'
    field "$ldap_dir"; printf '\t'
    field "$signing"; printf '\t'
    field "$smb1"; printf '\t'
    field "$ftp_anon"; printf '\t'
    field "$dns_axfr"; printf '\t'
    field "$clock_skew"; printf '\t'
    field "$users_count"; printf '\t'
    field "$shares_count"; printf '\n'
  } >"$host_dir/summary.tsv"
}

collect_host() {
  local ip="$1"
  local host_key host_dir service_ports full_ports
  host_key="$(safe_name "$ip")"
  host_dir="$RUN_DIR/hosts/$host_key"
  mkdir -p "$host_dir/nmap"

  log "$ip: enumeration started"

  service_ports="$PROFILE_TCP_PORTS"
  if (( FULL_PORTS == 1 )); then
    nmap -n -Pn "$NMAP_SCAN_TYPE" --open -p- --min-rate "$FULL_MIN_RATE" \
      --max-retries 2 --host-timeout "$NMAP_HOST_TIMEOUT" "$ip" \
      -oA "$host_dir/nmap/full-tcp" >/dev/null 2>&1 || true
    full_ports="$(grep -oE '[0-9]+/open/tcp' "$host_dir/nmap/full-tcp.gnmap" 2>/dev/null \
      | cut -d/ -f1 | sort -n | paste -sd, -)"
    [[ -n "$full_ports" ]] && service_ports="$full_ports"
  fi

  nmap -n -Pn "$NMAP_SCAN_TYPE" -sV --version-all --open \
    -p "$service_ports" --script "$NSE_SCRIPTS" --script-timeout 45s \
    --host-timeout "$NMAP_HOST_TIMEOUT" "$ip" \
    -oA "$host_dir/nmap/services" >/dev/null 2>&1 || true

  if (( ENABLE_UDP == 1 )) && (( EUID == 0 )); then
    nmap -n -Pn -sU -sV --open -p "$PROFILE_UDP_PORTS" \
      --max-retries 1 --host-timeout 3m "$ip" \
      -oA "$host_dir/nmap/udp" >/dev/null 2>&1 || true
  else
    : >"$host_dir/nmap/udp.gnmap"
  fi

  collect_smb "$ip" "$host_dir"
  collect_ldap "$ip" "$host_dir"
  derive_identity "$ip" "$host_dir"
  collect_dns "$ip" "$host_dir"
  collect_clock "$ip" "$host_dir"
  collect_ftp "$ip" "$host_dir"
  collect_web "$ip" "$host_dir"
  collect_kerberos "$ip" "$host_dir"
  summarize_host "$ip" "$host_dir"

  log "$ip: enumeration completed"
}

write_dependencies() {
  local cmd
  {
    printf 'winrecon_version\t%s\n' "$VERSION"
    printf 'run_utc\t%s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    printf 'euid\t%s\n' "$EUID"
    for cmd in nmap nxc smbclient smbmap rpcclient enum4linux-ng enum4linux \
      ldapsearch dig curl ntpdate net impacket-GetNPUsers GetNPUsers.py; do
      if have "$cmd"; then
        printf '%s\tpresent\t%s\n' "$cmd" "$(command -v "$cmd")"
      else
        printf '%s\tmissing\t\n' "$cmd"
      fi
    done
  } >"$RUN_DIR/dependencies.tsv"
}

parse_args() {
  while (($#)); do
    case "$1" in
      -i|--input)
        INPUT_FILE="${2:?Missing input file}"
        shift 2
        ;;
      -o|--output)
        OUT_BASE="${2:?Missing output directory}"
        shift 2
        ;;
      -j|--jobs)
        JOBS="${2:?Missing job count}"
        shift 2
        ;;
      --rid-max)
        RID_MAX="${2:?Missing maximum RID}"
        shift 2
        ;;
      --asrep)
        ENABLE_ASREP=1
        shift
        ;;
      --no-udp)
        ENABLE_UDP=0
        shift
        ;;
      --full-ports)
        FULL_PORTS=1
        shift
        ;;
      --assume-up)
        ASSUME_UP=1
        shift
        ;;
      --timeout)
        COMMAND_TIMEOUT="${2:?Missing command timeout}"
        shift 2
        ;;
      --host-timeout)
        NMAP_HOST_TIMEOUT="${2:?Missing Nmap host timeout}"
        shift 2
        ;;
      -h|--help)
        usage
        exit 0
        ;;
      --)
        shift
        while (($#)); do SCOPES+=("$1"); shift; done
        ;;
      -*)
        printf 'Unknown option: %s\n' "$1" >&2
        usage >&2
        exit 2
        ;;
      *)
        SCOPES+=("$1")
        shift
        ;;
    esac
  done
}

main() {
  banner
  parse_args "$@"

  have nmap || { printf 'Error: nmap is required.\n' >&2; exit 1; }
  [[ "$JOBS" =~ ^[1-9][0-9]*$ ]] || { printf 'Error: --jobs must be greater than 0.\n' >&2; exit 2; }
  [[ "$RID_MAX" =~ ^[0-9]+$ ]] || { printf 'Error: --rid-max must be numeric.\n' >&2; exit 2; }
  [[ "$COMMAND_TIMEOUT" =~ ^[1-9][0-9]*$ ]] || { printf 'Error: --timeout must be greater than 0.\n' >&2; exit 2; }

  if [[ -n "$INPUT_FILE" ]]; then
    [[ -r "$INPUT_FILE" ]] || { printf 'Error: cannot read %s.\n' "$INPUT_FILE" >&2; exit 1; }
  fi

  if [[ -z "$INPUT_FILE" ]] && ((${#SCOPES[@]} == 0)); then
    usage >&2
    exit 2
  fi

  if (( EUID == 0 )); then
    NMAP_SCAN_TYPE="-sS"
  else
    NMAP_SCAN_TYPE="-sT"
    if (( ENABLE_UDP == 1 )); then
      log "Insufficient privileges: UDP checks are disabled. Run with sudo to test DNS/NTP/NetBIOS/Kerberos over UDP."
      ENABLE_UDP=0
    fi
  fi

  local stamp scope_file source_list discovery_args candidate_input
  stamp="$(date '+%Y%m%d_%H%M%S')"
  RUN_DIR="$OUT_BASE/$stamp"
  mkdir -p "$RUN_DIR/hosts"
  scope_file="$RUN_DIR/scope.txt"
  : >"$scope_file"

  if [[ -n "$INPUT_FILE" ]]; then
    sed -E 's/#.*$//; s/^[[:space:]]+//; s/[[:space:]]+$//' "$INPUT_FILE" \
      | sed '/^$/d' >>"$scope_file"
  fi
  if ((${#SCOPES[@]} > 0)); then
    printf '%s\n' "${SCOPES[@]}" >>"$scope_file"
  fi
  sort -u -o "$scope_file" "$scope_file"

  [[ -s "$scope_file" ]] || { printf 'Error: the scope is empty.\n' >&2; exit 2; }

  write_dependencies
  log "Output directory: $RUN_DIR"

  if (( ASSUME_UP == 1 )); then
    candidate_input="$scope_file"
  else
    log "Discovering live hosts"
    discovery_args=(-n -sn -PE -PS53,80,88,135,139,389,443,445,3389,5985 -PA80,135,139,443,445,3389,5985)
    if (( EUID == 0 )); then
      discovery_args+=( -PU53,88,123,137 )
    fi
    nmap "${discovery_args[@]}" -iL "$scope_file" -oA "$RUN_DIR/discovery" >/dev/null 2>&1 || true
    awk '/Status: Up/{print $2}' "$RUN_DIR/discovery.gnmap" | sort -u >"$RUN_DIR/live-hosts.txt"
    candidate_input="$RUN_DIR/live-hosts.txt"
  fi

  if [[ ! -s "$candidate_input" ]]; then
    log "No live hosts were detected. Try --assume-up."
    exit 0
  fi

  log "Identifying Windows/AD candidates"
  nmap -n -Pn "$NMAP_SCAN_TYPE" --open -p "$PROFILE_TCP_PORTS" \
    --max-retries 2 --host-timeout 5m -iL "$candidate_input" \
    -oA "$RUN_DIR/candidates-scan" >/dev/null 2>&1 || true

  awk '/Ports:/{print $2}' "$RUN_DIR/candidates-scan.gnmap" \
    | sort -u >"$RUN_DIR/candidates.txt"

  if [[ ! -s "$RUN_DIR/candidates.txt" ]]; then
    log "No candidates exposing Windows profile ports were found."
    exit 0
  fi

  log "Processing $(wc -l <"$RUN_DIR/candidates.txt" | tr -d ' ') candidates with $JOBS parallel jobs"
  while IFS= read -r ip; do
    [[ -n "$ip" ]] || continue
    collect_host "$ip" &
    while (( $(jobs -rp | wc -l) >= JOBS )); do
      wait -n || true
    done
  done <"$RUN_DIR/candidates.txt"
  wait || true

  {
    printf 'ip\thostname\tdomain\tos\topen_ports\tsmb_null\tsmb_guest\trpc_null\tldap_rootdse\tldap_directory\tsmb_signing\tsmb1\tftp_anonymous\tdns_axfr\tclock_skew_seconds\tusers_found\tanonymous_shares\n'
    find "$RUN_DIR/hosts" -mindepth 2 -maxdepth 2 -name summary.tsv -type f -print0 \
      | sort -z \
      | xargs -0 -r cat
  } >"$RUN_DIR/summary.tsv"

  log "Completed. Summary: $RUN_DIR/summary.tsv"
  printf '%s\n' "$RUN_DIR"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
