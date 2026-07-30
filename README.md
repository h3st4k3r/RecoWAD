# RecoWAD

**Author:** h3st4k3r  
**Version:** 0.3.0  
**Purpose:** Initial Windows and Active Directory reconnaissance from Kali Linux.

```
 ____                 __        ___    ____
|  _ \ ___  ___ ___   \ \      / / \  |  _ \\
| |_) / _ \/ __/ _ \   \ \ /\ / / _ \ | | | |
|  _ <  __/ (_| (_) |   \ V  V / ___ \| |_| |
|_| \_\___|\___\___/     \_/\_/_/   \_\____/${reset}

```

`recowad.sh` automates the initial collection phase against one or more Windows or Active Directory hosts, ranges, or networks.

## What it collects

The workflow has three stages: host discovery, Windows/AD candidate identification using characteristic ports, and parallel per-host enumeration.

For each candidate, it checks and correlates:

- TCP ports and services, with an optional full TCP port scan.
- DNS, Kerberos, RPC, SMB, LDAP/LDAPS, RDP, WinRM, ADWS, MSSQL, FTP, and common web services.
- Hostname, domain, base DN, operating system, and NTLM information exposed through SMB, RDP, HTTP, or MSSQL.
- Null-session and `guest` SMB access, shares, users, groups, password policy, SMBv1, and SMB signing.
- Anonymous RPC information, including domain data, SID, users, groups, shares, and policy details.
- LDAP RootDSE and, where allowed, anonymous users, groups, computers, and domain policy data.
- Domain DNS records, Active Directory SRV records, recursion, BIND version, and AXFR zone transfer results.
- Remote time and clock skew using LDAP, RDP/SMB, NTP, and `net time`.
- Anonymous FTP access.
- HTTP and HTTPS headers and responses, including WinRM/WSMan endpoints.
- A consolidated list of discovered usernames.
- Optional anonymous RID brute forcing and AS-REP roasting.

The script does not change the local system clock. It measures clock skew independently for each host.

## Default behaviour

RecoWAD is console-first.

When `-o` is not supplied, the tool uses a temporary working directory, prints the final findings to the terminal, and removes all temporary artifacts when execution finishes. It does not create a persistent `recowad-output` directory.

```bash
sudo ./recowad.sh 10.129.0.0/24
```

To preserve the complete evidence tree, provide an output directory:

```bash
sudo ./recowad.sh 10.129.0.0/24 -o results
```

The console summary is printed in both modes.

## Console summary

At the end of the run, RecoWAD prints an overall summary and a detailed block for every enumerated host.

The summary includes:

```text
Scope entries
Live hosts, unless discovery was skipped
Windows/AD candidates
Enumerated hosts
Persistent output status
Hostname and domain
Operating system
Open TCP and UDP ports
SMB null-session access
SMB guest access
Anonymous RPC access
LDAP RootDSE access
Anonymous LDAP directory access
SMB signing state
SMBv1 state
Anonymous FTP access
DNS zone transfer result
Clock skew
Discovered usernames
Anonymous share names
AS-REP hashes, when enabled
```

Example:

```text
============================================================
RecoWAD scan summary
============================================================
Scope entries        : 1
Host discovery       : skipped (--assume-up)
Windows/AD candidates: 1
Enumerated hosts     : 1
Detailed output      : disabled (console-only mode)

------------------------------------------------------------
[10.10.10.10] DC01.corp.local
OS                   : Windows Server 2019
Open ports           : 53/tcp,88/tcp,389/tcp,445/tcp
Anonymous access     : SMB null=allowed | SMB guest=denied | RPC null=allowed
LDAP                 : RootDSE=allowed | directory=denied
SMB security         : signing=not_required | SMBv1=disabled
Other exposure       : FTP anonymous=not_tested | DNS AXFR=denied
Clock skew           : -12 seconds
Discovered users     : 3 (administrator, guest, svc_backup)
Anonymous shares     : 2 (IPC$, Public)
============================================================
```

Usernames are limited to the first 20 entries in the console preview to prevent large domains from flooding the terminal. The complete list is preserved in `users.txt` when `-o` is used.

## Dependencies

Required:

```bash
nmap
```

Optional tools are used automatically when available:

```bash
nxc
smbclient
smbmap
rpcclient
enum4linux-ng
enum4linux
ldapsearch
dig
curl
ntpdate
net
impacket-GetNPUsers
GetNPUsers.py
```

Missing optional tools do not stop execution. When persistent output is enabled, their status is recorded in `dependencies.tsv`.

## Basic usage

Make the script executable:

```bash
chmod +x recowad.sh
```

Scan a network and print findings only:

```bash
sudo ./recowad.sh 10.129.0.0/24
```

Scan multiple networks or addresses:

```bash
sudo ./recowad.sh \
  10.10.10.0/24 \
  10.10.20.10 \
  172.16.50.0/27
```

Read the scope from a file:

```bash
cat > scope.txt <<'SCOPE'
10.10.10.0/24
10.10.20.10
172.16.50.0/27
SCOPE

sudo ./recowad.sh -i scope.txt -j 8
```

Keep the complete output:

```bash
sudo ./recowad.sh -i scope.txt -o results -j 8
```

Run a full TCP scan, RID brute force, and AS-REP checks:

```bash
sudo ./recowad.sh \
  -i scope.txt \
  -o results \
  -j 8 \
  --full-ports \
  --rid-max 5000 \
  --asrep
```

When discovery probes are filtered:

```bash
sudo ./recowad.sh -i scope.txt --assume-up
```

## Options

```text
-i, --input FILE          Read one host, range, or CIDR per line.
-o, --output DIR          Preserve detailed artifacts under DIR.
-j, --jobs N              Process N hosts in parallel.
    --rid-max N           Run anonymous RID brute force up to N.
    --asrep               Test AS-REP roasting against discovered users.
    --no-udp              Skip UDP checks.
    --full-ports          Scan all TCP ports before enumeration.
    --assume-up           Skip host discovery.
    --timeout SEC         Set the auxiliary command timeout.
    --host-timeout VALUE  Set the per-host Nmap timeout.
-h, --help                Show the help message.
```

## Execution banner

Every execution displays the tool name, author, version, and purpose.

ANSI colours are enabled only in an interactive terminal. Disable them with:

```bash
NO_COLOR=1 sudo ./recowad.sh -i scope.txt
```

## Persistent output structure

The following tree is created only when `-o DIR` is supplied:

```text
DIR/YYYYMMDD_HHMMSS/
├── scope.txt
├── dependencies.tsv
├── discovery.*
├── live-hosts.txt
├── candidates-scan.*
├── candidates.txt
├── summary.tsv
└── hosts/
    └── IP/
        ├── identity.tsv
        ├── users.txt
        ├── summary.tsv
        ├── nmap/
        ├── smb/
        ├── ldap/
        ├── dns/
        ├── clock/
        ├── ftp/
        ├── web/
        └── kerberos/
```

`summary.tsv` is the master inventory. Its columns are:

```text
ip, hostname, domain, os, open_ports, smb_null, smb_guest, rpc_null,
ldap_rootdse, ldap_directory, smb_signing, smb1, ftp_anonymous,
dns_axfr, clock_skew_seconds, users_found, anonymous_shares
```

## Recommended profiles

Fast console-only network collection:

```bash
sudo ./recowad.sh 10.129.0.0/24 -j 6
```

Single Hack The Box machine with expanded checks:

```bash
sudo ./recowad.sh \
  10.129.95.180 \
  --assume-up \
  --full-ports \
  --rid-max 5000 \
  --asrep
```

Persistent evidence collection:

```bash
sudo ./recowad.sh \
  -i scope.txt \
  -o results \
  -j 8
```

Large network without UDP checks:

```bash
sudo ./recowad.sh -i scope.txt -j 12 --no-udp
```

## Current limitations

The script does not automatically download files from SMB shares or FTP servers. It first identifies access and permissions; file collection should remain a separate module to prevent unbounded copying by default.

It does not perform password spraying or authentication attempts using blank passwords against discovered users. The `--asrep` option only checks known accounts for disabled Kerberos pre-authentication.

Identity data is correlated from LDAP RootDSE, NetExec, SMB, RDP/NTLM, and reverse DNS. In segmented environments, some candidates may have incomplete identity information.

Console-only mode still requires a temporary working directory while the scan is running. That directory is deleted automatically when the process exits normally or because of an error or interruption.

## Source language

The script source code, function names, variable names, help text, runtime messages, output labels, and documentation are written in English.
