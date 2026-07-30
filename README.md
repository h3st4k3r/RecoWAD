# WinRecon

**Author:** h3st4k3r  
**Version:** 0.2.0  
**Purpose:** Initial Windows and Active Directory reconnaissance from Kali Linux.

```
 ____                 __        ___    ____
|  _ \ ___  ___ ___   \ \      / / \  |  _ \
| |_) / _ \/ __/ _ \   \ \ /\ / / _ \ | | | |
|  _ <  __/ (_| (_) |   \ V  V / ___ \| |_| |
|_| \_\___|\___\___/     \_/\_/_/   \_\____/

RecoWAD: Windows & Active Directory Reconnaissance by h3st4k3r

```

`winrecon.sh` automates the initial collection phase against one or more Windows or Active Directory hosts, ranges, or networks.

## What it collects

The workflow has three stages: host discovery, Windows/AD candidate identification using characteristic ports, and parallel per-host enumeration.

For each candidate, it records:

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

The script does not change the local system clock. It only measures clock skew independently for each host.

## Dependencies

Required:

```bash
nmap
```

Optional tools are used automatically when available:

```bash
nxc smbclient smbmap rpcclient enum4linux-ng ldapsearch dig curl ntpdate net impacket-GetNPUsers
```

Missing optional tools are recorded in `dependencies.tsv` and do not stop execution.

## Basic usage

```bash
chmod +x winrecon.sh
sudo ./winrecon.sh 10.129.0.0/24
```

Multiple networks or addresses:

```bash
sudo ./winrecon.sh \
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

sudo ./winrecon.sh -i scope.txt -o results -j 8
```

Full TCP scan, RID brute force, and AS-REP checks:

```bash
sudo ./winrecon.sh \
  -i scope.txt \
  -o results \
  -j 8 \
  --full-ports \
  --rid-max 5000 \
  --asrep
```

When ICMP and discovery probes are filtered:

```bash
sudo ./winrecon.sh -i scope.txt --assume-up
```

## Execution banner

Every execution displays the tool banner, author, version, and purpose. The banner is written to standard error so the final output directory remains the only value written to standard output, which keeps command substitution and automation predictable.

ANSI colours are enabled only in an interactive terminal. Disable them with:

```bash
NO_COLOR=1 sudo ./winrecon.sh -i scope.txt
```

## Output structure

Each execution creates a timestamped directory:

```text
results/YYYYMMDD_HHMMSS/
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

Fast network collection:

```bash
sudo ./winrecon.sh 10.129.0.0/24 -j 6
```

Single Hack The Box machine:

```bash
sudo ./winrecon.sh 10.129.95.180 --assume-up --full-ports --rid-max 5000 --asrep
```

Large network without UDP checks:

```bash
sudo ./winrecon.sh -i scope.txt -j 12 --no-udp
```

## Current limitations

The script does not automatically download files from SMB shares or FTP servers. It first identifies access and permissions; file collection should remain a separate module to prevent unbounded copying by default.

It does not perform password spraying or authentication attempts using blank passwords against discovered users. The `--asrep` option only checks known accounts for disabled Kerberos pre-authentication.

Identity data is correlated from LDAP RootDSE, NetExec, SMB, RDP/NTLM, and reverse DNS. In segmented environments, some candidates may have incomplete identity information.
