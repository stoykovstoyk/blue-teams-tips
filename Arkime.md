## General Traffic Investigation

* ### Search for traffic between two IPs

```
ip.src == 192.168.1.10 && ip.dst == 10.0.0.5
```
* ### Search for specific protocol

```
protocol == dns
protocol == http
```

* ### Search for traffic by port

```
port == 80
port.dst == 443
```

* ### Search by packet size (e.g., greater than 1500 bytes)

```
packetsize > 1500
```

* ### Search for all traffic to a specific subnet

```
ip.dst == 10.10.0.0/16
```

## Suspicious Behavior

* ### Find traffic to uncommon ports

```
port > 1024 && !port in [80, 443, 22, 53]
```

* ### Find non-standard protocols on common ports

```
port == 80 && protocol != http
```

* ### Detect large uploads/downloads

```
bytes > 10000000
```

* ### Find traffic with unusual user agents

```
http.user-agent == "*curl*" || http.user-agent == "*wget*"
```

* ### Detect potential exfiltration

```
protocol == dns && dns.qry.name contains "exfil"
```

## Malware Detection

* ### Search for known malicious IPs

```
ip.src in [<list of IPs>] || ip.dst in [<list of IPs>]
```

* ### Identify DNS queries to suspicious domains

```
dns.qry.name contains "malicious-domain.com"
```

* ### Search for malware-related file types

```
http.content-type == "application/x-dosexec"  # For PE files
```

* ### Find traffic with executable downloads

```
http.uri contains ".exe"
```

## User Activity Analysis

* ### Find logins over HTTP

```
protocol == http && http.uri contains "login"
```

* ### Search for SSH connections

```
port == 22
```

* ### Filter traffic by user-agent

```
http.user-agent contains "Mozilla"
```

## Threat Hunting

* ### Find beaconing behavior (e.g., regular intervals)

```
ip.dst == <C2 server IP> && packet.deltaTime < 5
```

* ### Look for DNS tunneling

```
dns.qry.name.length > 50
```

* ### Detect brute-force attempts

```
protocol == ssh && count(ip.src) > 10
```

## Network Baselines

* ### Find hosts with the highest volume of traffic

```
bytes > 1000000
```

* ### List all unique IPs communicating with a subnet

```
ip.src == 192.168.1.0/24 || ip.dst == 192.168.1.0/24
```

* ### Top talkers (source IPs)

```
distinct(ip.src)
```

## Exercise-Specific Examples

* ### Identify connections to the exercise environment

```
ip.dst == 172.16.10.0/24
```

* ### Track commands via HTTP GET/POST

```
http.method == "GET" || http.method == "POST"
```

* ### Check for suspicious file uploads

```
http.uri contains "upload"
```

* ### Notes for Effective Use

Time Filters: Always scope your search to relevant time ranges to reduce noise.

start == "2025-01-18T10:00:00Z" && stop == "2025-01-18T12:00:00Z"

* ### Combine Filters: Use logical operators (&&, ||, !) for complex queries.

```
ip.dst == 8.8.8.8 && protocol == dns
```

* ### Wildcards: Use * for partial matches.

```
http.uri contains "*.php"
```

## Detect Nmap Scans by Characteristics

* ### Look for High-Frequency Port Probes

Nmap scans often generate traffic with multiple destination ports from the same source IP.

```
distinct(port.dst) > 100 && count(ip.src) > 200
```

This query identifies sources probing a large number of distinct ports, which is a hallmark of Nmap scanning.


* ### Search for Nmap Default User-Agent (HTTP or HTTPS Scans)

When Nmap performs web-based scans (e.g., --script http-*), it often uses a default user-agent.

```
http.user-agent contains "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)"
```

* ### Detect TCP SYN Scans (Stealth Scan)

SYN scans generate a high number of TCP connections with a single SYN packet per destination port.

```
tcp.flags.syn == 1 && tcp.flags.ack == 0 && tcp.flags.fin == 0 && tcp.flags.rst == 0
```

* ### Identify Version Detection Scans

Nmap's version detection (-sV) generates traffic that interacts with open ports.

```
http.uri contains "/"
```

This finds unusual HTTP requests from Nmap during version detection.

* ### ICMP Echo Requests (Ping Scans)

Nmap's ping scans rely on ICMP echo requests to discover hosts.

```
protocol == icmp && icmp.type == 8
```

* ### Aggressive Scanning Behavior

Nmap's aggressive scans (-A) combine multiple scan types, generating unusual patterns.

```
distinct(port.dst) > 500 && bytes < 100
```

This captures traffic involving many ports but with low data transfer, typical of Nmap probes.

## Reconnaissance Activity
* ### DNS Enumeration

Identify possible DNS reconnaissance (e.g., zone transfers or high query volumes):

```
protocol == dns && count(dns.qry.name) > 50
```

* ### Host Discovery via ICMP

Detect high volumes of ICMP echo requests:

```
protocol == icmp && icmp.type == 8 && count(ip.src) > 100
```

* ### HTTP Directory Brute-Forcing

Look for requests indicating directory or file enumeration:

```
http.uri contains ".php" || http.uri contains ".txt" || http.uri contains ".backup"
```

## Exploitation Attempts
* ### SQL Injection

Search for SQL syntax in HTTP URIs:

```
http.uri contains "' OR 1=1 --" || http.uri contains "UNION SELECT"
```

* ### Command Injection

Detect command injection attempts in web traffic:

```
http.uri contains "; ls" || http.uri contains "&& whoami"
```

* ### LFI/RFI (Local/Remote File Inclusion)

Identify potential LFI/RFI attempts:

```
http.uri contains "../" || http.uri contains "http://"
```

## Privilege Escalation

* ### Unusual Authentication

Look for unusual login activity over HTTP or HTTPS:

```
http.uri contains "login" && ip.src != 192.168.1.0/24
```

* ### Kerberos Golden Ticket Activity

Search for anomalous ticket-granting service (TGS) requests:

```
protocol == kerberos && kerberos.cname contains "krbtgt"
```

## Command and Control (C2) Traffic

* ### Beaconing

Identify regular interval traffic to the same destination:

```
ip.dst == <C2_IP> && packet.deltaTime < 5
```

* ### DNS Tunneling

Detect DNS queries with long domain names (typical in tunneling):

```
dns.qry.name.length > 50
```

## Data Exfiltration

* ### HTTP POST Requests with Large Payloads

Identify large data uploads over HTTP:

```
http.method == "POST" && http.content-length > 1000000
```

* ### Unusual File Transfers

Search for uncommon file types being downloaded or uploaded:

```
http.uri contains ".rar" || http.uri contains ".7z"
```

* ### Exfiltration via DNS

Search for large volumes of outbound DNS queries:

```
protocol == dns && count(ip.src) > 1000
```

## Brute-Force Attacks

* ### SSH Brute-Force

Detect SSH login attempts with high connection volumes:

```
port == 22 && count(ip.src) > 50
```

* ### Web Application Login Brute-Force

Look for repeated login attempts:

```
http.uri contains "login" && count(ip.src) > 20
```

## Malware Activity

* ### Ransomware Traffic

Identify SMB traffic with suspicious file extensions (e.g., .lock, .crypt):

```
protocol == smb && smb.filename contains ".lock"
```

* ### Command and Control (C2) Callback

Look for outbound HTTP requests with suspicious user agents:

```
http.user-agent contains "bot" || http.user-agent contains "malware"
```

## Suspicious Network Activity

* ### Unusual Ports

Find traffic on non-standard or high-risk ports:

```
port.dst not in [80, 443, 22, 53] && port.dst > 1024
```

* ### Traffic to Known Malicious IPs

Search for communication with known bad actors:

```
ip.dst in [<list of malicious IPs>]
```

* ### Anomalous Data Volume

Identify hosts with excessive inbound or outbound traffic:

```
bytes > 10000000
```

## Lateral Movement

* ### SMB Traffic Between Hosts

Identify SMB traffic within the internal network:

```
protocol == smb && ip.dst == 192.168.1.0/24
```

* ### Remote Desktop Protocol (RDP) Usage

Detect RDP traffic in the network:

```
port == 3389
```

* ### Windows Management Instrumentation (WMI) Abuse

Look for WMI activity over RPC:

```
protocol == rpc && rpc.method contains "ExecMethod"
```

## Baseline Deviation

* ### Top Talkers

Identify the top IP addresses generating the most traffic:

```
distinct(ip.src) && bytes > 1000000
```

* ### New Hosts in the Network

Look for previously unseen IPs:

```
ip.src not in [<known IPs>]
```

* ### Protocol Anomalies

Find unexpected protocols in use:

```
protocol not in [http, dns, tcp, udp]
```

## Insider Threats

* ### Email Exfiltration

Search for large SMTP traffic:

```
protocol == smtp && bytes > 1000000
```

* ### USB Device Traffic

Identify unusual traffic indicating potential USB device activity:

```
protocol == usb
```

## Domain Controller Monitoring
Suspicious Authentication Activity

* ### Unusual Account Lockouts Detect excessive failed login attempts, which could indicate brute force or password spraying:

```
protocol == kerberos && kerberos.error_code == "0x18" && count(ip.src) > 10
```

* ### Golden Ticket Activity Search for Kerberos tickets with unusually high lifetimes:

```
protocol == kerberos && kerberos.ticket_lifetime > 10h
```

* ### Unusual Logins from Service Accounts Identify service accounts used for interactive logins:

```
protocol == kerberos && kerberos.cname contains "svc" && kerberos.logon_type == 10
```

* ### LDAP Enumeration

Look for large volumes of LDAP queries:

```
protocol == ldap && count(ip.src) > 50
```

* ### Group Policy Changes

Search for updates to Group Policy objects:

```
protocol == smb && smb.filename contains "Sysvol" && smb.filename contains "GPO"
```

## Exchange Server Monitoring
* ### OWA (Outlook Web Access) Brute Force

Detect multiple failed login attempts to OWA:

```
http.uri contains "/owa/" && http.status == 401 && count(ip.src) > 10
```

* ### Suspicious EWS (Exchange Web Services) Activity

Look for access to EWS endpoints by unusual clients:

```
http.uri contains "/ews/" && http.user-agent not in ["Outlook", "ExchangeServices"]
```

* ### Mailbox Export Attempts

Identify requests to export mailboxes, often used in data exfiltration:

```
http.uri contains "/powershell" && http.body contains "New-MailboxExportRequest"
```

* ### Unusual SMTP Traffic

Detect large or unexpected SMTP traffic:

```
protocol == smtp && bytes > 1000000
```

## Lateral Movement via SMB
Suspicious File Access on DC

* ### Detect access to sensitive files like the NTDS.dit or SAM database:

```
protocol == smb && smb.filename contains ["ntds.dit", "sam"]
```

* ### Mimikatz Usage via SMB

Search for SMB traffic with filenames associated with tools like Mimikatz:

```
protocol == smb && smb.filename contains "mimikatz"
```

## Privilege Escalation Attempts
* ### Unusual WMI Traffic

WMI is often abused for lateral movement or privilege escalation:

```
protocol == rpc && rpc.method contains "ExecMethod"
```

* ### Shadow Copy Manipulation

Identify commands to delete Volume Shadow Copies:

```
http.uri contains "vssadmin" && http.body contains "delete shadows"
```

## Command and Control (C2) Detection
* ### DNS Beaconing

Detect regular DNS queries to a single domain:

```
protocol == dns && dns.qry.name == "<suspicious_domain>" && packet.deltaTime < 10
```

* ### PowerShell C2 Traffic

Search for encoded PowerShell commands in HTTP traffic:

```
http.body contains "powershell.exe -enc"
```

## Data Exfiltration
* ### Large File Transfers via SMB

Identify unusual file transfers to non-internal systems:

```
protocol == smb && smb.filename contains [".zip", ".rar", ".7z"] && ip.dst != 192.168.1.0/24
```

* ### Unusual Email Attachments

Search for emails with large attachments sent outside the organization:

```
protocol == smtp && smtp.attachment.size > 5000000 && smtp.recipient not contains "@yourdomain.com"
```

## Anomalous Account Behavior
* ### Creation of New Admin Accounts

Detect Kerberos traffic associated with new account creation:

```
protocol == kerberos && kerberos.service.name == "Administrator" && kerberos.logon_type == 2
```

* ### Password Changes

Look for Kerberos password change requests:

```
protocol == kerberos && kerberos.service.name contains ```
"kadmin"
```

## Exchange Server Exploitation (ProxyShell, ProxyNotShell, etc.)
* ### ProxyShell Exploit

Detect unusual requests to Exchange AutoDiscover and EWS endpoints:

```
http.uri contains "/autodiscover/autodiscover.json" && http.method == "POST"
```

* ### ProxyNotShell Exploit

Look for requests targeting /owa with shell commands:

```
http.uri contains "/owa/auth" && http.body contains "cmd.exe"
```

## Network Traffic Anomalies
* ### Traffic to Suspicious IPs

Search for connections to known malicious IPs:

```
ip.dst in [<list_of_malicious_IPs>]
```

* ### High-Frequency Connections

Identify devices making an unusual number of connections:

```
count(ip.src) > 1000
```

## General Monitoring
* ### New Services or Tools

Look for installation or usage of new tools on the DC or Exchange Server:

```
protocol == smb && smb.filename contains ["net.exe", "winrm", "powershell.exe"]
```

* ### RDP Sessions

Monitor RDP traffic to critical servers:

```
port == 3389 && ip.dst == "<DC_IP>" || ip.dst == "<Exchange_Server_IP>"
```

## Credential Harvesting and Authentication Events

* ### content contains "Authorization: Basic"

Detects cleartext credentials in HTTP Basic Authentication.

Kerberos Authentication Traffic
```
protocol == kerberos && content contains "AS-REQ"
```

* ### Suspicious File Transfers

Executable File Transfers
```
file.extension in ["exe", "dll", "bat", "ps1"]
```

* ### PowerShell Script Execution

Detecting Encoded PowerShell Commands
```
content contains "powershell" && content contains "-enc"
```
Find PowerShell commands with -enc, often used for obfuscation.

* ### PowerShell Network Traffic
```
http.user-agent == "Microsoft-Windows-PowerShell"
```

## Detecting Process Creation Events

* ### Sysmon Process Creation Logs
```
content == "EventID:1" && content contains "New Process Created"
```
Use this query to detect Sysmon logs for new processes being created.

* ### Suspicious Command-Line Arguments
```
content contains "cmd.exe" || content contains "powershell.exe" || content contains 
```

## Event Logs Monitoring
Suspicious Event Logs

* ### Event ID 4624 (Logon Events)
Identify high volumes of successful logins:
```
http.uri contains "4624" && http.body contains "Account Name"
```

* ### Event ID 4625 (Failed Logins)

Detect brute force or password spraying attempts:
```
http.uri contains "4625" && count(ip.src) > 10
```
   
* ### Event ID 4776 (NTLM Authentication Failures)

Monitor failed NTLM authentication attempts:

```
http.uri contains "4776" && http.body contains "NTLM"
```

* ### Event ID 4688 (Process Creation)  

Look for suspicious processes being executed:
```
http.uri contains "4688" && http.body contains ["mimikatz", "powershell.exe"]
```

## Process Creation Monitoring
Suspicious Processes

* ###  Unusual PowerShell Commands
 Monitor execution of obfuscated or encoded PowerShell commands:
```
http.body contains "powershell.exe" && http.body contains "-enc"
```

* ### Execution of Dual-Use Tools

Search for tools like `net.exe`, `ipconfig`, and `tasklist`:
```
http.body contains ["net.exe", "tasklist.exe", "ipconfig.exe"]
```
* ### Tools for Reconnaissance or Lateral Movement
Monitor tools like wmic, psexec, or rundll32:
```
http.body contains ["wmic.exe", "psexec.exe", "rundll32.exe"]
```


## PowerShell Scripts Monitoring
* ### PowerShell Logging (Event ID 4104)   

Detect encoded commands:
```
http.body contains "powershell" && http.body contains "-enc"
```
* ### Suspicious PowerShell Scripts

Monitor for commands used in exploitation or C2 activity:
```
http.body contains "powershell" && http.body contains ["Invoke-Mimikatz", "Invoke-Expression"]
```

## File System Changes

Suspicious File Access

* ### NTDS.dit or SAM Database
Look for unauthorized access:

```
protocol == smb && smb.filename contains ["ntds.dit", "SAM"]
```

* ### LSASS Memory Dumping Monitor for dumping LSASS memory:
```
http.body contains "lsass" && http.body contains "procdump"
```

## Scheduled Task or Service Creation
4698 (Scheduled Task Creation)  

* ### Detect suspicious tasks:
```
http.uri contains "4698" && http.body contains "Task Name"
```
* ### New Service Creation
Monitor for unauthorized services:
```
http.uri contains "7045" && http.body contains "Service Name"
```
## Network-Specific Queries
SMB Traffic

* ### Monitor unauthorized file shares:
```
protocol == smb && smb.filename contains ["C$", "ADMIN$"]
```

* ### RDP Sessions

Detect RDP connections:

```
protocol == tcp && port == 3389
```

## Custom Tools or Frameworks

Metasploit Framework

* ### Detect common Metasploit-generated payloads:
```
http.user-agent contains "Meterpreter"
```

* ### Cobalt Strike Beacons

Identify potential C2 traffic:
```
http.uri contains "/beacon" && packet.deltaTime < 10
```

## Data Exfiltration

* ### Large File Transfers
Identify files sent outside the network:
```
protocol == http && http.body.size > 5000000 && ip.dst not contains "192.168.0.0/16"
```

* ### Compressed or Encrypted Archives  
Monitor for `.zip`, `.rar`, or `.7z` files:
```
http.body contains [".zip", ".rar", ".7z"]
```
## Specific Malware Techniques

* ### DLL Injection

Detect process creation with DLL injection keywords:
```
http.body contains ["rundll32.exe", "Regsvr32.exe"]
```

* ### Persistence Mechanisms
Monitor registry key changes for persistence:
``` 
http.uri contains "regedit" && http.body contains ["Run", "RunOnce"]
```