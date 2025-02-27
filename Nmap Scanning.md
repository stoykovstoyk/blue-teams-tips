## Nmap Scanning

* ### Nmap stealth scan using SYN
```
$ nmap -sS $ip
```
* ### Nmap stealth scan using FIN
```
$ nmap -sF $ip
```
* ### Nmap Banner Grabbing 
```
$ nmap -sV -sT $ip
```
* ### Nmap OS Fingerprinting
```
$ nmap -O $ip
```
* ### Nmap Regular Scan: 
```
$ nmap $ip/24
```

* ### Enumeration Scan 
```
$ nmap -p 1-65535 -sV -sS -A -T4 $ip/24 -oN nmap.txt
```
* ### Enumeration Scan All Ports TCP / UDP and output to a txt file 
```
$ nmap -oN nmap2.txt -v -sU -sS -p- -A -T4 $ip
```

* ### Nmap output to a file: 
```
$ nmap -oN nmap.txt -p 1-65535 -sV -sS -A -T4 $ip/24
```

* ### Quick Scan: 
```
$ nmap -T4 -F $ip/24
```
* ### Quick Scan Plus: 
```
$ nmap -sV -T4 -O -F --version-light $ip/24
```

* ### Quick traceroute
```
$ nmap -sn --traceroute $ip
```
* ### All TCP and UDP Ports 

```
$ nmap -v -sU -sS -p- -A -T4 $ip
```

* ### Intense Scan: 
```
$ nmap -T4 -A -v $ip
```
* ### Intense Scan Plus UDP 
```
$ nmap -sS -sU -T4 -A -v $ip/24
```
* ### Intense Scan ALL TCP Ports 
```
$ nmap -p 1-65535 -T4 -A -v $ip/24
```
* ### Intense Scan - No Ping 
```
$ nmap -T4 -A -v -Pn $ip/24
```
* ### Ping scan 
```
$ nmap -sn $ip/24
```
* ### Slow Comprehensive Scan 
```
$ nmap -sS -sU -T4 -A -v -PE -PP -PS80,443 -PA3389 -PU40125 -PY -g 53 --script "default or (discovery and safe)" $ip/24
```
* ### Scan with Active connect in order to weed out any spoofed ports designed to troll you 
```
$ nmap -p1-65535 -A -T5 -sT $ip
```

* ## Port Scanning

### Vpn necesita full connect scan:
```
$ nmap -sT -p- --min-rate=1000 -vvvvv 10.10.10.116 -T4 -oA nmap-ipsec2
```
### Quick:
```
$ nmap  -O -sV -Pn -oA nmap/host-quick.txt -v -T4 10.10.10.10
```
### Complete:
```
$ nmap -Pn -p-  -oA nmap/full.txt -v -T4 10.10.10.10.
```
### Correrle script default

```
$ nmap -Pn -p 139 -sC -sV  -v -T4 -oA nmap/puerto.txt
$ nmap -Pn -p- -sV --script "vuln and safe" -vvv -T4 -oA sarasa  10.10.10.135
```
* ### quick through proxy (no and SYN)

```
$ nmap  -O -sT -Pn -oA nmap/host-quick.txt -v -T4 10.10.10.10
```
* ### Scirpts

```
$ nmap -v -p 80 --scripts all 192.168.31.210  
```
* ### Scan cold fusion web server for a directory traversal vulnerability
```
$ nmap -v -p 80 --script=http-vuln-cve2010-2861 --scripts-args vulns.showall 192.168.1.210
```
* ### Check for anonymous ftp
```
$ nmap -v -p 21 --script=ftp-anon.nse 192.168.1.200-254
```

* ### Check smb server
```
$ nmap -v -p 139, 445 --script=smb-security-mode 192.168.1.100
```
* ### Verify if servers are patched
```
$ nmap -v -p 80 --script=http-vuln-cve2011-3192  --scripts-args vulns.showall  192.168.11.205-210
```