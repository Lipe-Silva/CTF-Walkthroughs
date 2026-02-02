## Scope:
10.10.183.159
## Information Gathering:
### Nmap Scan:
```bash
sudo nmap -sS 10.10.183.159
```

```nmap
Starting Nmap 7.95 ( https://nmap.org ) at 2025-04-14 15:58 -03
Note: Host seems down. If it is really up, but blocking our ping probes, try -Pn
Nmap done: 1 IP address (0 hosts up) scanned in 3.88 seconds
```

```bash
sudo nmap -Pn -sC -sV -p80,3389 10.10.183.159
```

```nmap 
PORT     STATE SERVICE       VERSION
80/tcp   open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_http-title: IIS Windows Server
| http-methods:
|_  Potentially risky methods: TRACE
3389/tcp open  ms-wbt-server Microsoft Terminal Services
|_ssl-date: 2025-04-14T18:58:47+00:00; 0s from scanner time.
| rdp-ntlm-info:
|   Target_Name: RETROWEB
|   NetBIOS_Domain_Name: RETROWEB
|   NetBIOS_Computer_Name: RETROWEB
|   DNS_Domain_Name: RetroWeb
|   DNS_Computer_Name: RetroWeb
|   Product_Version: 10.0.14393
|_  System_Time: 2025-04-14T18:58:42+00:00
| ssl-cert: Subject: commonName=RetroWeb
| Not valid before: 2025-04-13T18:40:55
|_Not valid after:  2025-10-13T18:40:55
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```
## Enumeration:
### Directory Fuzzing:
 `dirb http://10.10.183.159 /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt`

```dirb
-----------------
DIRB v2.22
By The Dark Raver
-----------------

START_TIME: Mon Apr 14 16:09:11 2025
URL_BASE: http://10.10.183.159/
WORDLIST_FILES: /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt

-----------------

GENERATED WORDS: 87568

---- Scanning URL: http://10.10.183.159/ ----
==> DIRECTORY: http://10.10.183.159/retro/
```

### Web Crawling:
after reading this post:
![[Pasted image 20250414172018.png]]
lets check the comments:
![[Pasted image 20250414172134.png]]

## Exploitation:

Let's use the credentials `Wade:parzival` to make try to login to the WordPress Admin Page:
![[Pasted image 20250414172416.png]]

Bingo!

Let's see if the same credentials work for RDP

```bash
xfreerdp /v:10.10.186.87 /u:Wade /p:parzival
```

We have gained initial access to the machine!
![[Pasted image 20250415133656.png]]

## Post:
### Information Gathering:
We can now take the time to gather further information and answer some of the questions:

what's in user.txt?

what is our current user?

what are our current privileges?

are there any interesting apps on the system?

### Enumeration:
what privilege escalation vulnerabilities can we use:

when we search hhupd privilege escalation vulnerabilities, we find CVE-2019-1388

https://sotharo-meas.medium.com/cve-2019-1388-windows-privilege-escalation-through-uac-22693fa23f5f

### Exploitation:
let's attempt privilege escalation:
1. Start hhupd
	![[Pasted image 20250415142631.png]]
2. Click show more details
	![[Pasted image 20250415142742.png]]
3. Click on the publisher's certificate.
	![[Pasted image 20250415142504.png]]
4. Click the CA link to open a browser tab with an privileged process.
	![[Pasted image 20250415144706.png]]
5. open the browser settings and try to download the file 
	![[Pasted image 20250415145426.png]]
6. now we can ignore this error and open a command prompt by lowering the drop down menu.
	![[Pasted image 20250415145537.png]]
	
	![[Pasted image 20250415145707.png]]

### Create Persistence:

gain a meterpreter shell:

use the persistence module:




